#!/usr/bin/env python3
"""Serve the local payment benchmark from explicitly selected build assets."""

# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import mimetypes
from pathlib import Path
import secrets
import shutil
import tempfile
import threading
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
HELPERS = HERE.parents[1] / "emscripten_templates" / "ecdsa"
CASES = (("test_send", "EVM payment"), ("test_send_tron", "TRON payment"))
MAX_RESULTS_BYTES = 8 * 1024 * 1024


def asset(directory, name):
    """Resolve an allowlisted filename without allowing symlink escapes."""
    root = Path(directory).resolve(strict=True)
    path = (root / name).resolve(strict=True)
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"Invalid benchmark asset: {path}")
    return path


def make_state(args):
    routes = {
        "/": HERE / "index.html",
        "/index.html": HERE / "index.html",
        "/benchmark.mjs": HERE / "benchmark.mjs",
    }
    variants = []
    source_variants = []
    if args.baseline_assets:
        source_variants.append(("baseline", "Baseline", args.baseline_assets,
                                args.baseline_assets, args.baseline_commitment_cache_mb))
    source_variants.append(("candidate", "Optimized", args.candidate_web,
                            args.witness_build, 0))
    if args.commitment_cache_mb is not None:
        source_variants.append(("candidate-cached", "Optimized + cache",
                                args.candidate_web, args.witness_build,
                                args.commitment_cache_mb))
    for name, label, web, witness, cache in source_variants:
        prefix = f"/{name}/"
        routes[prefix + "payment_proof_worker.js"] = HERE / "payment_proof_worker.js"
        for role in ("prover", "verifier"):
            for extension in ("js", "wasm", "data"):
                filename = f"webgpu_{role}.{extension}"
                routes[prefix + filename] = asset(web, filename)
        for filename in ("ecdsa_witness.js", "ecdsa_witness.wasm"):
            routes[prefix + filename] = asset(witness, filename)
        for filename in ("ecdsa_precompute.js", "ecdsa_witness_worker.js"):
            routes[prefix + filename] = asset(HELPERS, filename)
        routes[prefix + "payroll_verification.wasm"] = args.program
        routes[prefix + "ecdsa_secp256k1_v1.r1cs.gz"] = args.template
        variants.append(dict(id=name, label=label, assetBase=prefix,
                             commitmentCacheMb=cache))
    for name, _ in CASES:
        routes[f"/fixtures/{name}.json"] = asset(args.fixtures, f"{name}.json")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = dict(
        schemaVersion=1,
        sessionId=secrets.token_hex(12),
        startedAt=datetime.now(timezone.utc).isoformat(),
        variants=variants,
        cases=[dict(id=name, label=label) for name, label in CASES],
        warmups=1, runs=3, packing=16384,
        resultFile=str(args.output / "results.json"),
        sources={key: str(getattr(args, key)) if getattr(args, key) else None
                 for key in ("baseline_assets", "candidate_web", "witness_build",
                             "program", "template", "fixtures")},
    )
    return dict(routes=routes, manifest=manifest, token=secrets.token_urlsafe(32),
                output=args.output, report=None, lock=threading.Lock())


def validate_report(report, manifest):
    if not isinstance(report, dict) or report.get("schemaVersion") != 1:
        raise ValueError("Unsupported result format")
    if report.get("sessionId") != manifest["sessionId"]:
        raise ValueError("Result belongs to a different server session")
    records = report.get("records")
    if not isinstance(records, list) or len(records) > 128:
        raise ValueError("Invalid result records")
    versions = {variant["id"] for variant in manifest["variants"]}
    cases = {case["id"] for case in manifest["cases"]}
    for record in records:
        if (record.get("version") not in versions or record.get("fixture") not in cases
                or record.get("run") not in (-1, 0, 1, 2)):
            raise ValueError("Unexpected benchmark case")
        if "proof" in record or "config" in record or "args" in record:
            raise ValueError("Results must not contain proof or input data")
        for role in ("prove", "verify"):
            metrics = record.get(role, {})
            for name in ("preparationMs", "mainMs", "wallMs"):
                value = metrics.get(name)
                if (not isinstance(value, (int, float)) or isinstance(value, bool)
                        or not math.isfinite(value) or value < 0):
                    raise ValueError("Invalid benchmark timer")


def handler_for(state):
    class Handler(BaseHTTPRequestHandler):
        def allowed_host(self):
            port = self.server.server_address[1]
            return self.headers.get("Host") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def send_headers(self, status, mime, length):
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(length))
            # Assets may be rebuilt between benchmark sessions. Never silently
            # reuse an earlier binary; warmups still warm browser/GPU caches.
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.end_headers()

        def send_json(self, value, status=200):
            encoded = json.dumps(value, allow_nan=False).encode()
            self.send_headers(status, "application/json", len(encoded))
            self.wfile.write(encoded)

        def do_GET(self):
            if not self.allowed_host():
                self.send_error(403, "Use the loopback URL printed by the server")
                return
            path = urlsplit(self.path).path
            if path == "/config":
                self.send_json({**state["manifest"], "saveToken": state["token"]})
                return
            if path == "/results":
                self.send_json(state["report"])
                return
            file = state["routes"].get(path)
            if file is None:
                self.send_error(404)
                return
            try:
                with file.open("rb") as stream:
                    mime = mimetypes.guess_type(file.name)[0] or "application/octet-stream"
                    if file.suffix == ".wasm":
                        mime = "application/wasm"
                    elif file.suffix in (".js", ".mjs"):
                        mime = "text/javascript"
                    elif file.suffix == ".gz":
                        mime = "application/gzip"
                    self.send_headers(200, mime, file.stat().st_size)
                    shutil.copyfileobj(stream, self.wfile, 1024 * 1024)
            except (FileNotFoundError, IsADirectoryError):
                self.send_error(404)

        def do_POST(self):
            if not self.allowed_host() or urlsplit(self.path).path != "/results":
                self.send_error(403)
                return
            origin = self.headers.get("Origin")
            expected_origin = "http://" + self.headers["Host"]
            if (origin not in (None, expected_origin)
                    or self.headers.get("X-Benchmark-Token") != state["token"]
                    or self.headers.get_content_type() != "application/json"):
                self.send_error(403)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_RESULTS_BYTES:
                    raise ValueError("Invalid result size")
                report = json.loads(self.rfile.read(size))
                validate_report(report, state["manifest"])
                encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
                with state["lock"]:
                    with tempfile.NamedTemporaryFile(mode="w", dir=state["output"],
                            prefix=".results-", suffix=".json.tmp", delete=False) as stream:
                        stream.write(encoded)
                        temporary = Path(stream.name)
                    try:
                        temporary.replace(state["output"] / "results.json")
                    finally:
                        temporary.unlink(missing_ok=True)
                    state["report"] = report
                self.send_json({"saved": True})
            except (ValueError, TypeError, KeyError, AttributeError, json.JSONDecodeError) as error:
                self.send_json({"error": str(error)}, 400)

    return Handler


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-assets", type=Path,
                        help="Optional directory with baseline backend and witness assets")
    parser.add_argument("--baseline-commitment-cache-mb", type=int,
                        help="Explicit cache budget for a baseline that supports caching")
    parser.add_argument("--candidate-web", type=Path, required=True)
    parser.add_argument("--witness-build", type=Path, required=True)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True, help="Compressed .r1cs.gz template")
    parser.add_argument("--fixtures", type=Path, required=True,
                        help="Directory containing test_send.json and test_send_tron.json")
    parser.add_argument("--output", "--output-dir", dest="output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8789)
    parser.add_argument("--commitment-cache-mb", type=int,
                        help="Add a cache-enabled candidate variant, e.g. 768 MiB")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.commitment_cache_mb is not None and args.commitment_cache_mb < 1:
        parser.error("--commitment-cache-mb must be positive when specified")
    if args.baseline_commitment_cache_mb is not None:
        if not args.baseline_assets or args.baseline_commitment_cache_mb < 0:
            parser.error("--baseline-commitment-cache-mb requires baseline assets and a nonnegative budget")
    for name in ("baseline_assets", "candidate_web", "witness_build", "program",
                 "template", "fixtures", "output"):
        value = getattr(args, name)
        if value is not None:
            setattr(args, name, value.expanduser().resolve())
    for name in ("program", "template"):
        if not getattr(args, name).is_file():
            parser.error(f"--{name} must name an existing file")
    return args


def main():
    args = parse_args()
    state = make_state(args)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler_for(state))
    print(f"Open http://127.0.0.1:{args.port}/", flush=True)
    print(f"JSON results: {args.output / 'results.json'}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
