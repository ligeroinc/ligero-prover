#!/usr/bin/env python3
"""Serial native payment benchmarks, including public-input-only verification.

Use synthetic fixture JSONs. Logs contain the arguments printed by the backend.
Each timed run is a new process; template loading is included in wall time.
"""

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import time


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def invoke(binary, config, directory, environment, role, label):
    start = time.perf_counter()
    process = subprocess.run(
        [str(binary), json.dumps(config)], cwd=directory, env=environment,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300,
    )
    elapsed = time.perf_counter() - start
    output = ANSI.sub("", process.stdout)
    log = directory / f"{role}-{label}.log"
    log.write_text(output)
    if process.returncode or not re.search(
        rf"Final {role} (?:Result|result):\s*true", output, re.I
    ):
        raise RuntimeError(f"{role} failed; see {log}")
    timers = {
        name: float(value)
        for name, value in re.findall(r"^([\w. -]+):\s+(\d+(?:\.\d+)?)ms", output, re.M)
    }
    ecdsa = {
        name: float(value)
        for name, value in re.findall(r"^(ECDSA [\w-]+ seconds): ([\d.e+-]+)", output, re.M)
    }
    counts = {
        name: int(value)
        for name, value in re.findall(r"^Num (Linear constraints|quadratic constraints):\s+(\d+)", output, re.M)
    }
    return dict(wall_s=elapsed, timers_ms=timers, ecdsa_seconds=ecdsa,
                constraints=counts, version=output.splitlines()[0])


def public_inputs(config):
    result = copy.deepcopy(config)
    for index in result["private-indices"]:
        value = result["args"][index - 1]
        if "hex" in value:
            value["hex"] = "0" * len(value["hex"])
        elif "i64" in value:
            value["i64"] = 0
        elif "str" in value:
            value["str"] = "0" * len(value["str"].encode("utf-8"))
        else:
            raise ValueError(f"Unsupported private argument: {index}")
    return result


def median_metrics(runs, role):
    values = [run[role] for run in runs]
    return {
        "wall_s": statistics.median(value["wall_s"] for value in values),
        "timers_ms": {
            key: statistics.median(value["timers_ms"][key] for value in values)
            for key in values[0]["timers_ms"]
        },
        "ecdsa_seconds": {
            key: statistics.median(value["ecdsa_seconds"][key] for value in values)
            for key in values[0]["ecdsa_seconds"]
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("prover", "verifier", "program", "shader", "template", "fixtures", "output"):
        parser.add_argument(f"--{name}", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--cases", nargs="+", default=["test_send", "test_send_tron", "test_transfer"])
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--packing", type=int, default=16384)
    parser.add_argument("--cache-mb", type=int, help="GPU commitment cache budget; zero forces replay")
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0:
        parser.error("--runs must be positive and --warmups nonnegative")
    if args.cache_mb is not None and args.cache_mb < 0:
        parser.error("--cache-mb must be nonnegative")
    args.output.mkdir(parents=True, exist_ok=True)
    environment = {
        **os.environ, "LIGERO_REQUIRE_GPU": "1",
        "LIGETRON_ECDSA_TEMPLATE": str(args.template),
    }
    report = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "machine": platform.machine(),
        "processor": platform.processor(), "packing": args.packing,
        "runs": args.runs, "warmups": args.warmups,
        # This is the CLI/environment default, not a fixture's override.
        "cache_mb": args.cache_mb if args.cache_mb is not None else environment.get("LIGERO_CACHE_COMMITMENTS_MB", "0"),
        "cache_mb_scope": "CLI/environment default; see case_cache for effective settings",
        "case_cache": {},
        "paths": {name: str(getattr(args, name)) for name in
                  ("prover", "verifier", "program", "shader", "template", "fixtures")},
        # Capture exact artifact provenance before any timed invocation.
        "sha256": {
            **{name: sha256_file(getattr(args, name)) for name in
               ("prover", "verifier", "program", "template")},
            "shader": {name: sha256_file(args.shader / name) for name in
                       ("bignum.wgsl", "sha256.wgsl")},
            "fixtures": {case: sha256_file(args.fixtures / f"{case}.json")
                         for case in args.cases},
        },
        "results": [], "medians": {},
    }
    for case in args.cases:
        config = json.loads((args.fixtures / f"{case}.json").read_text())
        config.update(program=str(args.program), packing=args.packing)
        config["shader-path"] = str(args.shader)
        if args.cache_mb is not None:
            config["commitment-cache-mb"] = args.cache_mb
        report["case_cache"][case] = {
            "effective_cache_mb": config.get("commitment-cache-mb", report["cache_mb"]),
            "source": ("command-line" if args.cache_mb is not None else
                       "fixture" if "commitment-cache-mb" in config else
                       "environment" if "LIGERO_CACHE_COMMITMENTS_MB" in environment else
                       "default"),
        }
        public = public_inputs(config)
        directory = args.output / case
        directory.mkdir(parents=True, exist_ok=True)
        case_runs = []
        for iteration in range(-args.warmups, args.runs):
            prove = invoke(args.prover, config, directory, environment, "prove", iteration)
            verify = invoke(args.verifier, public, directory, environment, "verify", iteration)
            run = dict(case=case, run=iteration, prove=prove, verify=verify,
                       proof_bytes=(directory / "proof_data.gz").stat().st_size)
            if iteration >= 0:
                report["results"].append(run)
                case_runs.append(run)
            print(f"{case} {iteration}: prove {prove['wall_s']:.4f}s; "
                  f"verify {verify['wall_s']:.4f}s", flush=True)
            (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        report["medians"][case] = {
            "prove": median_metrics(case_runs, "prove"),
            "verify": median_metrics(case_runs, "verify"),
            "proof_bytes": statistics.median(run["proof_bytes"] for run in case_runs),
            "constraints": case_runs[-1]["prove"]["constraints"],
        }
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["medians"], indent=2))


if __name__ == "__main__":
    main()
