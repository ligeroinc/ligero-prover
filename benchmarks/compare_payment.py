#!/usr/bin/env python3
"""Interleaved native payment comparison with matching, masked-input verification.

Run versions serially, alternating their order between iterations. Use synthetic
fixtures: backend logs include arguments. Public template generation is excluded.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import statistics

from payment import invoke, median_metrics, public_inputs, sha256_file


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for version in ("baseline", "candidate"):
        for artifact in ("prover", "verifier", "shader"):
            parser.add_argument(f"--{version}-{artifact}", required=True, type=Path)
    for artifact in ("program", "template", "fixtures", "output"):
        parser.add_argument(f"--{artifact}", required=True, type=Path)
    parser.add_argument("--cases", nargs="+", default=["test_send", "test_send_tron", "test_transfer"])
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--packing", type=int, default=16384)
    parser.add_argument("--cache-mb", type=int, default=768)
    args = parser.parse_args()
    if args.runs < 1 or args.warmups < 0 or args.cache_mb < 0:
        parser.error("Require positive runs, nonnegative warmups and cache budget")
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    args.output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "LIGERO_REQUIRE_GPU": "1",
           "LIGETRON_ECDSA_TEMPLATE": str(args.template)}
    report = {
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(), "machine": platform.machine(),
        "runs": args.runs, "warmups": args.warmups,
        "packing": args.packing, "cache_mb": args.cache_mb,
        "ordering": "serial baseline/candidate, reversed on odd iterations",
        "sha256": {
            "program": sha256_file(args.program),
            "template": sha256_file(args.template),
            "fixtures": {case: sha256_file(args.fixtures / f"{case}.json") for case in args.cases},
        },
        "paths": {name: str(value) for name, value in vars(args).items() if isinstance(value, Path)},
        "results": [], "medians": {},
    }
    for version in ("baseline", "candidate"):
        report["sha256"][version] = {
            role: sha256_file(getattr(args, f"{version}_{role}"))
            for role in ("prover", "verifier")
        }
        report["sha256"][version]["shader"] = {
            name: sha256_file(getattr(args, f"{version}_shader") / name)
            for name in ("bignum.wgsl", "sha256.wgsl")
        }
    for case in args.cases:
        original = json.loads((args.fixtures / f"{case}.json").read_text())
        runs = {"baseline": [], "candidate": []}
        for iteration in range(-args.warmups, args.runs):
            order = ("baseline", "candidate") if iteration % 2 == 0 else ("candidate", "baseline")
            for version in order:
                config = {**original, "program": str(args.program), "packing": args.packing,
                          "shader-path": str(getattr(args, f"{version}_shader")),
                          "commitment-cache-mb": args.cache_mb}
                directory = args.output / case / version
                directory.mkdir(parents=True, exist_ok=True)
                prove = invoke(getattr(args, f"{version}_prover"), config,
                               directory, env, "prove", iteration)
                verify = invoke(getattr(args, f"{version}_verifier"), public_inputs(config),
                                directory, env, "verify", iteration)
                row = dict(case=case, version=version, run=iteration,
                           prove=prove, verify=verify,
                           proof_bytes=(directory / "proof_data.gz").stat().st_size)
                report["results"].append(row)
                if iteration >= 0:
                    runs[version].append(row)
                print(f"{case} {iteration} {version}: prove {prove['wall_s']:.4f}s; "
                      f"verify {verify['wall_s']:.4f}s", flush=True)
                (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        report["medians"][case] = {
            version: {
                "prove": median_metrics(values, "prove"),
                "verify": median_metrics(values, "verify"),
                "proof_bytes": statistics.median(value["proof_bytes"] for value in values),
                "constraints": values[-1]["prove"]["constraints"],
            }
            for version, values in runs.items()
        }
        (args.output / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["medians"], indent=2))


if __name__ == "__main__":
    main()
