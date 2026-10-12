#!/usr/bin/env python3
# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
"""Run the arithmetic fixture and independently reject modified witnesses."""

import argparse
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True
CHECKER_PATH = Path(__file__).with_name("check_exports.py")
SPEC = importlib.util.spec_from_file_location("ecdsa_export_checker", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def reject(r1cs, witness, label, **kwargs):
    try:
        CHECKER.check_exports(r1cs, witness, **kwargs)
    except ValueError as error:
        # Parsing errors do not demonstrate arithmetic rejection. The modified
        # witness must remain structurally valid and fail an actual R1CS row.
        require(str(error).startswith("unsatisfied constraint "),
                f"{label}: rejected for the wrong reason: {error}")
        print(f"{label}: {error}")
    else:
        raise RuntimeError(f"{label}: invalid witness was accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arithmetic_test", type=Path)
    parser.add_argument("export_prefix", type=Path)
    args = parser.parse_args()
    args.export_prefix.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([str(args.arithmetic_test.resolve()), str(args.export_prefix)],
                            check=True, text=True, capture_output=True)
    print(result.stdout, end="")
    match = re.search(r"mutation wires: quotient_first=(\d+) quotient_last=(\d+) "
                      r"carry_first=(\d+) carry_last=(\d+)", result.stdout)
    require(match is not None, "arithmetic fixture did not report mutation wires")
    names = ("quotient_first", "quotient_last", "carry_first", "carry_last")
    wires = dict(zip(names, map(int, match.groups())))
    shape = re.search(r"shape ([0-9a-f]{64})", result.stdout)
    require(shape is not None, "arithmetic fixture did not report its circuit hash")
    r1cs = Path(str(args.export_prefix) + ".r1cs")
    witness = Path(str(args.export_prefix) + ".wtns")
    original = CHECKER.check_exports(r1cs, witness, expected_shape=shape.group(1))
    print(f"original: {original['constraints']} constraints satisfied")

    for label, wire in wires.items():
        reject(r1cs, witness, label, mutate_wire=wire)

    with witness.open("rb") as stream:
        section_map = CHECKER.sections(stream, b"wtns", 2, {1, 2})
    witness_offset = section_map[2][0]
    source = witness.read_bytes()
    with tempfile.TemporaryDirectory(prefix="ecdsa-r1cs-mutations-") as directory:
        for label, width in (("quotient_first", 64), ("carry_first", 72)):
            wire = wires[label]
            changed = bytearray(source)
            offset = witness_offset + wire * 32
            replacement = int.from_bytes(changed[offset:offset + 32], "little") + 1
            require(replacement < (1 << width), f"{label}: mutation exceeds range")
            changed[offset:offset + 32] = replacement.to_bytes(32, "little")
            for bit in range(width):
                offset = witness_offset + (wire + 1 + bit) * 32
                changed[offset:offset + 32] = ((replacement >> bit) & 1).to_bytes(32, "little")
            target = Path(directory) / (label + ".wtns")
            target.write_bytes(changed)
            reject(r1cs, target, label + " with matching decomposition bits")
    print("all exported witness mutation tests passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"export mutation test failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stdout or "", end="", file=sys.stderr)
            print(error.stderr or "", end="", file=sys.stderr)
        sys.exit(1)
