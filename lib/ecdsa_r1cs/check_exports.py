#!/usr/bin/env python3
# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
"""Independently parse standard R1CS/witness files and evaluate every row.

Only Python's standard library is used. No circuit-building code is imported.
Use --mutate-wire N to alter an in-memory witness value and test rejection.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("truncated binary file")
    return data


def u32(stream):
    return struct.unpack("<I", exact(stream, 4))[0]


def u64(stream):
    return struct.unpack("<Q", exact(stream, 8))[0]


def sections(stream, magic, version, required):
    stream.seek(0, 2)
    file_size = stream.tell()
    stream.seek(0)
    if exact(stream, 4) != magic or u32(stream) != version:
        raise ValueError("wrong binary magic or version")
    count = u32(stream)
    if count != len(required):
        raise ValueError("unexpected sections; custom gates are not supported")
    result = {}
    for _ in range(count):
        kind, size = u32(stream), u64(stream)
        offset = stream.tell()
        if kind in result or kind not in required:
            raise ValueError("duplicate or unsupported binary section")
        if size > file_size - offset:
            raise ValueError("binary section extends beyond file")
        result[kind] = (offset, size)
        stream.seek(size, 1)
    if stream.tell() != file_size or set(result) != set(required):
        raise ValueError("trailing bytes or missing binary sections")
    return result


def check_exports(r1cs_path, witness_path, mutate_wire=None, expected_shape=None):
    with Path(r1cs_path).open("rb") as circuit, Path(witness_path).open("rb") as witness:
        cs_sections = sections(circuit, b"r1cs", 1, {1, 2, 3})
        ws_sections = sections(witness, b"wtns", 2, {1, 2})
        circuit.seek(cs_sections[1][0])
        field_size = u32(circuit)
        if field_size != 32 or cs_sections[1][1] != 64:
            raise ValueError("expected a 32-byte field and 64-byte R1CS header")
        prime = int.from_bytes(exact(circuit, field_size), "little")
        if prime != BN254:
            raise ValueError("expected the BN254 scalar field")
        variables = u32(circuit)
        outputs, public_inputs, private_inputs = u32(circuit), u32(circuit), u32(circuit)
        labels, constraints = u64(circuit), u32(circuit)
        if variables < 1 or outputs + public_inputs + private_inputs >= variables:
            raise ValueError("invalid R1CS variable counts")
        if labels < variables or cs_sections[3][1] != 8 * variables:
            raise ValueError("invalid wire-label map size")

        witness.seek(ws_sections[1][0])
        if ws_sections[1][1] != 40 or u32(witness) != field_size:
            raise ValueError("invalid witness header")
        if int.from_bytes(exact(witness, field_size), "little") != prime:
            raise ValueError("witness and circuit fields differ")
        if u32(witness) != variables or ws_sections[2][1] != field_size * variables:
            raise ValueError("witness and circuit variable counts differ")
        witness.seek(ws_sections[2][0])
        values = []
        for _ in range(variables):
            value = int.from_bytes(exact(witness, field_size), "little")
            if value >= prime:
                raise ValueError("noncanonical witness value")
            values.append(value)
        if values[0] != 1:
            raise ValueError("constant witness wire must equal one")
        if mutate_wire is not None:
            if not 0 < mutate_wire < variables:
                raise ValueError("mutated wire must be an existing nonconstant wire")
            values[mutate_wire] = (values[mutate_wire] + 1) % prime

        circuit.seek(cs_sections[3][0])
        for wire in range(variables):
            label = u64(circuit)
            if label >= labels or (wire == 0 and label != 0):
                raise ValueError("invalid wire-label map entry")

        shape = hashlib.sha256(b"ecdsa_r1cs:BN254:shape:v1")
        circuit.seek(cs_sections[2][0])
        rows_end = cs_sections[2][0] + cs_sections[2][1]

        def linear_combination():
            if circuit.tell() + 4 > rows_end:
                raise ValueError("constraint exceeds its section")
            count_bytes = exact(circuit, 4)
            shape.update(count_bytes)
            terms = struct.unpack("<I", count_bytes)[0]
            if terms > variables or terms * 36 > rows_end - circuit.tell():
                raise ValueError("invalid linear-combination term count")
            result, previous_wire = 0, -1
            for _ in range(terms):
                term = exact(circuit, 36)
                shape.update(term)
                wire = struct.unpack_from("<I", term)[0]
                coefficient = int.from_bytes(term[4:], "little")
                if wire >= variables or wire <= previous_wire:
                    raise ValueError("LC wires must be valid, unique, and sorted")
                if not 0 < coefficient < prime:
                    raise ValueError("LC coefficient must be nonzero and canonical")
                previous_wire = wire
                result += coefficient * values[wire]
            return result % prime

        for row in range(constraints):
            a, b, c = linear_combination(), linear_combination(), linear_combination()
            if (a * b - c) % prime:
                raise ValueError(f"unsatisfied constraint {row}")
        if circuit.tell() != rows_end:
            raise ValueError("unused bytes in constraint section")
        shape.update(struct.pack("<QQQ", variables, public_inputs, constraints))
        fingerprint = shape.hexdigest()
        if expected_shape is not None and fingerprint != expected_shape:
            raise ValueError("circuit shape fingerprint mismatch")
        return {
            "constraints": constraints,
            "variables": variables,
            "public_inputs": public_inputs,
            "public_outputs": outputs,
            "private_inputs": private_inputs,
            "shape_hash": fingerprint,
            "satisfied": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("r1cs", type=Path)
    parser.add_argument("wtns", type=Path)
    parser.add_argument("--mutate-wire", type=int)
    parser.add_argument("--expected-shape")
    args = parser.parse_args()
    try:
        result = check_exports(args.r1cs, args.wtns, args.mutate_wire, args.expected_shape)
    except (OSError, ValueError) as error:
        print(f"export check failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
