#!/usr/bin/env python3
"""Generate and verify the Rust generator precompute tables.

The C++ SDK ships each curve's generator table as ~1.15 MB of hex strings in
``sdk/cpp/src/ecc/curves/<curve>_precomp.inc``, parsed into field elements at
runtime. The Rust SDK instead embeds them as little-endian byte constants, which
is both faster (no parsing) and roughly half the size.

Two modes:

  transcribe  convert a .inc into a checked-in .rs
  verify      independently recompute [j * 2^(8w)] G and diff against the .inc

``verify`` exists because these tables have shipped wrong before (commit 06508d6,
"fix incorrect generator precompute table values"). It reimplements the curve
arithmetic from scratch with Python integers, so it is a genuine cross-check
rather than a restatement of the same code.

Usage:

    python3 tools/gen_precomp.py transcribe \\
        --inc ../cpp/src/ecc/curves/ed25519_precomp.inc \\
        --name ED25519_G_PRECOMP \\
        --out src/ecc/curves/ed25519_precomp.rs

    python3 tools/gen_precomp.py verify --curve ed25519 \\
        --inc ../cpp/src/ecc/curves/ed25519_precomp.inc
"""

import argparse
import re
import sys

# Table geometry, shared by all three curves: 8-bit windows, 32 windows,
# 256 entries per window. Row w*256 + j holds [j * 2^(8w)] G.
BITS = 8
WINDOWS = 32
ENTRIES = 1 << BITS
TOTAL = WINDOWS * ENTRIES

ROW_RE = re.compile(r'\{\s*"(0x[0-9a-fA-F]+)"\s*,\s*"(0x[0-9a-fA-F]+)"\s*\}')

# --- curve parameters, for `verify` only -----------------------------------

CURVES = {
    "p256": {
        "kind": "weierstrass",
        "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        "gx": 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        "gy": 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    },
    "secp256k1": {
        "kind": "weierstrass",
        "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        "a": 0,
        "b": 7,
        "gx": 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        "gy": 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    },
    "ed25519": {
        "kind": "edwards",
        "p": (1 << 255) - 19,
        "d": 0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3,
        "gx": 0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A,
        "gy": 0x6666666666666666666666666666666666666666666666666666666666666658,
    },
}


def parse_inc(path):
    """Read a .inc file into a list of (x, y) integer pairs."""
    rows = []
    with open(path) as fh:
        for line in fh:
            m = ROW_RE.search(line)
            if m:
                rows.append((int(m.group(1), 16), int(m.group(2), 16)))
    if len(rows) != TOTAL:
        sys.exit(f"{path}: expected {TOTAL} rows, found {len(rows)}")
    return rows


# --- reference curve arithmetic, for `verify` ------------------------------


def w_add(P, Q, p, a):
    """Short Weierstrass affine addition with the (0, 0) sentinel identity."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def e_add(P, Q, p, d):
    """Twisted Edwards (a = -1) complete affine addition."""
    x1, y1 = P
    x2, y2 = Q
    dxy = d * x1 * x2 * y1 * y2 % p
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxy, -1, p) % p
    return (x3, y3)


def build_reference(curve):
    """Recompute the whole table from the generator, independently of the .inc."""
    c = CURVES[curve]
    p = c["p"]
    out = []
    if c["kind"] == "weierstrass":
        base = (c["gx"], c["gy"])
        for w in range(WINDOWS):
            acc = None  # identity
            for _ in range(ENTRIES):
                out.append((0, 0) if acc is None else acc)
                acc = w_add(acc, base, p, c["a"])
            # advance base by 2^8 for the next window
            for _ in range(BITS):
                base = w_add(base, base, p, c["a"])
    else:
        ident = (0, 1)
        base = (c["gx"], c["gy"])
        for w in range(WINDOWS):
            acc = ident
            for _ in range(ENTRIES):
                out.append(acc)
                acc = e_add(acc, base, p, c["d"])
            for _ in range(BITS):
                base = e_add(base, base, p, c["d"])
    return out


# --- modes -----------------------------------------------------------------


def transcribe(args):
    rows = parse_inc(args.inc)

    def le32(v):
        return v.to_bytes(32, "little")

    parts = [
        "/*\n"
        " * Copyright (C) 2023-2026 Ligero, Inc.\n"
        " *\n"
        ' * Licensed under the Apache License, Version 2.0 (the "License");\n'
        " * you may not use this file except in compliance with the License.\n"
        " * You may obtain a copy of the License at\n"
        " *\n"
        " *     http://www.apache.org/licenses/LICENSE-2.0\n"
        " *\n"
        " * Unless required by applicable law or agreed to in writing, software\n"
        ' * distributed under the License is distributed on an "AS IS" BASIS,\n'
        " * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
        " * See the License for the specific language governing permissions and\n"
        " * limitations under the License.\n"
        " */\n\n"
        f"//! @generated by `tools/gen_precomp.py` from `{args.inc}` — DO NOT EDIT.\n"
        "//!\n"
        "//! Regenerate with:\n"
        "//!\n"
        "//! ```text\n"
        f"//! python3 tools/gen_precomp.py transcribe \\\n"
        f"//!     --inc {args.inc} --name {args.name} --out {args.out}\n"
        "//! ```\n"
        "//!\n"
        f"//! Layout: row `w * {ENTRIES} + j` holds `[j * 2^({BITS}w)] G` as affine `(x, y)`,\n"
        "//! each coordinate 32 bytes little-endian. Row `j = 0` of every window is the curve\n"
        "//! identity — `(0, 0)` for Weierstrass curves, `(0, 1)` for Ed25519.\n\n"
        "#[rustfmt::skip]\n"
        f"pub static {args.name}: [[[u8; 32]; 2]; {TOTAL}] = [\n"
    ]

    for x, y in rows:
        xb = ",".join(str(b) for b in le32(x))
        yb = ",".join(str(b) for b in le32(y))
        parts.append(f"    [[{xb}],[{yb}]],\n")
    parts.append("];\n")

    with open(args.out, "w") as fh:
        fh.write("".join(parts))
    print(f"wrote {args.out}: {TOTAL} entries")


def verify(args):
    rows = parse_inc(args.inc)
    ref = build_reference(args.curve)
    bad = 0
    for i, (got, want) in enumerate(zip(rows, ref)):
        if got != want:
            bad += 1
            if bad <= 5:
                w, j = divmod(i, ENTRIES)
                print(f"MISMATCH row {i} (window {w}, index {j})")
                print(f"  inc:  ({hex(got[0])}, {hex(got[1])})")
                print(f"  ref:  ({hex(want[0])}, {hex(want[1])})")
    if bad:
        sys.exit(f"{bad} mismatching rows")
    print(f"{args.curve}: all {TOTAL} entries match the independent recomputation")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="mode", required=True)

    t = sub.add_parser("transcribe")
    t.add_argument("--inc", required=True)
    t.add_argument("--name", required=True)
    t.add_argument("--out", required=True)
    t.set_defaults(func=transcribe)

    v = sub.add_parser("verify")
    v.add_argument("--inc", required=True)
    v.add_argument("--curve", required=True, choices=sorted(CURVES))
    v.set_defaults(func=verify)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
