#!/usr/bin/env python3
"""Prove a test signature, verify with private placeholders, and reject mutations.

Requires a built native backend, shader directory, SDK example, and template.
Artifacts and logs stay in --output; no network or application data is used.
"""
# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
import argparse
import json
import os
import re
from pathlib import Path
import subprocess


def fixture():
    p = 2**256 - 2**32 - 977
    n = int('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 16)
    generator = (
        int('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 16),
        int('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 16),
    )

    def add(a, b):
        if a is None:
            return b
        if b is None:
            return a
        x, y = a
        u, v = b
        if x == u and (y + v) % p == 0:
            return None
        slope = ((3 * x * x) * pow(2 * y, -1, p) if a == b
                 else (v - y) * pow(u - x, -1, p)) % p
        w = (slope * slope - x - u) % p
        return w, (slope * (x - w) - y) % p

    def multiply(k):
        point, result = generator, None
        while k:
            if k & 1:
                result = add(result, point)
            point = add(point, point)
            k >>= 1
        return result

    # Public deterministic test data, never a production signing routine.
    secret, nonce = 7, 11
    digest = int('0123456789abcdef' * 4, 16)
    qx, qy = multiply(secret)
    r = multiply(nonce)[0] % n
    s = ((digest + r * secret) * pow(nonce, -1, n)) % n
    s = min(s, n - s)
    return qx, qy, r, s, digest, n


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prover', 'verifier', 'program', 'template', 'shader-path', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    env['LIGERO_REQUIRE_GPU'] = '1'
    env['LIGETRON_ECDSA_TEMPLATE'] = str(args.template.resolve())
    qx, qy, r, s, digest, n = fixture()
    config = {
        'program': str(args.program.resolve()),
        'shader-path': str(args.shader_path.resolve()),
        'packing': 8192,
        'private-indices': [2],
        'args': [{'hex': f'{qx:064x}{qy:064x}'}, {'hex': f'{r:064x}{s:064x}'},
                 {'hex': f'{digest:064x}'}],
    }

    def run(name, binary, cfg, succeeds, prover=False):
        path = output / (name + '.json')
        path.write_text(json.dumps(cfg, indent=2) + '\n')
        result = subprocess.run([str(binary.resolve()), json.dumps(cfg)], cwd=output,
                                env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=180)
        (output / (name + '.log')).write_text(result.stdout)
        label = 'Final prove result:' if prover else 'Final Verify Result:'
        passed = result.returncode == 0 and re.search(label + r'\s*true\b', result.stdout) is not None
        if passed != succeeds:
            raise RuntimeError(f'{name}: unexpected outcome; see {output / (name + ".log")}')
        if not succeeds and not re.search(label + r'\s*false\b', result.stdout):
            raise RuntimeError(name + ': failed before cryptographic verification')
        if succeeds:
            expected = 3 if prover else 1
            if result.stdout.count('ECDSA R1CS rows: 596424') != expected:
                raise RuntimeError(name + ': missing fixed relation in a proof stage')
        print('PASS: ' + name)

    run('prove', args.prover, config, True, prover=True)
    public = json.loads(json.dumps(config))
    public['args'][1]['hex'] = '00' * 64
    run('verify-private-placeholders', args.verifier, public, True)
    changed = json.loads(json.dumps(public))
    changed['args'][2]['hex'] = f'{digest ^ 1:064x}'
    run('reject-changed-digest', args.verifier, changed, False)
    # Valid empty custom section: changes exact program bytes without changing
    # execution, so rejection exercises the program binding specifically.
    modified = output / 'changed-program.wasm'
    modified.write_bytes(args.program.read_bytes() + b'\x00\x02\x01x')
    changed = json.loads(json.dumps(public))
    changed['program'] = str(modified)
    run('reject-changed-program', args.verifier, changed, False)
    changed = json.loads(json.dumps(config))
    changed['args'][1]['hex'] = f'{r:064x}{n-s:064x}'
    run('reject-high-s', args.prover, changed, False, prover=True)


if __name__ == '__main__':
    main()
