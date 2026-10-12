#!/usr/bin/env python3
# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
"""Verify the template loader rejects changed rows, metadata, and truncation."""

import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('asset', type=Path)
    args = parser.parse_args()
    binary, asset = args.binary.resolve(), args.asset.resolve()
    subprocess.run([str(binary), '--validate', str(asset)], check=True)
    with tempfile.TemporaryDirectory(prefix='template-test-', dir=asset.parent) as directory:
        changed = Path(directory) / 'changed.r1cs'
        cases = ((108, 'ECDSA R1CS template shape hash mismatch'),
                 (60, 'unexpected ECDSA R1CS template counts'),
                 (None, 'unexpected ECDSA R1CS template size'))
        for offset, expected in cases:
            shutil.copyfile(asset, changed)
            with changed.open('r+b') as stream:
                if offset is None:
                    stream.truncate(asset.stat().st_size - 1)
                else:
                    stream.seek(offset)
                    original = stream.read(1)[0]
                    stream.seek(offset)
                    stream.write(bytes([original ^ 1]))
            result = subprocess.run([str(binary), '--validate', str(changed)],
                                    text=True, capture_output=True)
            if result.returncode == 0 or expected not in result.stderr:
                raise RuntimeError('template corruption was not rejected as expected: ' + result.stderr)
            print('PASS: ' + expected)


if __name__ == '__main__':
    main()
