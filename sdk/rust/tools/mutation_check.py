#!/usr/bin/env python3
"""Check that the SDK's soundness constraints actually bind.

A passing vm-test proves only that the constraint system is *satisfiable*. It says
nothing about whether a given assertion is load-bearing: the host oracles always
return the correct answer, so deleting an assertion that nobody else pins usually
leaves every test green. That is not hypothetical -- removing the ``r < b`` check
from ``divide_qr_normalized`` leaves the whole uint256 suite passing.

This script closes that gap the only way ordinary tests can't: it removes each
assertion in turn, rebuilds, and reruns the suites. An assertion whose removal
still leaves everything passing is **SURVIVED** -- nothing in the test suite
depends on it, so a regression that silently drops it would go unnoticed.

Verdicts come from ``tests_wasm/run.sh``, not from the prover directly. That is
load-bearing now that negative suites exist: for them a *failed* proof is the
pass, so reading "Final prove result" here would score every one of them exactly
backwards. run.sh already knows the polarity, and also fails on constraint-count
DRIFT -- which is a test noticing, and so counts as a kill.

Mutation is the tool of LAST RESORT. Where an assertion guards user-supplied data
or oracle output, a negative test in tests_wasm/negative_* is strictly better:
permanent, in CI, and it says what the assertion is for. Use this to find out
WHICH assertions still lack one.

Usage, from sdk/rust:

    python3 tools/mutation_check.py                 # default targets
    python3 tools/mutation_check.py --files src/ff/storage.rs --tests prime_field_test
    python3 tools/mutation_check.py --list          # show mutation points, run nothing

Requires webgpu_prover built at ../../build (override with --build-dir).

MUTATED FILES ARE RESTORED ON A CLEAN EXIT OR Ctrl-C -- but NOT if the process is
killed outright. A SIGKILL, or a harness/CI step that times the run out, skips the
``finally`` block and leaves a soundness assertion COMMENTED OUT in your working
tree. That happened twice while this suite was being written. Two consequences:

  * run this in the background, not under anything that may time it out; and
  * after any interruption, ``grep -rn "// MUTATED" src/``.

This script refuses to start if it finds residue, rather than measuring against a
tree that is already sabotaged.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Calls that emit a binding constraint. Range checks count: dropping one lets an
# out-of-range witness through just as surely as dropping an equality.
ASSERT_RE = re.compile(
    r"(?:raw::)?(?:assert_equal(?:_u32|_u64|_bytes)?|check_bits(?:_signed)?|assert_one)\s*\(|"
    r"Bn254Fr::assert_(?:equal|add|mul|mulc)\s*\("
)

DEFAULT_FILES = ["src/uint256.rs", "src/bn254fr_bigint.rs"]
DEFAULT_TESTS = ["uint256_test", "bn254fr_bigint_test"]


def find_points(path: Path) -> list[tuple[int, int, str]]:
    """Return (start, end, text) line spans, 0-based and end-exclusive."""
    lines = path.read_text().split("\n")
    points = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        is_defn = re.match(r"(pub(\([a-z]+\))?\s+)?(unsafe\s+)?fn\s", stripped) is not None
        if not stripped.startswith("//") and not is_defn and ASSERT_RE.search(lines[i]):
            # a call may wrap; consume until the statement terminates
            j = i
            while j < len(lines) and not lines[j].rstrip().endswith(";"):
                j += 1
            j = min(j + 1, len(lines))
            points.append((i, j, "\n".join(lines[i:j]).strip()))
            i = j
            continue
        i += 1
    return points


def mutate(path: Path, start: int, end: int) -> None:
    lines = path.read_text().split("\n")
    for k in range(start, end):
        indent = len(lines[k]) - len(lines[k].lstrip())
        lines[k] = lines[k][:indent] + "// MUTATED " + lines[k][indent:]
    path.write_text("\n".join(lines))


def run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", nargs="+", default=DEFAULT_FILES)
    ap.add_argument("--tests", nargs="+", default=DEFAULT_TESTS)
    ap.add_argument("--build-dir", default="../../build")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    build_dir = Path(args.build_dir).resolve()
    prover = build_dir / "webgpu_prover"
    if not args.list and not prover.exists():
        print(f"webgpu_prover not found at {prover}", file=sys.stderr)
        return 2

    # Residue from a previous run that was killed before its restore. Measuring against
    # this would score every mutant relative to an already-broken baseline.
    residue = []
    for f in args.files:
        p = Path(f)
        if p.exists():
            residue += [f"{f}:{i + 1}" for i, ln in enumerate(p.read_text().split("\n"))
                        if ln.lstrip().startswith("// MUTATED ")]
    if residue:
        print("refusing to run: leftover mutations from an interrupted run", file=sys.stderr)
        for r in residue:
            print(f"  {r}", file=sys.stderr)
        print("uncomment them (or restore from git) and re-run.", file=sys.stderr)
        return 2

    targets = []
    for f in args.files:
        p = Path(f)
        if not p.exists():
            print(f"no such file: {f}", file=sys.stderr)
            return 2
        for start, end, text in find_points(p):
            targets.append((p, start, end, text))

    print(f"{len(targets)} mutation points across {len(args.files)} file(s)\n")
    if args.list:
        for p, start, _, text in targets:
            print(f"  {p}:{start + 1}  {text.splitlines()[0]}")
        return 0

    # Two passes, into separate target dirs. Enabling fault-injection changes lib
    # codegen and therefore the constraint counts, so the positive suites must be
    # built without it -- see the note at the top of tests_wasm/run.sh.
    base = ["cargo", "build", "--target", "wasm32-wasip1", "--release", "--features"]
    builds = [
        base + ["vm-tests", "--bins"],
        base + ["vm-tests,fault-injection", "--bins",
                "--target-dir", "target/fault-injection"],
    ]

    def rebuild():
        """True if both passes compiled."""
        return all(run(cmd)[0] == 0 for cmd in builds)

    def suites_pass():
        """run.sh's own verdict. Exit 0 means every named suite behaved as specified --
        which for a negative suite means it FAILED to prove."""
        rc, _ = run(["tests_wasm/run.sh", *args.tests])
        return rc == 0

    if not rebuild():
        print("baseline build failed; fix the tree first", file=sys.stderr)
        return 2
    if not suites_pass():
        print("baseline FAILED; fix the tree first (run tests_wasm/run.sh)", file=sys.stderr)
        return 2
    print("baseline: all suites behave as specified\n")

    survived, killed, skipped = [], 0, []
    backups = {p: tempfile.NamedTemporaryFile(delete=False).name for p, _, _, _ in targets}
    for p, name in backups.items():
        shutil.copy(p, name)

    try:
        for n, (path, start, end, text) in enumerate(targets, 1):
            head = text.splitlines()[0][:72]
            print(f"[{n}/{len(targets)}] {path}:{start + 1}  {head}", flush=True)

            mutate(path, start, end)
            if not rebuild():
                shutil.copy(backups[path], path)
                skipped.append((path, start + 1, head))
                print("      SKIPPED (does not compile without it)\n", flush=True)
                continue

            verdict = "SURVIVED" if suites_pass() else "killed"
            shutil.copy(backups[path], path)
            if verdict == "SURVIVED":
                survived.append((path, start + 1, head))
                print("      *** SURVIVED -- no test depends on this assertion\n", flush=True)
            else:
                killed += 1
                print("      killed\n", flush=True)
    finally:
        for p, name in backups.items():
            shutil.copy(name, p)
        rebuild()

    print("=" * 78)
    print(f"killed {killed}   survived {len(survived)}   skipped {len(skipped)}")
    if skipped:
        print("\nSkipped (removal breaks the build -- check by hand):")
        for path, line, head in skipped:
            print(f"  {path}:{line}  {head}")
    if survived:
        print("\nSURVIVED -- add a negative test in tests_wasm/ that fails when these go:")
        for path, line, head in survived:
            print(f"  {path}:{line}  {head}")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
