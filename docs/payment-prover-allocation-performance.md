# Payment prover allocation and interpreter follow-up

This follow-up reduces temporary allocation during ECDSA witness generation
and repeated interpreter value transfers. It builds on the
[previous performance report](payment-prover-performance.md), whose optimized
runtime is the baseline here. Constraint-template generation remains an offline
deployment step and is excluded from every runtime measurement.

## Comparison setup

- Baseline checkout: `b6a5b340e5bbf87fb91e6cf9fdc8adf242e49eab`; its runtime
  source is `f2f791aa9eaf1b1a69d270d37e39f51519a87436`.
- Candidate runtime source: `f6adb9cdfc1e7f44f65df8b9e60c9e037726fc6e`.
- Payment program: LigeroClear `4d38a643b8717e6645df35848b700512d14e8daa`.
- Machine: Apple M4 Max; macOS 26.6.2 (25G83).
- Payment comparison parameters: packing 16,384, 192 challenge samples,
  **768 MiB commitment-cache budget for both baseline and candidate** in
  EVM, TRON, transfer, and browser comparisons. The separate Stellar/Solana
  comparison uses 2,048 MiB for both versions.

Use identical synthetic fixtures, program, template, security parameters, and
cache budget. Each version uses its matching prover, verifier, witness helper,
and shader assets. Run versions serially without concurrent builds or GPU
benchmarks. This follow-up does not change the default cache policy: caching
remains optional and disabled by default. Its budget bounds cached payload,
not total process/GPU memory; memory allocation can still fail.

## Changes and invariants

`Builder::range_check()` retains the original `bits()` expansion in checked
mode, preserving every Boolean/reconstruction row and its order. In witness-only
mode, call sites that discard bit expressions append the same bit values and
wire positions directly. Width, value, builder-state, and wire-limit checks
remain. Call sites that consume bit expressions retain them. Runtime zero bits
now use GMP's default zero construction, avoiding an unnecessary limb allocation.

Linear combinations store a single `Term` inline and retain vector storage for
larger expressions. On the measured native target, an `LC` object grows from
24 to 32 bytes, while single-term expressions avoid a separate vector allocation.
`terms()` exposes an immutable borrowed span, valid only while its owning `LC`
is unchanged and alive. Moves reset their source to canonical empty storage.
Construction compacts duplicate terms and reduces noncanonical coefficients
in place. Terms remain sorted, unique, nonzero, and reduced modulo the native
field; constants and cancellations retain their previous meaning.

The interpreter constructs numeric stack entries directly and takes a numeric
path through `local.get` and `local.tee`. The existing fallback still handles
witnesses, decomposed bits, references, and invalid frame values. Managed witness
copies continue to share ownership, and the timing/order of last-owner release
is preserved. Host-module resolution is cached by each execution context, with
an owned module name checked on each use. Replacing the store or registering a
host module clears that cache; changing a function's module or name is respected.

The ECDSA relation remains **596,424 rows and 591,290 original wires**, with
20 bound interface limbs. Its pinned shape remains:

```text
44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f
```

These changes target execution and object storage. They introduce no new
witness assumption or omitted proof equation. Template authentication, public
input binding, and challenge parameters remain unchanged. The proof relation and format remain compatible across versions; validation
results are recorded below.

## Isolated CPU measurements

The witness microbenchmark prepares the public fixed-base table before timing.
Its timed region contains `verify_ecdsa()` in witness-only mode and `finish()`;
it excludes template loading/generation, witness hashing, object destruction,
the interpreter, and proof generation. Each reported variant has 14 measured
samples, retaining iterations 2–8 from two processes. Full-vector hashing occurs
outside the timed region. These are microbenchmarks, not payment proof timings.

The comparable variants in
`build/payment-perf/witness-alloc/timing-candidate2.json` give:

| Witness implementation | Median | Reduction from this round's baseline |
| --- | ---: | ---: |
| Baseline | 129.63 ms | — |
| Range-only bit generation | 105.07 ms | 18.9% |
| Range-only + inline LC + in-place normalization | 90.35 ms | 30.3% |

The inline-LC step is a further 14.0% reduction relative to the range-only
variant in the same round. An earlier range-only confirmation in
`timing-candidate1.json` measured 130.08 → 105.11 ms (19.2%).

The separate paired comparison in `timing-candidate3.json` measured
**90.84 → 89.47 ms (1.5%)** after removing zero-bit GMP allocations. Do not
combine medians from these separate rounds into a more precise aggregate
speedup. Every recorded run has 591,290 values and the same serialized witness
SHA-256:

```text
262f1cd45227e3df21517ea52fbc741b04a68f91e7be93f9c5302e1e37d3d5d1
```

The interpreter microbenchmark in `build/payment-perf/vm-tests/benchmark.log`
uses 3,000,000 iterations, one warmup, and seven measured samples:

| Isolated operation | Baseline median | Candidate median | Reduction |
| --- | ---: | ---: | ---: |
| Numeric local.get + local.tee | 23.662 ms | 19.065 ms | 19.4% |
| Host-module dispatch | 16.447 ms | 12.886 ms | 21.7% |
| Numeric stack push | 11.757 ms | 11.641 ms | 1.0% |

The stack-push difference is small and should be treated as approximately flat.
These repeated-operation results cannot be added to the witness improvement or
directly interpreted as an end-to-end proof speedup.

## Payment results

Native measurements use fresh processes on the Metal GPU, alternating version
order. EVM, TRON, and transfer have seven measured runs per version after one
warmup; Stellar and Solana have three measured runs after one warmup. All 64
paired proof/verification runs, including warmups, passed. These improvements
are incremental over the previous optimized runtime.

| Payment | Baseline prove | Candidate prove | Prove reduction | Baseline → candidate verify |
| --- | ---: | ---: | ---: | ---: |
| EVM send | 1.450 s | 1.380 s | 4.8% | 0.786 → 0.764 s |
| TRON send | 1.475 s | 1.385 s | 6.1% | 0.788 → 0.769 s |
| Transfer | 1.663 s | 1.544 s | 7.1% | 0.876 → 0.849 s |
| Stellar | 5.179 s | 4.790 s | 7.5% | 2.869 → 2.657 s |
| Solana | 5.259 s | 4.807 s | 8.6% | 2.845 → 2.656 s |

Stellar and Solana use 2,048 MiB cache budgets; the other comparisons use
768 MiB. Both versions use the same budget within each comparison. A separate
single-run candidate smoke test passed all eight payment types (FUND, EVM,
TRON, Stellar, Solana, exact send, vault, and transfer) at 768 MiB. At that smaller
budget, Stellar and Solana take about 6.6 s because Stage 3 recomputes commitments;
the 2,048 MiB results above are a separate comparison.

Native EVM diagnostics (medians, not additive totals):

| Timed component | Baseline | Candidate | Reduction |
| --- | ---: | ---: | ---: |
| Stage 1 | 684 ms | 623 ms | 8.9% |
| ECDSA private witness within Stage 1 | 176.89 ms | 135.33 ms | 23.5% |
| Public template load within Stage 1 | 136.97 ms | 137.41 ms | Approximately flat |
| Stage 2 | 543 ms | 523 ms | 3.7% |
| Stage 3 | 118 ms | 120 ms | Approximately flat |

The host's private-witness timer includes more work than the isolated CPU
microbenchmark. The interpreter changes also benefit Ed25519-based payment
execution and verification, where the secp256k1 witness path is not used.

Browser measurements use Chromium 154 with WebGPU, one excluded warmup and
three measured runs per version/payment, and fresh workers for every proof and
verification. Versions ran serially, baseline followed by candidate; both use
768 MiB caches. All 16 browser proof/verification pairs passed, including warmups.

| Version / payment | Prove preparation | Prove main | Prove end-to-end | Verify preparation | Verify main | Verify end-to-end |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline EVM | 1.637 s | 3.285 s | 4.928 s | 1.622 s | 2.160 s | 3.781 s |
| Baseline TRON | 1.638 s | 3.300 s | 4.942 s | 1.628 s | 2.212 s | 3.844 s |
| Candidate EVM | 1.651 s | 3.150 s | 4.803 s | 1.628 s | 2.097 s | 3.729 s |
| Candidate TRON | 1.655 s | 3.194 s | 4.849 s | 1.638 s | 2.133 s | 3.774 s |

Browser backend proving improved **4.1% for EVM and 3.2% for TRON**. Including
fresh-worker preparation, the improvements are **2.5% and 1.9%** respectively.
Backend verification improved 2.9% and 3.6%. Public preparation remains about
1.6 s and largely unchanged. EVM Stage 1 improved 988 → 936 ms (5.3%); its
private-witness timer improved 194.4 → 184.6 ms (5.0%), a smaller reduction than
the native path. Native microbenchmark improvements should not be extrapolated
to Wasm. These are local measurements with small sample counts, not a guarantee
for other hardware or browsers.

The completed local page is available at `http://127.0.0.1:8791/` while its server
is running. Select **Benchmark optimized + cache** for the matched-cache build
reported here; **Benchmark optimized** exercises the default uncached policy.

Native wall time includes process startup, public-template validation/loading,
and cleanup. Browser preparation includes fresh-worker asset loading, template
validation, and public table preparation; backend main excludes preparation.
Neither path generates the constraint template. Report medians of complete
runs rather than summing independently calculated phase medians.

Individual timings, medians, artifact hashes, microbenchmark results, and
validation outcomes are recorded in
[`payment-allocation-m4-max-2026-10-13.json`](../benchmarks/results/payment-allocation-m4-max-2026-10-13.json).
The embedded version banners come from earlier CMake configuration and are
stale (baseline `2f52c2b`, candidate `b6a5b34`). The explicit runtime revisions
above and the recorded SHA-256 hashes identify the measured artifacts.

## Memory tradeoff

Separate single-run `/usr/bin/time -l` measurements for EVM (all proofs verified):

| Version | Cache budget | Maximum RSS | OS peak footprint |
| --- | ---: | ---: | ---: |
| Baseline | 768 MiB | 417.0 MiB | 1120.6 MiB |
| Candidate | 768 MiB | 430.4 MiB | 1129.7 MiB |
| Candidate | 0 MiB | 423.5 MiB | 679.2 MiB |

This change reduces allocation churn; it does not reduce peak memory. With
matching caches, RSS rose by about 13 MiB and peak footprint by about 9 MiB in
these samples. Inline LCs are larger objects, and GPU/process memory also
contributes to these counters. Cache budgets describe retained payload, not a
cap on total memory. The zero-cache sample documents the existing option;
it is not the matched-cache performance comparison above.

## Reproduction

From the repository root, run the
[paired native harness](../benchmarks/compare_payment.py) with independently
built baseline/candidate artifacts. `--template` takes the raw `.r1cs` file;
`--baseline-shader` and `--candidate-shader` name shader directories.

```sh
python3 benchmarks/compare_payment.py \
  --baseline-prover /path/to/baseline/webgpu_prover \
  --baseline-verifier /path/to/baseline/webgpu_verifier \
  --baseline-shader /path/to/baseline/shader \
  --candidate-prover /path/to/candidate/webgpu_prover \
  --candidate-verifier /path/to/candidate/webgpu_verifier \
  --candidate-shader /path/to/candidate/shader \
  --program /path/to/payroll_verification.wasm \
  --template /path/to/ecdsa_secp256k1_v1.r1cs \
  --fixtures /path/to/payment-test-inputs \
  --cases test_send test_send_tron test_transfer \
  --packing 16384 --cache-mb 768 --warmups 1 --runs 7 \
  --output build/payment-allocation-native
```

The harness explicitly overrides the fixture's cache budget for both versions,
alternates their order between iterations, launches fresh processes, requires
a real GPU, and verifies every proof with masked private inputs. Its JSON records
individual timings, medians, and hashes of binaries, shaders, program, template,
and fixtures. Keep synthetic inputs: native diagnostic logs contain arguments.

For the browser, follow the
[browser harness documentation](../benchmarks/browser/README.md), supplying
both cache options explicitly:

```sh
python3 benchmarks/browser/serve.py \
  --baseline-assets /path/to/baseline/browser-assets \
  --baseline-commitment-cache-mb 768 \
  --candidate-web /path/to/candidate/web \
  --witness-build /path/to/candidate/witness-web \
  --program /path/to/payroll_verification.wasm \
  --template /path/to/ecdsa_secp256k1_v1.r1cs.gz \
  --fixtures /path/to/payment-test-inputs \
  --commitment-cache-mb 768 \
  --output build/payment-allocation-browser
```

Open `http://127.0.0.1:8789/`. The harness also offers an uncached candidate;
that variant is not the matched-cache comparison. Each version uses one
excluded warmup and three measured runs with fresh proving/verifying workers.
The server sends assets with `Cache-Control: no-store`; keep all build artifacts
unchanged throughout the session and preserve the output JSON.

## Validation

- All **13 native core tests passed**, including both ECDSA curves, exact
  checked/witness-only vectors, parallel witness serialization, template layout
  and corruption rejection, and exported witness mutation rejection.
- Range-only tests cover every width 0–200, boundary values, constant/nonconstant
  expressions, canonicalized constants, exact allocation order, and rejected
  widths/values/closed builders.
- The new LC test compares algebra with an independent map/GMP reference,
  including cancellation, negative and oversized coefficients, scalar aliasing,
  randomized expressions, copy/move transitions, and borrowed-view lifetimes.
  An independent Clang ASan/UBSan build of `r1cs.cpp` and `lc_test.cpp` also
  passed without diagnostics; command and logs are under
  `build/payment-perf2/lc-sanitizer/`.
- Native interpreter tests and their **ASan/UBSan run passed**. They check integer
  and float bit preservation (including signed zero and NaN payloads), witness
  and bit aliases, reverse release order, numeric replacement of witness locals,
  nested frames, frame traps, and context/store/module cache isolation.
- The integrated macOS suite passed **7 CPU tests and 70 Wasm/GPU tests**
  using hardware Metal. The Web interpreter ownership test also passed under
  Node; its target enables exception catching for the intentional trap tests.
- The pinned Linux GCC 13.3 build passed **13 core and 7 integrated CPU tests**.
  Both native prover and verifier built with all shared dependencies resolved.
- Browser harness validation passed **7 Node tests and 3 HTTP tests**.
- All **64 paired native runs** and **8 payment smoke runs** proved and verified
  with private inputs masked for verification. Three additional memory runs
  passed, including the candidate with commitment caching disabled.
- **6/6 cross-version checks passed**: EVM, TRON, and transfer proofs from each
  version verified under the other version's verifier.
- The candidate verifier rejected **3/3 negative cases**: changed public root,
  changed encoded-code coefficient, and changed sampled opening.
- All **16 browser proof/verification pairs passed** with private verifier
  inputs masked. The saved report contains no browser errors.

The remaining expected costs include GMP arithmetic, interpreter execution,
witness bookkeeping, public preparation, and proof serialization/compression.
The measurements isolate witness generation from complete proof timings;
further improvements need to address these remaining costs without changing
the proof relation.
