# Payment prover performance

This work reduces the runtime and memory cost of the optimized secp256k1
payment circuit. It retains the same standard R1CS relation and proof security
parameters. Public constraint-template generation remains a deployment step.

## Comparison setup

- Backend baseline: `2f52c2b18c30c2ab8f51fef20b9d8963a9007f5d`.
- Optimized runtime source: `f2f791aa9eaf1b1a69d270d37e39f51519a87436`.
- Payment program: LigeroClear `4d38a643b8717e6645df35848b700512d14e8daa`.
- Machine: Apple M4 Max, 16 reported hardware threads, macOS 26.6.2 (25G83).
- Browser: Chromium 154.0.0.0 in the in-app browser.
- Packing: 16,384; challenge samples: 192.
- Native cases: EVM send, TRON send, and transfer. Browser cases: EVM and TRON send.

The evidence manifest records exact artifact hashes. Candidate CMake build
directories were configured before the source commit was created, so their
embedded version banner still names the baseline revision; the candidate
binaries contain the optimized source revision above.

Use identical synthetic fixtures, payment WASM, public template, and packing for
each comparison. Each backend must use its corresponding shader assets. Run
versions serially, without concurrent builds or other GPU benchmarks.

Native measurements launch a fresh prover and verifier process for each run;
the example below uses one excluded warmup and five measured runs. Browser
measurements use fresh workers, one excluded warmup, and three measured runs.
Warmups warm system/browser/GPU caches; they do not retain the ECDSA runtime
between measured proofs. Report medians, retaining individual runs.

Every accepted run must produce a successful proof and verify it with private
arguments replaced by equal-length placeholders. Native wall time includes
process startup, public-template loading/validation, and cleanup. Browser
reports preparation, backend main, and end-to-end time separately. Preparation
includes runtime/program loading, public-template validation, and public table
preparation. Main excludes that preparation. Neither benchmark generates the
constraint template. Stage timings are diagnostic subphases and should not
replace end-to-end measurements.

## Results

Native results below are medians of five measured runs after one excluded
warmup, using the revisions and hardware above. Times are seconds and include
fresh-process startup and public-template loading, but no template generation.

| Payment | Backend | Prove wall | Verify wall |
| --- | --- | ---: | ---: |
| EVM | Baseline | 3.030 | 1.423 |
| EVM | Optimized, cache off | 1.688 | 0.759 |
| EVM | Optimized, 768 MiB cache | 1.422 | 0.757 |
| TRON | Baseline | 3.068 | 1.440 |
| TRON | Optimized, cache off | 1.723 | 0.756 |
| TRON | Optimized, 768 MiB cache | 1.413 | 0.767 |
| Transfer | Baseline | 3.378 | 1.542 |
| Transfer | Optimized, cache off | 1.989 | 0.852 |
| Transfer | Optimized, 768 MiB cache | 1.604 | 0.846 |

Native proving improves by 1.70–1.80x with the cache disabled and 2.11–2.17x
with the cache enabled. Verification improves by 1.82–1.88x. All measured
proofs and warmups verified with masked private inputs.

Native EVM diagnostic phase medians:

| Backend | Stage 1 | Stage 2 | Stage 3 |
| --- | ---: | ---: | ---: |
| Baseline | 1.340 s | 0.850 s | 0.587 s |
| Optimized, cache off | 0.640 s | 0.522 s | 0.411 s |
| Optimized, 768 MiB cache | 0.659 s | 0.536 s | 0.116 s |

The cached Stage 3 execution takes 8 ms, with roughly 106 ms left in proof
compression/write. Native Stage 1 includes public-template decoding; the
browser phase table below excludes that preparation. Medians of separate
phases do not sum exactly to the wall-time median.

Within native EVM Stage 1, the timed ECDSA witness-generation call falls from
467 ms to 172 ms, and public-template loading/validation falls from 378 ms to
132 ms in the cache-enabled comparison. Both are included in native wall time.

All eight payment fixtures also passed a single native proof/verification
coverage run with a 768 MiB cache budget. These are individual observations,
not repeated-run medians:

| Payment fixture | Prove wall | Verify wall |
| --- | ---: | ---: |
| FUND/disburse | 0.481 s | 0.274 s |
| EVM send | 1.386 s | 0.769 s |
| TRON send | 1.403 s | 0.756 s |
| Stellar send | 7.084 s | 2.731 s |
| Solana send | 6.956 s | 2.761 s |
| Exact send | 1.248 s | 0.676 s |
| Vault | 1.362 s | 0.730 s |
| Transfer | 1.576 s | 0.840 s |

Stellar and Solana exceed this cache budget and correctly use Stage 3 replay.
A separate EVM run with a deliberately insufficient 1 MiB budget also fell
back to replay and verified, taking 1.686 seconds to prove.

A separate three-run comparison after one excluded warmup used a 2,048 MiB
cache budget for Stellar and Solana. Each retained 698 commitment rows,
requiring 1,396 MiB of cached payload:

| Payment | Backend | Prove wall | Verify wall |
| --- | --- | ---: | ---: |
| Stellar | Baseline | 7.631 s | 3.060 s |
| Stellar | Optimized, 2,048 MiB cache | 5.029 s | 2.821 s |
| Solana | Baseline | 7.597 s | 3.018 s |
| Solana | Optimized, 2,048 MiB cache | 5.015 s | 2.725 s |

These Ed25519 payment paths improve by about 1.51–1.52x in proving, less than
the secp256k1 paths. All proofs verified; the larger budget is a measurement
configuration, not a new default.

For TRON, a packing sweep used one excluded warmup and three measured runs at
8,192 and 32,768; the 16,384 entry is from the five-run comparison above:

| Packing | Prove wall | Verify wall | Median compressed proof bytes |
| --- | ---: | ---: | ---: |
| 8,192 | 1.475 s | 0.744 s | 5,148,602 |
| 16,384 | 1.413 s | 0.767 s | 6,930,403 |
| 32,768 | 1.577 s | 0.841 s | 12,225,331 |

Packing 16,384 was fastest for proving in this sweep. Packing 8,192 reduced
compressed proof size by 25.7%, with 4.5% longer proving time. The main results
retain the original packing of 16,384.

Browser results are recorded in the
[benchmark evidence](../benchmarks/results/payment-m4-max-2026-10-12.json),
completed 2026-10-12 UTC. The raw local browser report is
`build/payment-perf/browser-portable/results.json`. All 24 proofs and 24
masked-input verifications passed, including warmups. Each table entry is the median of three measured runs;
times are seconds, rounded to three decimals. Preparation and end-to-end
measurements use fresh workers.

| Payment | Backend | Proof prep | Proof main | Proof end-to-end | Verify prep | Verify main | Verify end-to-end |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| EVM | Baseline | 4.148 | 8.582 | 12.734 | 4.143 | 4.641 | 8.807 |
| EVM | Optimized, cache off | 1.599 | 3.801 | 5.400 | 1.589 | 2.066 | 3.659 |
| EVM | Optimized, 768 MiB cache | 1.597 | 3.144 | 4.745 | 1.588 | 2.070 | 3.659 |
| TRON | Baseline | 4.148 | 8.553 | 12.702 | 4.144 | 4.687 | 8.834 |
| TRON | Optimized, cache off | 1.600 | 3.875 | 5.482 | 1.586 | 2.109 | 3.700 |
| TRON | Optimized, 768 MiB cache | 1.594 | 3.186 | 4.788 | 1.589 | 2.118 | 3.706 |

Across these two cases, cache-off proof main time fell 54.7–55.7% and
end-to-end time fell 56.8–57.6%. With the cache, the reductions were
62.7–63.4% and 62.3–62.7%, respectively. The cache affects proving only;
verification differences between optimized variants reflect separate runs.

The server uses `Cache-Control: no-store` for local asset fetches, and each
worker performs fresh preparation. The roughly 1.60-second optimized preparation
versus 4.15 seconds at baseline includes loading, decompression, validation,
compact template decoding, and public table preparation; it is **not constraint
template generation**. OS filesystem and GPU caches may still be warm.

EVM proof-stage medians show the remaining bottleneck:

| Backend | Stage 1 | Stage 2 | Stage 3 |
| --- | ---: | ---: | ---: |
| Baseline | 2.179 s | 3.937 s | 1.828 s |
| Optimized, cache off | 0.969 s | 1.898 s | 0.809 s |
| Optimized, 768 MiB cache | 0.967 s | 1.891 s | 0.158 s |

Stage 2 is now the largest main-call component. Cached Stage 3 spends about
12 ms gathering committed columns, followed by serialization and compression;
the uncached execution/replay portion takes about 665 ms. These stage medians
exclude preparation and separately timed setup/readback, and are computed
independently rather than summed to obtain end-to-end time.

## Changes

- Compact the authenticated public template into flat term storage, intern
  repeated coefficients, and derive each auxiliary wire's final use. Import each
  32-byte coefficient as four explicitly little-endian 64-bit words, preserving
  the serialized integer on every host architecture.
- Allocate auxiliary handles on first use, release them after final use, and
  reuse unit linear expressions directly. The witness manager preserves aliases
  by cloning handles when quadratic slots require separate instances.
- Skip the inactive challenge-weighting loop in Stage 1 and Stage 3. These
  passes still compute and commit identical values in the same order; Stage 2
  and verification retain every challenge-weighted equation. An isolated native
  host pass improved by 12.35% (about 8.9 ms saved), with all committed cells
  identical. This is an isolated measurement, not an end-to-end speedup.
- Build long canonicality-check expressions once, move temporary bit expressions,
  and avoid unnecessary GMP reductions and intermediate products during witness generation.
- Hash integer vectors in one update and use GMP's public limb APIs for equivalent
  byte import/export on supported little-endian builds. Bound 64-bit extraction
  so larger GMP values cannot overflow its destination.
- Use GMP multiplication/remainder for BN254 products, including aliased outputs;
  remove repeated host-dispatch string copies and reserve interpreter local storage.
- Avoid unused GMP decoding and read back only the decoded coefficients needed
  for validation. Optimize GPU hashing and offer optional commitment caching.
- Apply Emscripten `-O3` at link time as well as compilation. Asyncify remains
  enabled with its existing boundaries; no indirect-call exclusions were added.

### Optional commitment cache

The cache is **off by default**. Set the prover JSON field
`"commitment-cache-mb": 768` or, for native runs,
`LIGERO_CACHE_COMMITMENTS_MB=768` to allow up to 768 MiB of cached encoded
commitment payload. The JSON setting takes precedence; zero forces replay.

Caching retains the exact Stage 1 commitment rows and gathers the challenged
columns in Stage 3, avoiding another guest execution. Exceeding the configured
budget discards the cache and uses ordinary Stage 3 replay. The budget bounds
cached payload, not total GPU/process memory: other buffers and allocator
overhead remain, and GPU allocation failure can still fail a proof. Choose a
budget appropriate to the deployment device.

The EVM and TRON fixtures retain 440 MiB and 448 MiB of payload, respectively.
Separate native EVM memory observations from `/usr/bin/time -l` are below;
each proof was verified. These are single observations, not median timings.
RSS alone does not account for all GPU memory.

| Backend | Maximum RSS | Peak memory footprint |
| --- | ---: | ---: |
| Baseline | 912 MiB | 1,167 MiB |
| Optimized, cache off | 416 MiB | 679 MiB |
| Optimized, 768 MiB cache | 417 MiB | 1,122 MiB |

## Invariants and compatibility

The ECDSA relation still has **596,424 R1CS rows, 591,290 original wires, and
20 bound interface limbs**. Its pinned shape is unchanged:

```text
44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f
```

The exact template size, field, metadata, labels, canonical terms, and shape
hash remain validated. Compact decoding occurs after row authentication.
Coefficient IDs follow first occurrence in row order, independently of hash-table
iteration or GMP limb width. Allocation/release decisions depend on the public
template, not witness values. Guest-owned input handles remain bound and live.

Range, curve, low-S, scalar, and signature equations remain enforced by the
composed proof. Fast witness generation does not replace those checks. Statement
binding to the program, public inputs, and pinned circuit remains in place.
Sampling parameters and transcript domains are unchanged.

**Deploy matching optimized prover and verifier backends together.** The host's
linear-copy and packing schedule changes even though the R1CS relation is
unchanged. Proof interoperability with the baseline backend is not promised.
Linear witness-cell counts are distinct from standard R1CS row counts.

## Reproduce

Build each backend revision using the normal repository instructions and keep
its binaries/shaders separately. Generate the raw public template once as
described in [the ECDSA integration guide](ecdsa-r1cs.md). From the repository root:

```sh
python3 benchmarks/payment.py \
  --prover /path/to/optimized/webgpu_prover \
  --verifier /path/to/optimized/webgpu_verifier \
  --program /path/to/payroll_verification.wasm \
  --shader /path/to/optimized/shader \
  --template /path/to/ecdsa_secp256k1_v1.r1cs \
  --fixtures /path/to/payment-test-inputs \
  --output build/payment-benchmark-optimized \
  --packing 16384 --warmups 1 --runs 5 --cache-mb 0
```

Repeat with the baseline binary/shader paths and a separate output directory.
For an optimized cache comparison, use `--cache-mb 768` and another directory.
The harness requires a hardware GPU and records UTC start time, machine/OS,
artifact paths, and SHA-256 hashes of both binaries, program, template, both
shader files, and selected fixture JSONs. `cache_mb` records the CLI/environment
default; `case_cache` records each case's effective configured budget and its
source, including fixture overrides. Provenance hashing occurs outside timed
invocations. Keep selected assets unchanged during a run. Logs include backend
arguments, so use synthetic fixtures.

See [the browser benchmark instructions](../benchmarks/browser/README.md) for
asset serving, fresh-worker comparisons, and saved JSON results.

## Validation and remaining work

All 12 core tests and six native CPU tests passed, as did the hardware Metal
SHA/cache test. Coverage includes circuit and witness equivalence, mutation
rejection, exact reconstruction of the pinned template, and host composition
with public/private/shared inputs and verifier schedule comparison. The wide-word
template importer passed 4,610 equivalence cases and full template reconstruction.
The inactive-loop optimization preserves every committed cell.

CPU utility checks cover byte-identical hashes, GMP encoding, unchanged AES
stream consumption, bounded integer extraction, and BN254 boundary/random
products with output aliases. Native and WebAssembly utility tests passed;
native byte-helper tests also passed ASan/UBSan. Raw negative tests rejected a
changed public root, encoded code polynomial, and sampled opening. Payment proof
runs require successful verification with masked private inputs. The final
Linux run also passed all six tests (6/6).

A diagnostic CPU profile of the optimized native prover, taken before the final
inactive-loop and wide-word-import edits, contained 1,199 main-thread samples.
Stage 1 VM execution accounted for 607 samples (50.6%) and Stage 2 for 453
(37.8%). Within Stage 1, public-template work accounted for 167 samples (13.9%)
and private witness generation for 173 (14.4%). Allocation/free accounted for
at least 187 self samples (15.6%), GPU waits for 35 (2.9%), and gzip for 83 (6.9%).
These categories overlap; they are diagnostic samples, not median elapsed
timings or independent fractions to add together.

The profile points to interpreter and witness bookkeeping, GMP arithmetic, and
allocation as the main remaining costs; GPU waiting is a small fraction of
these samples. Cold public-template preparation and compression also remain
visible. The cache trades additional memory for reduced Stage 3 computation.

The final source profile contained 1,071 main-thread samples. GMP import fell
from 6.4% to 2.7% of samples, and GPU waits remained only 2.5%. Public-template
load time in these two individually sampled runs fell from 220 ms to 133 ms;
these are diagnostic observations, not matched timing medians.

The next implementation targets are:

1. Reduce temporary linear-combination and bit-vector allocations inside
   private ECDSA generation. Allocator routines accounted for 86 of its 148
   samples, about 8% of all main-thread samples. `LC::wire`, LC constructors,
   `ForeignField::relation`, and `Builder::bits` are concrete candidates for
   small-buffer storage or reusable scratch vectors. The witness manager and
   `mpz_vector` already reuse objects and retained GMP capacity.
2. Optimize ordinary VM value handling. Variant/value operations accounted for
   75 samples (7.0%); Stage 2 had 268 samples outside ECDSA append (25.0%).
   Numeric local/stack transfers could avoid generic variant construction,
   while preserving managed-witness copy semantics. Resolving host dispatch
   once is a smaller adjacent opportunity, at roughly 1.5% of samples.
3. Offer a measured latency/size choice for compression, as examined below.

Allocation-order and committed-value equivalence tests should accompany any
future witness or VM change. These profile categories overlap and must not be
added together as independent costs.

An isolated Python/zlib 1.2.12 compression experiment used the same serialized
EVM proof, with one excluded warmup and five measured runs per level. This
does not measure backend execution or file I/O; every output round-tripped to
the identical serialized proof:

| Gzip level | Compression median | Output bytes |
| --- | ---: | ---: |
| 0 (stored) | 0.545 ms | 7,695,590 |
| 1 | 93.844 ms | 6,972,233 |
| 3 | 93.027 ms | 6,969,306 |
| 6 (backend default) | 98.853 ms | 6,965,622 |
| 9 | 136.409 ms | 6,964,331 |

Changing from level 6 to level 1 or 3 saves little. An optional stored-gzip
mode could avoid most compression work at about 10.5% more proof bytes for
this fixture. That option is not implemented, and its full backend/network
tradeoff still needs measurement. The measured runtime retains level 6.

Native asynchronous public-template preload is deferred. Import detection also
matches FUND and unused ECDSA paths; joining a background load can make those
short proofs slower. Any future preload should be explicit and preserve the
existing failure-on-use behavior for unavailable or corrupt templates.
