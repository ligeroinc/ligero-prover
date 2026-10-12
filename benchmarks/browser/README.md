# Local browser payment benchmark

Run from the repository root with Python 3.10 or later. No package installation is needed.
Use synthetic EVM/TRON fixture JSONs from the payment circuit; this page does not connect a wallet or submit transactions.

```sh
python3 benchmarks/browser/serve.py \
  --candidate-web build/web \
  --witness-build build/witness-web \
  --program /path/to/payroll_verification.wasm \
  --template /path/to/ecdsa_secp256k1_v1.r1cs.gz \
  --fixtures /path/to/payment-test-inputs \
  --output build/browser-benchmark \
  --commitment-cache-mb 768
```

Open **http://127.0.0.1:8789/** in a browser with WebGPU enabled. Change the port with `--port`.
Optionally add `--baseline-assets /path/to/baseline/assets` to compare an earlier backend.
That directory must contain `webgpu_{prover,verifier}.{js,wasm,data}` and `ecdsa_witness.{js,wasm}`.
Both versions use the selected payment program, compressed R1CS template, and repository preparation helpers.
The candidate Web and witness directories must contain the corresponding files from their builds.

Each version runs one warmup plus three measured proofs for `test_send.json` (EVM) and
`test_send_tron.json` (TRON). Every proof and verification uses a fresh worker. The verifier
gets the proof and a separate copy of the configuration with private arguments masked.
Every run must report a successful proof and verification before its result is accepted.

The ordinary optimized variant explicitly disables the commitment cache. Passing
`--commitment-cache-mb 768` adds a separate optimized variant with that memory budget;
omitting the option does not enable it. Public template/table preparation runs in parallel
with backend loading. Constraint-template generation is not performed by the benchmark.

The page shows medians excluding warmups for preparation, the backend main call, and
end-to-end worker time. End-to-end includes startup, preparation, main, and result delivery.
Preparation includes loading and validating the public template; main excludes preparation.
The server sends assets with `Cache-Control: no-store` so rebuilt binaries cannot silently
reuse stale HTTP responses. Keep the selected builds unchanged during a benchmark session.

Results are saved after every verified run to `<output>/results.json`, including individual
timings, medians, build log versions, selected paths, and browser metadata. Backend argument
lines are omitted; private inputs and proof bytes are not saved. Restarting a benchmark for
one version replaces that version's earlier runs in the report. A new server session starts
a new report and replaces `results.json` after its first saved result; use a new output
directory when retaining separate comparisons.

The server binds only to `127.0.0.1`, serves an explicit asset whitelist, and accepts result
writes only for its current session. It has no arbitrary file-serving or output-path endpoint.

Lightweight checks, without a browser or GPU:

```sh
python3 -m unittest discover -s benchmarks/browser -p 'test_*.py'
node --test benchmarks/browser/benchmark.test.mjs
```
