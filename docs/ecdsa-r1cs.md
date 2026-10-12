# Prehashed secp256k1 verification with standard R1CS

`ligetron::ecdsa_r1cs::assert_secp256k1` adds a fixed, **596,424-row** BN254
R1CS relation to the current Ligero proof. It accepts an already constrained
digest and existing guest bytes, preserving their public/private status.
It is an opt-in API; existing `ecdsa_context` APIs retain their behavior.

```cpp
#include <ligetron/ecc/ecdsa_r1cs.hpp>

// Every argument points to 32 bytes, big-endian.
ligetron::ecdsa_r1cs::assert_secp256k1(qx, qy, r, s, digest);
```

The call asserts validity and returns no Boolean. It does not hash a message,
recover a public key, or perform a payment authorization check. An application
must constrain `digest` to its intended message and bind the key to its owner.
Use this call at the existing signature assertion after computing that digest.
The example `sdk/cpp/examples/ECDSA/secp256k1_r1cs.cpp` accepts three decoded
byte arguments: `Q.x || Q.y`, `r || s`, and the digest (64, 64, and 32 bytes).

## Relation and input policy

The circuit constrains canonical, finite, on-curve `Q`; `0 < r < n`;
`0 < s <= floor(n/2)`; and unsigned 256-bit digest `z`. It proves
`u1*s = z mod n`, `u2*s = r mod n`, and a finite
`R = u1*G + u2*Q` with `R.x mod n = r`.
Normalize a valid high-S signature off-circuit to `(r, n-s)` before calling.
Changing S for signatures with a recovery identifier can also require updating
that identifier; this API accepts no recovery identifier.

| Circuit component | R1CS rows |
| --- | ---: |
| Input validation | 2,978 |
| Scalar divisions | 1,762 |
| Fixed-base multiplication | 84,350 |
| Variable-base multiplication and decomposition | 504,349 |
| Final point addition and x-coordinate check | 2,985 |
| **Total** | **596,424** |

There are 591,290 original wires, including constant one. Twenty interface
wires contain `Q.x, Q.y, r, s, z`, each in four little-endian 64-bit limbs.
Standalone `.r1cs` exports declare those interface limbs public. **The host
integration instead aliases them to the original guest handles**; it does not
publish a private public-key value, signature, or digest. The SDK wrapper uses checked byte
imports to bind each handle to the original guest bytes.

The immutable circuit fingerprint is:

```text
44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f
```

Each row becomes one Ligero quadratic slot. The emitter also allocates linear
witness cells and uses the existing randomized linear checks to bind each
row's A/B/C expressions to its original wires. Linear witness cells are not
additional standard R1CS rows. The enclosing program finalizes the context.

## Generate the public template and run circuit tests

The native standalone build requires C++20, CMake, pkg-config, GMP/GMPXX,
OpenSSL, and Python 3. It does not require a GPU or the full prover build.

```sh
cmake -S lib/ecdsa_r1cs -B build/ecdsa-core -DCMAKE_BUILD_TYPE=Release
cmake --build build/ecdsa-core --parallel 16
ctest --test-dir build/ecdsa-core --output-on-failure --parallel 8
mkdir -p build/ecdsa-assets
build/ecdsa-core/ecdsa_r1cs_template build/ecdsa-assets/ecdsa_secp256k1_v1
gzip -n -c build/ecdsa-assets/ecdsa_secp256k1_v1.r1cs \
  > build/ecdsa-assets/ecdsa_secp256k1_v1.r1cs.gz
```

The generated template is public and deterministic: 111,833,276 bytes raw,
approximately 8.3 MiB gzipped. Generate it once for deployment; do not generate
it during a user's proof. No generated template, witness, or binary is tracked
in Git. The generator validates the pinned shape and deletes its dummy witness.

Every prover and verifier runtime validates the asset's dimensions, field,
labels, canonical terms, and full pinned shape hash before using it. Modified
rows, metadata, or truncated files fail closed. There is no circuit-generation
fallback and no ability for a witness to select a different template.

The standalone exporter can also write and independently check a test witness:

```sh
build/ecdsa-core/ecdsa_r1cs --curve secp256k1 --out build/ecdsa-assets/example
python3 lib/ecdsa_r1cs/check_exports.py \
  build/ecdsa-assets/example.r1cs build/ecdsa-assets/example.wtns
```

The standalone core retains P-256 support and its regression tests, but the
versioned SDK host in this change supports **secp256k1 only**.

## Build and use the native backend

Follow the repository's normal dependency/build instructions. The main build
links the core and host into both `webgpu_prover` and `webgpu_verifier`.
The SDK CMake build adds the `ecdsa_secp256k1_r1cs` example target.

```sh
cmake --build build --parallel 16 --target \
  webgpu_prover webgpu_verifier ecdsa_r1cs_host_test ecdsa_r1cs_statement_test \
  ecdsa_r1cs_template
ctest --test-dir build --output-on-failure -R '^ecdsa_r1cs_'

export LIGETRON_ECDSA_TEMPLATE="$PWD/build/ecdsa-assets/ecdsa_secp256k1_v1.r1cs"
build/webgpu_prover "$(cat prover-config.json)"
build/webgpu_verifier "$(cat verifier-config.json)"
```

The optional hardware-GPU smoke test proves the SDK example, verifies with
private placeholders, and requires cryptographic rejection for a changed
digest, changed program bytes, and high-S signature:

```sh
python3 tests/ecdsa_r1cs/proof_smoke.py \
  --prover build/webgpu_prover --verifier build/webgpu_verifier \
  --program build/sdk/examples/ecdsa_secp256k1_r1cs.wasm \
  --template build/ecdsa-assets/ecdsa_secp256k1_v1.r1cs \
  --shader-path build/shader --output build/ecdsa-proof-smoke
```

Use a fresh output directory for each run. The runner requires a hardware GPU
and rejects Dawn's non-computing Null backend.

Use the existing configuration format and private argument indices. Give the
verifier only public arguments and same-length placeholders for private ones.
The verifier replays the public constraint schedule with dummy auxiliary
values; it never generates or reads the prover's auxiliary witness cache.
Use matching, trusted program and backend versions for both roles.

The host follows the existing `bn254fr` handle ABI and its trusted-guest-memory
assumptions; it is not a new memory sandbox for arbitrary hostile guest code.
The auxiliary witness is an untrusted hint constrained by the fixed relation.

## Browser preparation and parallel witness generation

Build the WebGPU prover/verifier using the repository's existing Emscripten
build. Build the small CPU-only witness worker separately using the same
WebAssembly GMP/OpenSSL archives (no WebGPU initialization in this worker):

```sh
emcmake cmake -S emscripten_templates/ecdsa -B build/ecdsa-worker \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/absolute/path/to/wasm-libs
cmake --build build/ecdsa-worker --parallel 16
```

Serve these files together in the application's versioned asset directory:

```text
webgpu_prover.js / .wasm / .data
webgpu_verifier.js / .wasm / .data
ecdsa_witness.js / .wasm
ecdsa_witness_worker.js
ecdsa_precompute.js
ecdsa_secp256k1_v1.r1cs.gz
```

The helper and worker scripts are copied into `build/ecdsa-worker` by CMake.
Serve the `.gz` as a gzip file without HTTP `Content-Encoding: gzip`; the
helper explicitly decompresses it. Use HTTPS or localhost, and the normal
WebGPU/cross-origin isolation headers used by the application.

In a **fresh worker per proof or verification**, start public preparation
before loading the Emscripten backend. The following is the integration pattern;
the application still supplies its normal FS/configuration/proof handling:

```js
importScripts(new URL('ecdsa_precompute.js', assetBase).href);
const preparation = LigeroEcdsaR1cs.precompute({
  assetBase, // Absolute URL ending in '/', containing all assets above.
  prover: kind === 'prover',
  parallel: true,
});

var Module = {
  noInitialRun: true,
  locateFile: name => new URL(name, assetBase).href,
  onRuntimeInitialized: async () => {
    try {
      await preparation.prepare(Module);
      // Stage the guest program, configuration, and verifier proof in Module.FS.
      // Start witness-dependent timing here.
      let status = Module.callMain([JSON.stringify(config)]);
      if (Asyncify.currData) status = await Asyncify.whenDone();
      // Check status and the backend's final proof/verification result.
    } finally {
      preparation.dispose();
    }
  },
};
importScripts(new URL(`webgpu_${kind}.js`, assetBase).href);
```

The helper fetches/decompresses the public template and warms two CPU workers
concurrently with loading the main runtime. `prepare()` validates and loads the
template before proof timing. Proving then computes independent fixed-base and
variable-base scalar-multiplication witnesses in parallel, merges their exact
wire ranges, and computes the final point check. The measured private-witness
time includes coordination, transfer, parsing, and merge.

`parallel: false` uses the same witness-only generator sequentially. Both modes
retain the same pinned rows and wire order. All 596,424 rows are appended in
each of the three proving stages and in verification. Witness values are cached
per thread for an exact twenty-limb input match across stages; that cache is
not a cache of constraint checks. Applications should dispose of the runtime
after each invocation to release private data and memory.

The exported `ligero_ecdsa_prepare(mode)` accepts 0 (verifier), 1 (sequential
prover, warm public tables), or 2 (parallel prover). The helper configures it;
the parallel callback is `globalThis.ligeroGenerateEcdsaWitness`. This callback
belongs to one main worker/runtime and is removed by `dispose()`.

## Transcript compatibility

Guests importing `ecdsa_r1cs` opt into the domain
`LigetronEcdsaR1csStatementV1`. Both drivers bind the exact program-byte hash,
pinned circuit shape, and existing public-input hash before deriving the
Stage 1 challenge. The import is `ecdsa_r1cs.assert_secp256k1_v1`.

The verifier selects its trusted program independently of the proof. A future
relation change must use a new circuit fingerprint/version and matching
deployment assets. Programs without this import retain their historical
transcript. Earlier payment benchmark prototype proofs used a different domain
and must be regenerated with this backend.

## Circuit construction and validation

The construction uses four 64-bit foreign-field limbs, bounded quotient/carry
identities, a 29-window fixed-base table with 9-bit windows, and secp256k1 GLV
decomposition with constrained signed 128-bit components. Joint 2-bit tables
reduce variable-point additions. Complete affine case distinctions constrain
infinity, doubling, and inverse points. Selector bits, decomposition signs,
canonical coordinates, nonzero divisors, and final x-coordinate reduction are
part of the relation.

For the foreign-field relation `F = 0 mod m`, the circuit supplies
`q' = F/m + 2^260`, constrains it to 262 bits, and checks
`F + 2^260*m - q'*m = 0`. With base `B = 2^64`, paired carry equations have
residual magnitude below `2^202`, below BN254 Fr; a field equality therefore
implies the required integer equality. Initial/final carries are zero, and
three intermediate carries are encoded with offset `64B` and bounded to
72 bits. These bounds depend on the enforced operand/term limits in
`ForeignField::relation`.

The regression suite covers OpenSSL cross-checks, arithmetic boundaries,
invalid signatures and curve points, exceptional group cases, exported witness
mutations, byte-for-byte witness-only and parallel equivalence, malformed
worker parts, and modified templates. The native composition test checks the
real witness manager, private input aliases, zero-private verifier replay, and
an invalid digest whose witness generation succeeds but whose rows fail.
Transcript tests cover legacy compatibility and changed program/circuit/input.
These checks are implementation validation, not an independent security audit.

## Prior payment benchmark

The payment prototype using this exact relation was measured on Apple M4 Max
hardware WebGPU, packing 16,384, with a three-input TRON send and change.
Medians of three successful proof/verification runs:

| Full payment implementation | Prove | Verify | Stage 1 | Quadratic slots |
| --- | ---: | ---: | ---: | ---: |
| Existing SDK | 33.014 s | 14.720 s | 9.114 s | 3,374,562 |
| This relation, parallel witness | 8.411 s | 4.598 s | 2.041 s | 1,097,959 |

The optimized private ECDSA witness pass was 0.373 s (sequential: 0.515 s).
These prove/verify numbers exclude separately measured public runtime/template
preparation. Including that preparation, medians were 9.688 s / 5.825 s for
the optimized implementation and 33.054 s / 14.756 s for the existing SDK.
Template generation itself happened before deployment. Browser compilation
caches may have been warm. These are historical application measurements,
not a new benchmark of this packaged branch or a hardware-independent claim.
