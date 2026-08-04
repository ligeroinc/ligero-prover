# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.7.0](https://github.com/ligeroinc/ligetron/compare/v1.6.0...v1.7.0) (2026-08-04)


### ⚠ BREAKING CHANGES

* **sdk:** ligetron_sha512 is renamed to ligetron_sha2_512 and its declaration moves from sha512.h to sha2.h, which is deleted. Its len parameter is now uint32_t rather than int. In Rust, sha2::ligetron_sha512 becomes sha2::ligetron_sha2_512; the idiomatic sha2::sha256 / sha2::sha512 are unaffected.
* **sdk:** the SHA-2 functions are regrouped under one module. sha512::sha512 becomes sha2::sha512 and sha2::sha2_256 becomes sha2::sha256; the module sha512 is removed. The ligetron_* C-parity forms keep their names.
* **sdk:** ecdsa_context::verify(sig, msg) is renamed to verify_sha256(sig, msg).
* **sdk:** <ligetron/poseidon_s.h> is removed — include <ligetron/poseidon.h>. poseidon_s_context becomes poseidon_context and poseidon_s_vec_context becomes poseidon_vec_context.

### Features

* **sdk:** Add ed25519 public key derivation to ecc::eddsa_context and correct the name of the "eddsa_context::point_decompress" function ([0c41465](https://github.com/ligeroinc/ligetron/commit/0c414658da712458eca9703d907b902181a95c9a))
* **sdk:** move per-curve constants into eddsa_params and add eddsa_context::from_seed ([1a7f806](https://github.com/ligeroinc/ligetron/commit/1a7f8064e66df734242e66c7f52baad83458ec5d))
* **sdk:** Port ecc, ff and bigint layers and missing hash functions from C++ SDK to the Rust SDK ([37c8058](https://github.com/ligeroinc/ligetron/commit/37c8058c52a4d877ecaa27808fae9099fa0aa318))
* **sdk:** replace the redundant Poseidon-v1 sponge with the existing sol_poseidon-compatible construction ([814398a](https://github.com/ligeroinc/ligetron/commit/814398a3b0b96b13dc0d6ad08ca99a1aa7ce43c1))
* **sdk:** split ecdsa_context::verify into verify_digest and verify_sha256 ([9489c3a](https://github.com/ligeroinc/ligetron/commit/9489c3abef72ffa6de28bf132360d22d8342e3d4))


### Bug Fixes

* **sdk:** add the prime_field storage set_u32 that set_zero/set_one call ([4710c5b](https://github.com/ligeroinc/ligetron/commit/4710c5b89b3def87530dd119cd24f4d99a6a7d59))
* **sdk:** bind uint256_invmod_checked's comparand to the constant ([612204f](https://github.com/ligeroinc/ligetron/commit/612204f07460485bad55a8b18955d915031f9814))
* **sdk:** bind uint256.cpp's shared constants to their values ([c94c177](https://github.com/ligeroinc/ligetron/commit/c94c17782b210a276f5108c695ae84dc5905ac70))
* **sdk:** bn254fr_bigint::set_bytes_big drops leading bytes ([1502d73](https://github.com/ligeroinc/ligetron/commit/1502d73cfca4ac0d76042248df63341a02aec036))
* **sdk:** correct SHA-256 padding and unify the SHA-2 signatures ([cb6b565](https://github.com/ligeroinc/ligetron/commit/cb6b5658ec20bc2407a9e76cc3fa045f95d699ad))
* **sdk:** Fixed the test_assert_equal_bytes test ([b07c368](https://github.com/ligeroinc/ligetron/commit/b07c368ee931a4839d9bd89728615fff72eecc3b))
* **sdk:** make the unported coordinate types a compile error, not a trap ([ff8a9af](https://github.com/ligeroinc/ligetron/commit/ff8a9afc429481723a249dd631297e892758d941))
* **sdk:** reset the byte buffer length in poseidon2 digest_final ([e7efeb3](https://github.com/ligeroinc/ligetron/commit/e7efeb37f6844cfe854629bc01df25dece0d297f))
* **sdk:** unify the SHA-2 API on ligetron_sha2_512 with an unsigned length ([f416a4a](https://github.com/ligeroinc/ligetron/commit/f416a4a40b666598310baee50be6d1bf328c49b9))
* **webgpu:** correct transposed parameters in buffer_view::slice_bytes ([08852bf](https://github.com/ligeroinc/ligetron/commit/08852bffb197d9f90b3e2503be385bd4f446baf4))
* **webgpu:** size the vals vector in vbn254fr_set_ui ([a39a29d](https://github.com/ligeroinc/ligetron/commit/a39a29d7aa5dd1c90010953e593aee93d5705348))


### Performance Improvements

* **sdk:** size three widths from the derivation instead of a margin ([287208a](https://github.com/ligeroinc/ligetron/commit/287208adf6c014a2977f55d81d7f327732737a94))

## [1.6.0](https://github.com/ligeroinc/ligetron/compare/v1.5.0...v1.6.0) (2026-07-24)


### Features

* **webgpu:** log HARDWARE vs SOFTWARE adapter acceleration ([#400](https://github.com/ligeroinc/ligetron/issues/400)) ([ef42460](https://github.com/ligeroinc/ligetron/commit/ef42460ece81874e14c4f435935e0de9c3d05fc8))


### Bug Fixes

* **log:** terminate web log records with a newline ([#412](https://github.com/ligeroinc/ligetron/issues/412)) ([b3e8978](https://github.com/ligeroinc/ligetron/commit/b3e897805acf85594a47971c210204d0496371f0))
* **shader:** drop uniform-space pointer param from bn254fr_powmod ([#399](https://github.com/ligeroinc/ligetron/issues/399)) ([f655ba9](https://github.com/ligeroinc/ligetron/commit/f655ba97533296514fc3c8ad0226ea73f30aeae3)), closes [#397](https://github.com/ligeroinc/ligetron/issues/397)
* **webgpu:** fail with a clear message when no adapter is returned ([#411](https://github.com/ligeroinc/ligetron/issues/411)) ([8a9dbac](https://github.com/ligeroinc/ligetron/commit/8a9dbacb122bc0e0db9fb96118db0ccb78268bf8))
* **webgpu:** zero-init storage buffers at allocation (wgpu init hazard, [#408](https://github.com/ligeroinc/ligetron/issues/408)) ([#409](https://github.com/ligeroinc/ligetron/issues/409)) ([87394e3](https://github.com/ligeroinc/ligetron/commit/87394e302a514151e168c4bff380deaaebb14a83))
* **web:** report proof/verify completion when main() actually returns ([#413](https://github.com/ligeroinc/ligetron/issues/413)) ([2a77774](https://github.com/ligeroinc/ligetron/commit/2a777749699e00e4a43530912f1f5419e36d7e0d))

## [1.5.0](https://github.com/ligeroinc/ligetron/compare/v1.4.0...v1.5.0) (2026-07-09)


### Features

* add web demo templates with per-target Emscripten shell files ([#315](https://github.com/ligeroinc/ligetron/issues/315)) ([435600e](https://github.com/ligeroinc/ligetron/commit/435600e0faa70bd30d3dd77d8011dc461c1795bf))
* **core:** migrate proof serialization from Boost to Protocol Buffers ([#310](https://github.com/ligeroinc/ligetron/issues/310)) ([5034d25](https://github.com/ligeroinc/ligetron/commit/5034d25ef384cbcedb626f00d21db2963f40de89))
* **sdk:** implement fast Ed25519 EdDSA signature verification using MSM trick ([#380](https://github.com/ligeroinc/ligetron/issues/380)) ([3fb806a](https://github.com/ligeroinc/ligetron/commit/3fb806a03bbf928f52fbbef311a2b2c7ab6401ca))
* **sdk:** Optimize scalar version of "poseidon_s" by using "mulmod_constant" in permutation ([#371](https://github.com/ligeroinc/ligetron/issues/371)) ([ebdceab](https://github.com/ligeroinc/ligetron/commit/ebdceaba5c1e299586c97b45c5a4890d3e6512dd))
* **sdk:** Rewrite P256/Secp256k1 ECDSA as MSM for performance and soundness ([#367](https://github.com/ligeroinc/ligetron/issues/367)) ([d90586d](https://github.com/ligeroinc/ligetron/commit/d90586d113dd4d7000a41a5545538cd551b5665a))


### Bug Fixes

* "weierstrass_affine_curve" - fixed "point_add" ([ad3a795](https://github.com/ligeroinc/ligetron/commit/ad3a7950c82115bc4520befe17934adb7319fecb))
* **core:** add merkle root to stage2 fiat-shamir & remove fiat-shamir seed from proof ([321dff7](https://github.com/ligeroinc/ligetron/commit/321dff74e2cda22566032cf432650bd53332ea99))
* **core:** add missing constraints for div/rem and private inputs ([511a1aa](https://github.com/ligeroinc/ligetron/commit/511a1aafe01d1852477f78ef01b56fbc90919ea5))
* **core:** deterministic linear commitment order across C++ stdlibs ([#374](https://github.com/ligeroinc/ligetron/issues/374)) ([#375](https://github.com/ligeroinc/ligetron/issues/375)) ([53115d7](https://github.com/ligeroinc/ligetron/commit/53115d7b76eb1370cdb9ee3f93b0662dab2a7110))
* **core:** include public inputs in stage1 seed generation ([bfc0010](https://github.com/ligeroinc/ligetron/commit/bfc00103b4dd6f6548cd6915ed86f313060a8e67))
* Fixed "bn254fr_to_bytes" for big-endian order ([050a7f1](https://github.com/ligeroinc/ligetron/commit/050a7f1355c310690ed1085cc584f6c7ba87d673))
* **interpreter:** clear secret tags in memory.fill and memory.init ([#313](https://github.com/ligeroinc/ligetron/issues/313)) ([#327](https://github.com/ligeroinc/ligetron/issues/327)) ([612668a](https://github.com/ligeroinc/ligetron/commit/612668a2422098339bd8340c87639eefd91b6638))
* resolve remaining 32-bit WASM vs 64-bit native divergences ([#312](https://github.com/ligeroinc/ligetron/issues/312)) ([#328](https://github.com/ligeroinc/ligetron/issues/328)) ([c4c9e67](https://github.com/ligeroinc/ligetron/commit/c4c9e67d72b45ae2ef79a9deecb9d017ad843262))
* **sdk:** fix incorrect generator precompute table values ([06508d6](https://github.com/ligeroinc/ligetron/commit/06508d6eb5da07fa4989350a7e48d8c16e642d0c))
* **tests:** point shader-path at build directory after PR [#333](https://github.com/ligeroinc/ligetron/issues/333) ([#342](https://github.com/ligeroinc/ligetron/issues/342)) ([48f66d1](https://github.com/ligeroinc/ligetron/commit/48f66d1890b61925a8e0f4b1caaee9d9a4145a65))
* **webgpu:** add sha256 shader to CMake dependency list ([d5c585f](https://github.com/ligeroinc/ligetron/commit/d5c585f6392c58ac503d4c8a1c377e03eb0758f1))
* **webgpu:** improve CMake behaviors ([6682453](https://github.com/ligeroinc/ligetron/commit/66824539d91fd1f32dfd7283775e80ca98a2b8d7))

## [1.4.0](https://github.com/ligeroinc/ligetron/compare/v1.3.1...v1.4.0) (2026-03-03)


### Features

* implement public path for all f32/f64 floating-point instructions ([#298](https://github.com/ligeroinc/ligetron/issues/298)) ([7ce75d3](https://github.com/ligeroinc/ligetron/commit/7ce75d345d93ade2e541433df3330713335ea76f))


### Bug Fixes

* resolve 32-bit WASM vs 64-bit native divergence bugs ([#312](https://github.com/ligeroinc/ligetron/issues/312)) ([fa774a2](https://github.com/ligeroinc/ligetron/commit/fa774a230b502c8be06f5cd8bef94f223eb49599))
* **sdk:** fix bug in eq implementation for uint256 field ([#307](https://github.com/ligeroinc/ligetron/issues/307)) ([3d6ef0c](https://github.com/ligeroinc/ligetron/commit/3d6ef0ca0bf550a70a5e657297346b8c0f99e0c3))

## [1.3.1](https://github.com/ligeroinc/ligetron/compare/v1.3.0...v1.3.1) (2026-02-16)


### Features

* **sdk:** secp256k1 ECDSA implementation ([8eadb12](https://github.com/ligeroinc/ligetron/commit/8eadb1234f0db6f5e0b77f57dae5bdd8d2ea1a68))
* **sdk:** add pre-hashed message variant to ecdsa_verify ([#285](https://github.com/ligeroinc/ligetron/issues/285)) ([d090105](https://github.com/ligeroinc/ligetron/commit/d0901050edf6f473df1445243ecf838635e0d8fd)), ([14c62b8](https://github.com/ligeroinc/ligetron/commit/14c62b8))


### Bug Fixes

* **sdk:** fix ecdsa verify prehash build ([#287](https://github.com/ligeroinc/ligetron/issues/287)) ([b6f5a5c](https://github.com/ligeroinc/ligetron/commit/b6f5a5c2b29abbd6695f3848cf6e2c370e6020af))

## [1.3.0](https://github.com/ligeroinc/ligetron/compare/v1.2.0...v1.3.0) (2026-01-29)


### Features

* **sdk:** add sha256 hash into p256 ECDSA example ([906c346](https://github.com/ligeroinc/ligetron/commit/906c346304b3436c37d305dc79cfcdf404482d91))
* **sdk:** generic ECDSA and P-256 implementation ([b4d68ba](https://github.com/ligeroinc/ligetron/commit/b4d68ba63cb386daf55069ebf1cc56ed1713646f))
* **sdk:** implement ECDSA verification for message hash ([a5154e1](https://github.com/ligeroinc/ligetron/commit/a5154e1ea8fad1ce9dc8787eb7c0e4e8781b9858))
* **sdk:** implement generator point optimization for p256 ([7cbe94e](https://github.com/ligeroinc/ligetron/commit/7cbe94e9c12e82c33920c4f26d9ec1deb0919540))
* **sdk:** implement import/export bytes for uint256 field ([5a2cd72](https://github.com/ligeroinc/ligetron/commit/5a2cd72abe6a6c02c6b1203609d43f4ee2aaa605))
* **sdk:** optimized uint256 field arithmetic implementation ([1dc3a7d](https://github.com/ligeroinc/ligetron/commit/1dc3a7dd57b5534116e96298e3d85fda45e27401))
* **sdk:** pass arguments as hex data in P256 example ([760aa48](https://github.com/ligeroinc/ligetron/commit/760aa48e06cf33a179e0c4b0a6b76fda385b5407))
* **sdk:** update Rust sdk to match 1.2.0 ([#232](https://github.com/ligeroinc/ligetron/issues/232)) ([e6667b3](https://github.com/ligeroinc/ligetron/commit/e6667b31e9b1aef3c20b7d3c0137562d65ef30ae))
* updated "Web" build to use "emdawnwebgpu" ([#230](https://github.com/ligeroinc/ligetron/issues/230)) ([c2519f8](https://github.com/ligeroinc/ligetron/commit/c2519f8c444311f5535a34c4a20de65e59abc8c5))


### Bug Fixes

* **sdk:** add constraints in uint256 field import_limbs/export_limbs ([e60a576](https://github.com/ligeroinc/ligetron/commit/e60a5761c95ecb22fba0c0a34ce76a1de8d0133e))
* **sdk:** fix overflow bug in uint256 field implementation ([d04bc5e](https://github.com/ligeroinc/ligetron/commit/d04bc5e88ed9c32916a812fb38fe45d444d58142))
* **sdk:** fix polynomial multiplication check in big integer implementation ([#257](https://github.com/ligeroinc/ligetron/issues/257)) ([059e6fb](https://github.com/ligeroinc/ligetron/commit/059e6fba31492cdc49159119652e2c378c2d838e))
* **sdk:** fix return type for witness_cast_u64 ([1c9a96e](https://github.com/ligeroinc/ligetron/commit/1c9a96ed7b7c90dd4885ff1a8472570264ac99b9))

## [1.2.0](https://github.com/ligeroinc/ligetron/compare/v1.1.0...v1.2.0) (2025-11-22)


### Features

* **sdk:** implement C++ wrapper for uint256 values ([77cac8b](https://github.com/ligeroinc/ligetron/commit/77cac8bdbc4f5b9041094930c36845f4c3b38436))
* **sdk:** implement mux, eqz, to_bits operations for uint256 field element ([4e87f85](https://github.com/ligeroinc/ligetron/commit/4e87f85868b6498b7cf0cd37090f4c8740fcbde1))
* **sdk:** implement uint256 field arithmetic ([c12cd9f](https://github.com/ligeroinc/ligetron/commit/c12cd9f9c468e85ae79ea3516832606748b6879b))
* **sdk:** uint256 API implementation ([8128a33](https://github.com/ligeroinc/ligetron/commit/8128a33fa65e05d034feee7a14bb45eab2fbd7f7))
* **webgpu:** implement webgpu modular exponentiation ([f156795](https://github.com/ligeroinc/ligetron/commit/f156795f106016ae08d43f5f73caeb5a01bd97b9))


### Bug Fixes

* add correct sdk build paths to gitignore for cpp and rust ([7ed9acd](https://github.com/ligeroinc/ligetron/commit/7ed9acd3ebf7a2f8d3cdda72cb0a63be627cfb2f))
* **sdk:** respect len parameter in uint256_set_bytes* functions ([a6a2f29](https://github.com/ligeroinc/ligetron/commit/a6a2f293ff3f6d51f9ee74de2b576532e22c9aed))
* **util:** safely extract 64-bit values from mpz::get_ui() ([2f02f74](https://github.com/ligeroinc/ligetron/commit/2f02f74c9acd42725c1706dd9d36ea6055cb3788))

## [1.1.0]

### Added
- Add commitment(hash) in stage 2 for randomness rows
- Add sampling of randomness rows in stage 3

### Changed
- Bumped Dawn version to commit cec4482ecc
- Change non-batch randomness from AES to powers of some `r`
- Change stage 1 hash scheme to Poseidon 2

### Removed

## [1.0.0] 2025-06-25

### Changed

#### SDK
- Introduced `bn254fr_class.h` and `vbn254fr_class.h` which contain C++ wrappers for API functions from `bn254fr.h` and `vbn254fr.h`
- Deprecated integer debug `print` function.
- Adapted the examples to the new API

## [0.9.9] 2025-06-01

### Changed

#### Interpreter
- Implement a new backend that performs no allocation at runtime
- Add decomposed bit vector to the stack type to reduce constraints
- Rewrite opcode and interpreter to eliminate dynamic_cast overhead
- Refine host module API
- Extend the backend with bit operations to improve performance

#### SDK
- Deprecate old `fp256.h` interface, replace it with `bn254fr.h` and `vbn254fr.h`.
- `bn254fr.h` features new explicit computation APIs and constraints APIs.
- `vbn254fr.h` is the renaming of the old API.

## [0.1.4] 2025-05-06

### Changed

- [SDK] Change Poseidon2 interface to take arbitrary input length
- [SDK] Change EdDSA interface to take message hash

## [0.1.3] 2025-02-19

### Changed
- Rename generic `finite_field_gmp` to `bn254_gmp`
- Move field related parameters inside `bn254_gmp`
- Replace `mpz_mod` to Barrett Reduction
- Improve GPU Barrett Reduction shader by fitting the factor into single bigint
- Improve `mpz_export` by selecting native word size

## [0.1.2] 2025-02-13

### Added
- Added the "println" helper functions to SDK

### Fixed
- Fix typo that cause double release a `WGPUBindGroupLayout`
- Fix browser performance degradation caused by submit blocker

## [0.1.1] 2025-02-12

### Added
- Print semantic versioning string at the start
- Implement Poseidon 2 compression in SDK

### Changed
- Bump supported `Dawn` version to `4111d9e10b6a885cebd55c1a0e48b2f10a8158b1`
- Removed the "@print" and "@print_str" message headers from the respective calls it is better to allow users to customize their own debug messages during printouts, and not have any if desired

### Fixed
- Improve GPU memory leakage
- Fix Firefox compatibility by requesting default limits on mobile devices
- Enabled the `assert_zero` call from the `call_host`

## [0.1.0] 2025-01-23

### Changed
* Argument `shader_path` changed to `shader-path`
* Native build now requires to install `Dawn`, see README for instructions
* Deprecate `wgpu-native` due to buffer offset bugs, use `Dawn` instead
* Rewrite WebGPU driver code to improve speed drastically
* Optimize shader code to improve bignum and NTT efficiency
* Move all examples to SDK
