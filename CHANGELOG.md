# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.4.0](https://github.com/ligeroinc/ligetron/compare/v1.3.0...v1.4.0) (2026-02-09)


### Features

* **sdk:** add ecdsa variant taking pre-hashed message ([#285](https://github.com/ligeroinc/ligetron/issues/285)) ([d090105](https://github.com/ligeroinc/ligetron/commit/d0901050edf6f473df1445243ecf838635e0d8fd))


### Bug Fixes

* **sdk:** add edcsa verify prehash to build ([#287](https://github.com/ligeroinc/ligetron/issues/287)) ([b6f5a5c](https://github.com/ligeroinc/ligetron/commit/b6f5a5c2b29abbd6695f3848cf6e2c370e6020af))

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
