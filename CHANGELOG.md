# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

### Changed
- Change non-batch randomness from AES to powers of some `r`
- Change stage 1 hash scheme to Poseidon 2
- Add commitment(hash) in stage 2 for randomness rows
- Add sampling of randomness rows in stage 3

### Removed

## [0.9.9] 2025-06-01

### CHanged

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
