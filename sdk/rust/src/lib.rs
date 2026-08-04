//! Ligetron Rust SDK
//!
//! This crate provides Rust bindings for the Ligetron zero-knowledge proof system.
//!
//! ## Modules
//!
//! - [`api`] - Core API functions
//! - [`sha2`] - SHA-2 family: SHA-256 and SHA-512
//! - [`keccak256`] - Keccak-256 (the Ethereum variant, not SHA3-256)
//! - [`bn254fr`] - BN254 scalar field arithmetic
//! - [`vbn254fr`] - Vectorized BN254 operations
//! - [`uint256`] - 256-bit unsigned integer arithmetic
//! - [`poseidon`] - Poseidon hash function (t=3, t=5)
//! - [`poseidon2`] - Poseidon2 hash function (t=2)
//! - [`babyjubjub`] - Baby Jubjub elliptic curve operations
//! - [`eddsa`] - Edwards-curve Digital Signature Algorithm over Baby Jubjub
//! - [`ecc`] - Generic elliptic curve cryptography (P-256, secp256k1, Ed25519)

pub mod api;
pub mod babyjubjub;
pub mod bn254fr;
pub mod bn254fr_bigint;
pub mod ecc;
pub mod eddsa;
pub mod ff;
/// Test-only corruption of host-oracle output. See the module docs before enabling.
#[cfg(feature = "fault-injection")]
pub mod fault;
pub mod keccak256;
pub mod poseidon;
pub mod poseidon2;
pub mod sha2;
pub mod uint256;
pub mod vbn254fr;
// private modules
mod poseidon2_constant;
mod poseidon_constant;

// Re-export core types and functions for convenience
pub use api::*;
