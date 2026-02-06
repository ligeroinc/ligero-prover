//! Ligetron Rust SDK
//!
//! This crate provides Rust bindings for the Ligetron zero-knowledge proof system.
//!
//! ## Modules
//!
//! - [`api`] - Core API functions
//! - [`sha2`] - SHA-256 hash function
//! - [`bn254fr`] - BN254 scalar field arithmetic
//! - [`vbn254fr`] - Vectorized BN254 operations
//! - [`uint256`] - 256-bit unsigned integer arithmetic
//! - [`poseidon`] - Poseidon hash function (t=3, t=5)
//! - [`poseidon2`] - Poseidon2 hash function (t=2)
//! - [`babyjubjub`] - Baby Jubjub elliptic curve operations
//! - [`eddsa`] - Edwards-curve Digital Signature Algorithm

pub mod api;
pub mod babyjubjub;
pub mod bn254fr;
pub mod eddsa;
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
