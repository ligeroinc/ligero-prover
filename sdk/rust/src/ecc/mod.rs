/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Generic elliptic curve cryptography over the Ligetron constraint system.
//!
//! ## Overview
//!
//! This is distinct from
//! [`crate::babyjubjub`] and [`crate::eddsa`], which implement BabyJubJub natively over the
//! BN254 scalar field; everything here works over a *foreign* 256-bit prime field emulated
//! with big-integer arithmetic, which is what makes P-256, secp256k1 and Ed25519 reachable.
//!
//! Verification results are **circuit booleans** ([`crate::bn254fr::Bn254Fr`] holding 0 or 1),
//! never a Rust `bool`. The caller decides what to assert about them.

pub mod coordinates;
pub mod curve;
pub mod curves;
pub mod ecdsa;
pub mod eddsa;
pub mod host;
pub mod twisted_edwards;
pub mod utils;
pub mod weierstrass;

pub use coordinates::Affine;
pub use curve::{AffineCurve, CurveForm};
pub use ecdsa::{EcdsaContext, P256Ecdsa, Secp256k1Ecdsa};
pub use eddsa::{Ed25519Eddsa, EddsaContext, EddsaParams};
pub use host::EccCurveType;
pub use twisted_edwards::Am1TwistedEdwards;
pub use weierstrass::Weierstrass;
