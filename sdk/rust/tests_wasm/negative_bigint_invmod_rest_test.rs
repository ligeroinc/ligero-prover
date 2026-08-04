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

//! NEGATIVE test: `Bn254FrBigint::invmod` binds the product's HIGHER limbs to zero
//! (bn254fr_bigint.rs:966).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! This is A23's attack made concrete, and it is the reason that fix mattered. The
//! verification asserts `res * a mod m == 1` as two parts: limb 0 equals 1, and every higher
//! limb is zero. Before A23 the second part compared against a freshly allocated handle, which
//! is an unconstrained witness -- so a prover could target `res * a mod m == 1 + k*2^64` and
//! submit `zero = k`, and the circuit would accept a non-inverse as an inverse.
//!
//! The fault takes that path: it replaces the oracle's answer with `res * (1 + 2^64) mod m`,
//! so the product verifies as `1 + 2^64`. Limb 0 is still 1, which satisfies the check ABOVE
//! the target and leaves this loop as the only objector.
//!
//! Note `negative_bigint_invmod_test` CANNOT cover this line: it claims `a^-1 == 0` in order to
//! isolate the `limbs[0] == 1` check, which makes the product zero and this loop vacuously
//! true. The two tests are complementary, not redundant.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintInvmodRestSkew);

    let a = bigint_from_limbs(&["39812738912fffff", "12978e3183798127", "12397"]);
    let m = bigint_from_limbs(&["ffffffffffffffff", "ffffffff", "0", "ffffffff00000001"]);

    let _ = Bn254FrBigint::invmod(&a, &m);
}
