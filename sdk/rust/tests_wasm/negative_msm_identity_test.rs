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

//! NEGATIVE test: step 9, `[x]P + [z]Q == O` (curve.rs:229).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault flips a bit in the oracle's `[k]P` and leaves the decomposition honest, so
//! step 5 (`x_signed == z_signed * k`, which never mentions the result) still passes and only
//! the multi-scalar identity fails. This is the assertion that makes `result` a proof rather
//! than a claim.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{P256Scalar, P256};
use ligetron::fault::{arm, Fault};
use ligetron::ff::FieldElement;

fn main() {
    arm(Fault::ScalarMulResult);

    let curve = P256::new();
    let k = FieldElement::<P256Scalar>::from_str("112233445566778899");

    // One constrained call, so a failure has exactly one candidate cause.
    let _ = curve.scalar_mul(&k, curve.generator());
}
