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

//! NEGATIVE test: step 5, `x_signed == z_signed * k` (curve.rs:171).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault feeds BOTH oracles a `k'` one bit away from `k`. They stay consistent with
//! each other -- `x ≡ z·k'` and `result = [k']P` -- so step 9 still passes; only step 5, which
//! compares against the real `k`, fails. That is precisely the attack step 5 exists to stop:
//! hand back `[k']P` and claim it is `[k]P`.
//!
//! Corrupting `x` directly would NOT work here: with an honest `result = [k]P`, steps 5 and 9
//! assert the same thing, so both would fire and neither could be attributed.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{P256Scalar, P256};
use ligetron::fault::{arm, Fault};
use ligetron::ff::FieldElement;

fn main() {
    arm(Fault::ScalarBeforeOracles);

    let curve = P256::new();
    let k = FieldElement::<P256Scalar>::from_str("112233445566778899");

    // One constrained call, so a failure has exactly one candidate cause.
    let _ = curve.scalar_mul(&k, curve.generator());
}
