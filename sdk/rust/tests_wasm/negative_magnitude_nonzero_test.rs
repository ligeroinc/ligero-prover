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

//! NEGATIVE test: step 4, `|x| != 0` (curve.rs:157).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault forces `|x|` to zero. `scalar_mul` documents that `k = 0` is unsupported
//! exactly because this constraint would then be unsatisfiable.
//!
//! ## Measured: this test does NOT isolate its target
//!
//! Commenting out `curve.rs:167` leaves this suite still failing to prove -- it is caught as
//! constraint-count DRIFT, not as PROVED-ANYWAY. The reason is structural: any single
//! perturbation that violates this assertion also violates step 5
//! (`x_signed == z_signed * k`), so the proof fails for the other reason and the removal
//! cannot be attributed here.
//!
//! That does NOT make the assertion redundant. A malicious prover chooses `x`, `z`, both sign
//! flags and `result` jointly, and can re-satisfy step 5 after breaking this one; single-fault
//! injection cannot reproduce that freedom. The test is kept because it pins the end-to-end
//! behaviour and would become the isolating test if step 5 ever moved. See A18.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{P256Scalar, P256};
use ligetron::fault::{arm, Fault};
use ligetron::ff::FieldElement;

fn main() {
    arm(Fault::MagnitudeXZero);

    let curve = P256::new();
    let k = FieldElement::<P256Scalar>::from_str("112233445566778899");

    // One constrained call, so a failure has exactly one candidate cause.
    let _ = curve.scalar_mul(&k, curve.generator());
}
