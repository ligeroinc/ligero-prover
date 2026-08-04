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

//! NEGATIVE test: `add_no_carry` binds the surplus limbs it copies across (bn254fr_bigint.rs:700).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! A `copy` immediately precedes this assertion, so the two sides are equal by construction and
//! no input can separate them -- nor can corrupting an oracle. The assertion binds a value a
//! malicious prover would otherwise choose freely, so the fault skews the destination limb in
//! between the copy and the assertion, which is the only way to be that prover.
//!
//! The surplus path runs only when the operands have DIFFERENT limb counts -- 3 against 2
//! here -- so limb 2 is copied from the wider side rather than added.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintAddSurplusSkew);

    let x = bigint_from_limbs(&["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"]);
    let y = bigint_from_limbs(&["9c15c81b7b00a5b5", "29f"]);

    let _ = Bn254FrBigint::add_no_carry(&x, &y);
}
