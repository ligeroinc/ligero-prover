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

//! NEGATIVE test: `lt` binds its returned boolean to the value it computed (bn254fr_bigint.rs:498).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! A copy/assert pair: `lt` folds the per-limb comparison chain into `ors[0]`, copies it into
//! the returned `Bn254Fr`, and the assertion is what stops a prover returning a different
//! answer. The fault skews the copy in between.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintLtSkew);

    let a = bigint_from_limbs(&["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"]);
    let b = bigint_from_limbs(&["9c15c81b7b00a5b5", "29f", "0"]);

    let _ = Bn254FrBigint::lt(&a, &b);
}
