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

//! NEGATIVE test: `range_check` binds the top limb of a proper representation to the carry it recomputes (bn254fr_bigint.rs:129).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! Not a copy/assert pair. `range_check` bit-checks limbs `0..count`, but the FINAL carry limb
//! `out[count]` gets no range check -- it is pinned solely by this equality against the running
//! carry the circuit recomputes from `in - out`. So skewing that one limb is exactly and only
//! what this assertion can see. Reached through `mul_checked`, which converts the no-carry product to
//! a proper representation and then range-checks it.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintProperTopSkew);

    let x = bigint_from_limbs(&["8575140ace900480", "f2ec973d606bca0c"]);
    let y = bigint_from_limbs(&["9c15c81b7b00a5b5", "29f"]);

    let _ = Bn254FrBigint::mul_checked(&x, &y);
}
