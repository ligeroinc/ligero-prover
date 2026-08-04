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

//! NEGATIVE test: `a * a^-1 == 1 (mod m)` in `Bn254FrBigint::invmod` (bn254fr_bigint.rs:923).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault adds 1 to limb 0 of the oracle's inverse, so the product reduces to something
//! other than 1. Both the `== 1` on limb 0 and the `== 0` on the rest are downstream of it.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintInvmodResult);

    let a = bigint_from_limbs(&["39812738912fffff", "12978e3183798127", "12397"]);
    let m = bigint_from_limbs(&["ffffffffffffffff", "ffffffff", "0", "ffffffff00000001"]);

    let _ = Bn254FrBigint::invmod(&a, &m);
}
