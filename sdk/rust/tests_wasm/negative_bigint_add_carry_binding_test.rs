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

//! NEGATIVE test: `add_checked` binds its top limb to the final carry (bn254fr_bigint.rs:752).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The carry out of the last limb becomes the top limb of the result. It is copied there and
//! then asserted equal -- without the assertion a prover could put anything in that limb, which
//! is a free 64 bits on every checked addition. The fault skews it in between.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintAddCarrySkew);

    let x = bigint_from_limbs(&["ffffffffffffffff", "ffffffffffffffff"]);
    let y = bigint_from_limbs(&["1", "0"]);

    let _ = Bn254FrBigint::add_checked(&x, &y);
}
