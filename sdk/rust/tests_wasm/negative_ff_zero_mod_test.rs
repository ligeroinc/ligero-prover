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

//! NEGATIVE test: `assert_equal_zero_mod` proves `x === 0 (mod m)` (ff/storage.rs).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! Reached through field division, whose whole soundness argument is `x2 === x (mod p)`. The
//! fault drops the quotient by one, so `d = x - q*m` comes out as `m` rather than zero and the
//! `d_proper == 0` loop must object. `r` is left alone, so the second loop still passes and the
//! failure belongs to the first.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::ff::FieldElement;
use ligetron::impl_prime_field;

/// The P-256 base field prime, as in prime_field_test.
#[derive(Copy, Clone, Debug)]
pub struct TestField;
impl_prime_field!(
    TestField,
    "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
);

type FE = FieldElement<TestField>;

fn main() {
    arm(Fault::FfZeroModSkew);

    let a = FE::from_u32(7);
    let b = FE::from_u32(3);
    let mut out = FE::zero();
    FE::div(&mut out, &a, &b);
}
