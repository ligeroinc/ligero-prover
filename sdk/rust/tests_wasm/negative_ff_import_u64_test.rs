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

//! NEGATIVE test: `import_u32` binds each full limb to the literal it came from (ff/storage.rs:530).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! `set_u64` is the UNCHECKED setter -- it puts the value in the handle without constraining
//! it -- so this assertion is the only thing tying the imported limb to the caller's literal.
//! Without it the import would be a free witness the prover chooses. An EVEN word count keeps
//! the odd trailing branch out of the way.
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
    arm(Fault::FfImportU64Skew);

    // Four 32-bit words -> two full 64-bit limbs; the odd branch does not run.
    let mut v = FE::zero();
    let _ = v.import_limbs(&[0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444]);
}
