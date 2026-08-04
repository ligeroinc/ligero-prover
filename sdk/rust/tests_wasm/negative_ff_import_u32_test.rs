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

//! NEGATIVE test: `import_u32` binds the odd trailing 32-bit limb (ff/storage.rs:537).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The trailing-word branch runs only for an ODD word count, so a single word exercises it
//! and skips the full-limb loop entirely. Same reasoning as the u64 case: `set_u32` does not
//! constrain, the assertion does.
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
    arm(Fault::FfImportU32Skew);

    // One 32-bit word: n_full is 0, so only the odd branch runs.
    let mut v = FE::zero();
    let _ = v.import_limbs(&[0x1234_5678]);
}
