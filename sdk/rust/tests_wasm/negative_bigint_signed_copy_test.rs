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

//! NEGATIVE test: `range_check_signed` binds the limbs it passes through (bn254fr_bigint.rs:166).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! When the proper representation is WIDER than the input, the surplus limbs have no `in[i]`
//! to subtract, so they are copied into the carry chain and bound by this assertion. The branch
//! runs only for that width mismatch, which is why the operands below are chosen to grow a limb
//! under `to_proper`. The fault skews the copy in between.
//!
//! ## Measured: this test does NOT isolate its target
//!
//! Deleting the assertion leaves this suite still failing to prove, so its removal goes
//! unnoticed. Both possible faults are blocked: skewing `tmp` (what it does) also breaks the
//! carry chain's terminal "last carry must vanish" check, and skewing `out[i]` instead
//! falsifies the `check_bits` that `range_check_signed` applies to every out limb at its top.
//! The assertion is still load-bearing against a malicious prover -- who picks `tmp` freely
//! rather than perturbing one value -- but single-fault injection cannot reproduce that. Kept
//! because it pins the end-to-end behaviour. See A22.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintSignedCopySkew);

    // sub_no_carry widens the bit count, so to_proper grows the limb count and the
    // pass-through branch runs.
    let x = bigint_from_limbs(&["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"]);
    let y = bigint_from_limbs(&["9c15c81b7b00a5b5", "29f"]);

    let d = Bn254FrBigint::sub_no_carry(&x, &y);
    let _ = d.to_proper();
}
