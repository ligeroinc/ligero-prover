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

//! NEGATIVE test: `from_limbs_checked` binds each limb to its source (bn254fr_bigint.rs:279).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! A `copy` immediately precedes this assertion, so the two sides are equal by construction and
//! no input can separate them -- nor can corrupting an oracle. The assertion binds a value a
//! malicious prover would otherwise choose freely, so the fault skews the destination limb in
//! between the copy and the assertion, which is the only way to be that prover.
//!
//! Reached through `Uint256::to_bigint()`. That bridge has no other caller left in the tree --
//! `divide_qr_normalized` now compares limbs directly via `lt_checked_limbs` -- so this test is
//! the only thing exercising it, and deleting the test would leave the binding unmeasured.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::uint256::Uint256;

fn main() {
    arm(Fault::BigintFromLimbsSkew);

    let v = Uint256::from_str("123456789012345678901234567890", 10);
    let _ = v.to_bigint();
}
