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

//! NEGATIVE test: `from_bits` binds each limb to the value composed from its bits (uint256.rs:436).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! Same shape as the `set_words` case: a copy makes the two sides equal, and the assertion
//! is what stops a prover substituting its own limb. The fault skews the limb in between.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::bn254fr::Bn254Fr;
use ligetron::fault::{arm, Fault};
use ligetron::uint256::Uint256;

fn main() {
    arm(Fault::FromBitsSkew);

    // 256 bits, alternating, so no limb sits at its range-check ceiling.
    let bits: Vec<Bn254Fr> = (0..256).map(|i| Bn254Fr::from_u32((i % 2) as u32)).collect();
    let _ = Uint256::from_bits(&bits);
}
