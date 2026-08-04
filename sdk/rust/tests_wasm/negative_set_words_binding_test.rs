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

//! NEGATIVE test: `set_words` binds each limb to its source (uint256.rs:350).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! This assertion cannot be reached by any input, nor by corrupting an oracle: the `copy`
//! immediately before it makes both sides equal by construction. It exists to bind a value a
//! malicious prover would otherwise choose freely, so the only way to exercise it is to BE
//! that prover. The fault skews the limb in between the copy and the assertion.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::bn254fr::Bn254Fr;
use ligetron::fault::{arm, Fault};
use ligetron::uint256::{Uint256, UINT256_NLIMBS};

fn main() {
    arm(Fault::SetWordsSkew);

    let words: [Bn254Fr; UINT256_NLIMBS] =
        core::array::from_fn(|i| Bn254Fr::from_u32(i as u32 + 1));
    let mut v = Uint256::new();
    v.set_words(&words);
}
