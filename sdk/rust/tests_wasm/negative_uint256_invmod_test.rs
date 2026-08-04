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

//! NEGATIVE test: `result * a === 1 (mod m)` in `uint256::invmod` (uint256.rs:654).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault adds 1 to the oracle's inverse, so `result * a mod m` lands on something that is
//! not 1. Nothing else in `invmod` looks at `result`, so the verification is the only
//! assertion that can fire.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::uint256::{invmod, Uint256};

fn main() {
    arm(Fault::Uint256InvmodResult);

    // The P-256 prime: >= 2^192, as uint512_mod's precondition requires.
    let m = Uint256::from_str(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);
    let a = Uint256::from_str("123456789012345678901234567890", 10);

    let _ = invmod(&a, &m);
}
