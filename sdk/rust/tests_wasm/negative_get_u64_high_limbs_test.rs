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

//! NEGATIVE test: `get_u64` asserts the higher limbs are zero (uint256.rs:314).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! No fault injection needed -- this one is reachable from the public API. `get_u64` returns
//! only limb 0, so it must constrain the other three to be zero or the caller would silently
//! receive a truncated value that the circuit still believes. Handing it a value above 2^64 is
//! the whole test.
//!
//! Requires `--features vm-tests` only; it uses no seam.

use ligetron::uint256::Uint256;

fn main() {
    // 2^64 exactly: limb 0 is zero, limb 1 is one.
    let v = Uint256::from_str("18446744073709551616", 10);
    let _ = v.get_u64();
}
