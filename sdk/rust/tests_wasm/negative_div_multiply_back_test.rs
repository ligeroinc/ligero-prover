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

//! NEGATIVE test: the multiply-back `q*b + r == a` in `divide_qr_normalized` (uint256.rs:129).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault adds 1 to the oracle's remainder and leaves the quotient alone, so `q*b + r`
//! overshoots `a` by exactly one. `r < b` still holds (the divisor here is far larger than the
//! remainder), so the multiply-back is the only assertion that can object.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::uint256::{Uint256, Uint256Wide};

fn main() {
    arm(Fault::DivRemainderPlusOne);

    // b = 2^200-ish, so b's top limb is nonzero (the documented precondition) and r + 1 stays
    // comfortably below b.
    let wide = Uint256Wide {
        lo: Uint256::from_str("340282366920938463463374607431768211455", 10),
        hi: Uint256::from_str("7", 10),
    };
    let b = Uint256::from_str("1606938044258990275541962092341162602522202993782792835301376", 10);

    let _ = wide.divide_qr_normalized(&b);
}
