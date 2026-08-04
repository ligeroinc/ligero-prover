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

//! NEGATIVE test: `divide_qr_normalized` binds the divisor's fifth-limb pad to zero
//! (uint256.rs:91).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! `q` is 256 + 64 bits, so the multiply-back pads the divisor to a matching fifth limb. That
//! pad is a fresh handle -- unconstrained unless asserted -- and a prover who could choose it
//! would be dividing by `b + pad * 2^256` rather than `b`.
//!
//! Isolating it is a question of INPUT, not of a cleverer fault. Pick `a < b` so the quotient
//! is zero: `mul_q` is then all zeros, `q * b` is zero whatever the pad holds, and the
//! multiply-back cannot see the pad at all. `r < b` holds because `r == a`, and the high
//! `add_out` limbs stay zero. The pad's own assertion is the only one left to object.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::uint256::{Uint256, Uint256Wide};

fn main() {
    arm(Fault::DivBPadSkew);

    // a = 12345, comfortably below b, so q == 0 and r == a.
    let wide = Uint256Wide {
        lo: Uint256::from_str("12345", 10),
        hi: Uint256::from_str("0", 10),
    };
    // 2^200: most significant limb nonzero, as the precondition requires.
    let b = Uint256::from_str("1606938044258990275541962092341162602522202993782792835301376", 10);

    let _ = wide.divide_qr_normalized(&b);
}
