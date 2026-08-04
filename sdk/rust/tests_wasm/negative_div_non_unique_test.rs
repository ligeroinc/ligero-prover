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

//! NEGATIVE test: `r < b` in `divide_qr_normalized` (uint256.rs:140).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! The fault moves one whole `b` from the quotient into the remainder: `q -= 1, r += b`. The
//! multiply-back is BLIND to this -- `(q-1)*b + (r+b) == q*b + r == a` -- so `r < b` is the
//! only thing standing between the circuit and an arbitrary factorisation of `a`. That is what
//! makes it a soundness constraint rather than a tidiness one.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};
use ligetron::uint256::{Uint256, Uint256Wide};

fn main() {
    arm(Fault::DivNonUnique);

    let wide = Uint256Wide {
        lo: Uint256::from_str("340282366920938463463374607431768211455", 10),
        hi: Uint256::from_str("7", 10),
    };
    let b = Uint256::from_str("1606938044258990275541962092341162602522202993782792835301376", 10);

    let _ = wide.divide_qr_normalized(&b);
}
