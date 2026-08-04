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

//! NEGATIVE test: `out < m` in `Bn254FrBigint::rem` (bn254fr_bigint.rs:899).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! `a` is an exact multiple of m (3x), so the honest remainder is zero. The fault then moves
//! one whole m across: `q -= 1, out = m`. The multiply-back cannot see that --
//! `(q-1)*m + m == q*m == a` -- so `out < m` is the only assertion left to object.
//! Without it a prover could hand back any factorisation at all.
//!
//! Requires `--features vm-tests,fault-injection`.

#[path = "common/mod.rs"]
mod common;

use common::bigint_from_limbs;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintRemNonUnique);

    // a = 3b, b's top limb nonzero.
    let a = bigint_from_limbs(&["d44158527101f11f", "7de", "0"]);
    let b = bigint_from_limbs(&["9c15c81b7b00a5b5", "29f"]);

    let _ = Bn254FrBigint::rem(&a, &b);
}
