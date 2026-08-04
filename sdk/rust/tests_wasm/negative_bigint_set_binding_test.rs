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

//! NEGATIVE test: `set` binds each replaced limb to its source (bn254fr_bigint.rs:339).
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` lists it in
//! NEGATIVE_SUITES, so `Final prove result: false` is the pass.
//!
//! A `copy` immediately precedes this assertion, so the two sides are equal by construction and
//! no input can separate them -- nor can corrupting an oracle. The assertion binds a value a
//! malicious prover would otherwise choose freely, so the fault skews the destination limb in
//! between the copy and the assertion, which is the only way to be that prover.
//!
//! Reached through `ff::build_modulus`, which is `set`'s shortest public path.
//!
//! Requires `--features vm-tests,fault-injection`.

use ligetron::fault::{arm, Fault};

fn main() {
    arm(Fault::BigintSetSkew);

    // The P-256 prime; any value would do, the binding is per-limb.
    let _ = ligetron::ff::build_modulus(
        "115792089210356248762697446949407573530086143415290314195533631308867097853951");
}
