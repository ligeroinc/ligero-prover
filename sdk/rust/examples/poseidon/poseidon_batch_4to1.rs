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

//! Poseidon Batch 4-to-1 Hash Example
//!
//! Demonstrates the vectorized Poseidon hash function with Montgomery
//! constants for fast batch processing with 4-to-1 compression (5-ary
//! permutation).
//!
//! Arguments:
//!     [1..4]: <str> Input numbers
//!     [5]:    <str> Reference hash


use ligetron::get_args;
use ligetron::vbn254fr::VBn254Fr;
use ligetron::poseidon::VPoseidonContext5;

fn main() {
    let args = get_args();

    // t = 5, so the hash takes exactly t-1 = 4 inputs.
    let inputs: Vec<VBn254Fr> = (1..=4)
        .map(|i| VBn254Fr::from_c_str_scalar(args.get_as_c_str(i)))
        .collect();
    let reference = VBn254Fr::from_c_str_scalar(args.get_as_c_str(5));

    let mut ctx = VPoseidonContext5::<true>::new();
    for input in &inputs {
        ctx.update(input);
    }
    let result = ctx.finalize();

    result.print_hex();

    VBn254Fr::assert_equal(&result, &reference);
}