/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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
//! This example demonstrates the vectorized Poseidon hash function for fast
//! batch processing with 4-to-1 compression (5-ary permutation).
//!
//! Arguments:
//!     [1]: <str> Input number
//!     [2]: <str> Reference hash


use ligetron::get_args;
use ligetron::vbn254fr::VBn254Fr;
use ligetron::poseidon::VPoseidonContext5;

fn main() {
    let args = get_args();

    let input_str = args.get_as_c_str(1);
    let reference_str = args.get_as_c_str(2);

    let input = VBn254Fr::from_c_str_scalar(input_str);
    let reference = VBn254Fr::from_c_str_scalar(reference_str);

    let mut ctx = VPoseidonContext5::<true>::new();
    ctx.update(&input);
    let result = ctx.finalize();

    VBn254Fr::assert_equal(&result, &reference);
}