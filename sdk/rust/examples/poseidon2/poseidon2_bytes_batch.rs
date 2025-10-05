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

//! Poseidon2 Bytes Batch Hash Example
//!
//! This example demonstrates batch processing of byte arrays using vectorized
//! Poseidon2 operations for improved performance.


use ligetron::vbn254fr::VBn254Fr;
use ligetron::poseidon2::vposeidon2_hash_bytes;

fn main() {
    // Test vector: 32 bytes of 0xFF
    let input_bytes = vec![0xFF; 32];
    let expected_hash = "0x20d0a48cbc645db12d09c441d41e6d5975d2f115f32b2e01d4a9bc6d87070bbc";

    let reference = VBn254Fr::from_str_scalar(expected_hash);

    let digest = vposeidon2_hash_bytes(&input_bytes);
    digest.print_hex();

    VBn254Fr::assert_equal(&digest, &reference);
}