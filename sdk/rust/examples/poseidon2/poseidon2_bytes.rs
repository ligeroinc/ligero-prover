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

//! Poseidon2 Bytes Hash Example
//!
//! This example demonstrates the Poseidon2 hash function for arbitrary byte arrays.
//!
//! Arguments:
//!     [1]: <hex> Input bytes
//!     [2]: <i64> Length of input bytes
//!     [3]: <str> Reference hash

use ligetron::*;
use ligetron::bn254fr::Bn254Fr;
use ligetron::poseidon2::poseidon2_hash_bytes;

fn main() {
    let args = get_args();

    let input = args.get_as_bytes(1);
    let length: usize = args.get_as_int(2).try_into().unwrap();
    let reference_str = args.get_as_c_str(3);

    if length > input.len() {
        fail_with_message!(b"Byte length must not be larger that the length of the input!");
    }

    let input_bytes = &input[..length];
    let reference = Bn254Fr::from_c_str(reference_str);

    let digest = poseidon2_hash_bytes(input_bytes);
    digest.print_hex();

    Bn254Fr::assert_equal(&digest, &reference);
}