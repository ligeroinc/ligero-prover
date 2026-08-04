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

//! Poseidon 4-to-1 Hash Example
//!
//! Demonstrates the Poseidon hash function (width t=5, four inputs, one
//! output). It uses the reference vector and produces the identical digest.
//!
//! Arguments:
//!     [1..4]: <str> Input numbers
//!     [5]:    <str> Reference hash

/*
    Example test vectors (verified against Solana's `sol_poseidon`,
    Parameters::Bn254X5, big-endian):
    Inputs = 1, 2, 3, 4
    Output = 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
*/

use ligetron::get_args;
use ligetron::bn254fr::Bn254Fr;
use ligetron::poseidon::PoseidonContext5;

fn main() {
    let args = get_args();

    // t = 5, so the hash takes exactly t-1 = 4 inputs; state[0] stays the
    // (zero) domain tag and is the lane read out.
    let inputs: Vec<Bn254Fr> = (1..=4)
        .map(|i| Bn254Fr::from_c_str(args.get_as_c_str(i)))
        .collect();
    let reference = Bn254Fr::from_c_str(args.get_as_c_str(5));

    let mut ctx = PoseidonContext5::new();
    for input in &inputs {
        ctx.update(input);
    }
    let result = ctx.finalize();

    result.print_dec();

    Bn254Fr::assert_equal(&result, &reference);
}