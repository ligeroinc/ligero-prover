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

//! Poseidon Hash Example
//!
//! This example demonstrates the Poseidon hash function with a single input.
//!
//! Arguments:
//!     [1]: <str> Input number
//!     [2]: <str> Reference hash

/*
    Example test vectors:
    Input  = 42
    Output = 11900205294312547303566650979164934562713672929231722670359450569937552281134
*/

use ligetron::get_args;
use ligetron::bn254fr::Bn254Fr;
use ligetron::poseidon::PoseidonContext5;

fn main() {
    let args = get_args();

    let input_str = args.get_as_c_str(1);
    let reference_str = args.get_as_c_str(2);

    let input = Bn254Fr::from_c_str(input_str);
    let reference = Bn254Fr::from_c_str(reference_str);

    let mut ctx = PoseidonContext5::new();
    ctx.update(&input);
    let result = ctx.finalize();

    result.print_dec();

    Bn254Fr::assert_equal(&result, &reference);
}