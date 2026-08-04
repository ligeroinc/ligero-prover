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

//! SHA-512 of an input string, compared against a reference digest.
//!
//! Arguments:
//!     [0]: <str> input text
//!     [2]: <i64> Length of input text
//!     [3]: <hex> Reference SHA-512 to compare

use ligetron::api::*;
use ligetron::sha2::*;

fn main() {
    let args = get_args();

    let len = args.get_as_int(2) as u32;
    let ref_hash = args.get_as_bytes(3);

    let mut out = [0u8; 64];

    ligetron_sha2_512(&mut out, args.get_as_bytes(1), len);

    for i in 0..64 {
        assert_one(out[i] == ref_hash[i]);
    }
}
