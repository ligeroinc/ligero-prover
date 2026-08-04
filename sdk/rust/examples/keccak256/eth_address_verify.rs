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

//! Proves the Ethereum wallet address derived from a public key:
//! `address = keccak256(X || Y)[12..32]`.
//!
//! Arguments:
//!     [0]: <hex> 64-byte uncompressed public key (X || Y, no 0x04 prefix)
//!     [1]: <hex> 20-byte reference Ethereum address
//!
//! Example inputs (private key 0x1111...1111):
//!     [0] = 4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
//!           385b6b1b8ead809ca67454d9683fcf2ba03456d6fe2c4abe2b07f0fbdbb2f1c1
//!     [1] = 19e7e376e7c213b7e7e7e46cc70a5dd086daff2a

use ligetron::api::*;
use ligetron::keccak256::keccak256;

fn main() {
    let args = get_args();
    let pubkey = args.get_as_bytes(1);
    let reference = args.get_as_bytes(2);

    // The uncompressed public key must be exactly 64 bytes (X || Y, no 0x04 prefix).
    assert_one(i32::from(pubkey.len() == 64));

    let digest = keccak256(pubkey);

    // The address is the last 20 bytes of the digest.
    for i in 0..20 {
        assert_one(i32::from(digest[12 + i] == reference[i]));
    }
}
