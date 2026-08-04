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

//! Ed25519 signature verification.
//!
//! Arguments:
//!     [0]: <hex> 32-byte encoded public key Enc(A), little-endian
//!     [1]: <hex> 64-byte signature (Enc(R), S), little-endian
//!     [2]: <hex> message
//!
//! Sample test vector (RFC 8032 section 7.1, TEST 2):
//!     Enc(A) = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
//!     Sig    = 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
//!              085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
//!     Msg    = 72

use ligetron::api::*;
use ligetron::fail_with_message;
use ligetron::bn254fr::assert_equal_u32;
use ligetron::ecc::eddsa::Ed25519Eddsa;

fn main() {
    let args = get_args();
    if args.len() != 4 {
        fail_with_message!(b"Expect 3 arguments (pk, sig, msg)");
    }

    let pk = args.get_as_bytes(1);
    let sig = args.get_as_bytes(2);
    let msg = args.get_as_bytes(3);

    if pk.len() != Ed25519Eddsa::PUBKEY_BYTES {
        fail_with_message!(b"Invalid pubkey size");
    }
    if sig.len() != Ed25519Eddsa::SIGNATURE_BYTES {
        fail_with_message!(b"Invalid signature size");
    }

    let ctx = Ed25519Eddsa::from_pubkey(pk);
    let valid = ctx.verify(sig, msg);

    assert_equal_u32(&valid, 1);
}
