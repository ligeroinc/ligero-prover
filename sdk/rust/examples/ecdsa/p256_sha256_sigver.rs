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

//! ECDSA over NIST P-256 with SHA-256.
//!
//! Arguments:
//!     [0]: <hex> 64-byte public key (Qx, Qy), big-endian
//!     [1]: <hex> 64-byte signature (R, S), big-endian
//!     [2]: <hex> message

use ligetron::api::*;
use ligetron::fail_with_message;
use ligetron::bn254fr::assert_equal_u32;
use ligetron::ecc::ecdsa::P256Ecdsa;

fn main() {
    let args = get_args();
    if args.len() != 4 {
        fail_with_message!(b"Expect 3 arguments (pk, sig, msg)");
    }

    let pk = args.get_as_bytes(1);
    let sig = args.get_as_bytes(2);
    let msg = args.get_as_bytes(3);

    if pk.len() != P256Ecdsa::PUBKEY_BYTES {
        fail_with_message!(b"Invalid pubkey size");
    }
    if sig.len() != P256Ecdsa::SIGNATURE_BYTES {
        fail_with_message!(b"Invalid signature size");
    }

    let ctx = P256Ecdsa::from_pubkey(pk);
    let valid = ctx.verify_sha256(sig, msg);

    assert_equal_u32(&valid, 1);
}
