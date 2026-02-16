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

//! EdDSA Batch Signature Verification Example
//!
//! This example demonstrates vectorized EdDSA signature verification using
//! Baby Jubjub elliptic curve operations for improved performance with
//! batch processing.


use ligetron::vbn254fr::VBn254Fr;
use ligetron::babyjubjub::JubjubPointVec;
use ligetron::eddsa::EddsaSignatureVec;
use ligetron::poseidon2::VPoseidon2Context;

fn main() {
    // Test data - Private key = 114514, Message = 42
    let message = VBn254Fr::from_str_scalar("42");

    // Public key (vectorized)
    let mut public_key = JubjubPointVec::new(
        VBn254Fr::from_str_scalar("0x2b00e7584d377a90c4ce698903466b37b2a11cf6936e79cddf0f055a2cdb2af0"),
        VBn254Fr::from_str_scalar("0x16975c19b438cbc029c40f818efc838ea7aee80ead7e67de957cb0c925c66bbf")
    );

    // Create vectorized signature
    let signature_r = JubjubPointVec::new(
        VBn254Fr::from_str_scalar("0x248db8d47110053756e1c7c9e040f3e607494949a88e4ee54e344f18009870f9"),
        VBn254Fr::from_str_scalar("0x1ad1af70568fcaac16bcb645b189db6599506f97a3661e6a23f3bb5fba14c5fb")
    );
    let signature_s = VBn254Fr::from_str_scalar("0x19084fb97be9c264ae13df247d87eee2d423f2dac3880cd4a3e6c1f6fe74f674");
    let mut signature = EddsaSignatureVec::new(signature_r, signature_s);

    let mut ctx = VPoseidon2Context::new();
    ctx.digest_update(&signature.r.x);
    ctx.digest_update(&signature.r.y);
    ctx.digest_update(&public_key.x);
    ctx.digest_update(&public_key.y);
    ctx.digest_update(&message);
    let mut digest = ctx.digest_final();

    EddsaSignatureVec::verify(&mut signature, &mut public_key, &mut digest);
}