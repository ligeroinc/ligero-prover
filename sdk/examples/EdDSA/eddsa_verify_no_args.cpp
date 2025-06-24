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

#include <ligetron/eddsa.h>
#include <ligetron/poseidon2.h>

using namespace ligetron;

// Private key = 114514
bn254fr_class message = 42;

jubjub_point public_key {
    "0x2b00e7584d377a90c4ce698903466b37b2a11cf6936e79cddf0f055a2cdb2af0",
    "0x16975c19b438cbc029c40f818efc838ea7aee80ead7e67de957cb0c925c66bbf"
};

eddsa_signature signature {
    {
        "0x248db8d47110053756e1c7c9e040f3e607494949a88e4ee54e344f18009870f9",
        "0x1ad1af70568fcaac16bcb645b189db6599506f97a3661e6a23f3bb5fba14c5fb"
    },
    "0x19084fb97be9c264ae13df247d87eee2d423f2dac3880cd4a3e6c1f6fe74f674"
};

int main() {
    bn254fr_class digest;
    auto *ctx = poseidon2_bn254_context_new();
    poseidon2_bn254_digest_update(ctx, signature.R.x);
    poseidon2_bn254_digest_update(ctx, signature.R.y);
    poseidon2_bn254_digest_update(ctx, public_key.x);
    poseidon2_bn254_digest_update(ctx, public_key.y);
    poseidon2_bn254_digest_update(ctx, message);
    poseidon2_bn254_digest_final(ctx, digest);

    // Verify EdDSA signatures
    // ------------------------------------------------------------
    eddsa_verify(signature, public_key, digest);

    poseidon2_bn254_context_free(ctx);
    return 0;
}