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

/*
 * Ed25519 SHA512 signature verification
 * 
 * argv[1]: 32-byte encoded pubkey Enc(A) in little-endian hex string
 * argv[2]: 64-byte signature (Enc(R), S) in little-endian hex string
 * argv[3]: plain message in little-endian hex string
 * argv[4]: expected result string ("pass" or "fail")
 *
 * Sample test vector:
 * Enc(A) = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
 * Sig    = 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
            085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
 * Msg    = 72
 * Res    = "pass"
 */

#include <ligetron/api.h>
#include <ligetron/ecc/curves/ed25519.hpp>
#include <ligetron/ecc/eddsa.hpp>

using namespace ligetron::ecc;
using Ctx = eddsa_context<curves::ed25519>;

int main(int argc, char* argv[]) {
    if (argc != 5) {
        printf("Expect 3 arguments (pk, sig, msg, result), got %d\n", argc - 1);
        exit(-1);
    }

    int args_len[argc];
    args_len_get(argv, args_len);

    if (args_len[1] != Ctx::pubkey_bytes) {
        printf("Invalid pubkey size of %d bytes\n", args_len[1]);
        exit(-1);
    }

    if (args_len[2] != Ctx::signature_bytes) {
        printf("Invalid signature size of %d bytes\n", args_len[2]);
        exit(-1);
    }

    auto pk_bytes =
        std::as_bytes(std::span<const char, Ctx::pubkey_bytes>{argv[1], Ctx::pubkey_bytes});
    auto sig_bytes =
        std::as_bytes(std::span<const char, Ctx::signature_bytes>{argv[2], Ctx::signature_bytes});
    auto msg_bytes =
        std::as_bytes(std::span<const char>{argv[3], static_cast<size_t>(args_len[3])});

    Ctx ec{pk_bytes};
    auto valid = ec.verify(sig_bytes, msg_bytes);

    bn254fr_assert_equal_u32(valid.data(), (std::strcmp(argv[4], "fail") == 0) ? 0u : 1u);

    return 0;
}


