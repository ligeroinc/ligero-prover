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
 * ECDSA P-256 SHA256 signature verification
 * 
 * argv[1]: pubkey (Qx, Qy) in big-endian hex string
 * argv[2]: signature (R, S) in big-endian hex string
 * argv[3]: plain message in big-endian hex string
 * argv[4]: expected result string ("pass" or "fail")
 *
 * Sample test vector:
 * 
 * Msg = e1130af6a38ccb412a9c8d13e15dbfc9e69a16385af3c3f1e5da954fd5e7c45f
 *       d75e2b8c36699228e92840c0562fbf3772f07e17f1add56588dd45f7450e1217
 *       ad239922dd9c32695dc71ff2424ca0dec1321aa47064a044b7fe3c2b97d03ce4
 *       70a592304c5ef21eed9f93da56bb232d1eeb0035f9bf0dfafdcc4606272b20a3
 * Qx = e424dc61d4bb3cb7ef4344a7f8957a0c5134e16f7a67c074f82e6e12f49abf3c
 * Qy = 970eed7aa2bc48651545949de1dddaf0127e5965ac85d1243d6f60e7dfaee927
 * R = bf96b99aa49c705c910be33142017c642ff540c76349b9dab72f981fd9347f4f
 * S = 17c55095819089c2e03b9cd415abdf12444e323075d98f31920b9e0f57ec871c
 * Result = "pass"
 */

#include <ligetron/api.h>
#include <ligetron/ecc/curves/p256.hpp>
#include <ligetron/ecc/ecdsa.hpp>

using namespace ligetron::ecc;
using Ctx = ecdsa_context<curves::p256>;

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
