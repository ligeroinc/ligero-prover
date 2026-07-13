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
 * ECDSA Secp256k1 SHA256 signature verification
 * 
 * argv[1]: pubkey (Qx, Qy) in big-endian hex string
 * argv[2]: signature (R, S) in big-endian hex string
 * argv[3]: plain message in big-endian hex string
 * argv[4]: expected result string ("pass" or "fail")
 *
 * Sample test vector:
 * 
 * Msg = 736563703235366b31207465737420766563746f72
 * Qx  = 64ff88781f22246a47057a784ff39a39d38b30c61b8c4b2ff43daf2a0884c4b1
 * Qy  = 32ee9126a3d57e5460b0cbe0113125e64ddabb97deb1806c17f08d880262f5b3
 * R   = 08b2a8c29506cdf27fe61b47f6f0852e0ad0abc1fcb50ebce19d2fd9eed93ed7
 * S   = 624679801abc0f6efdebbfae829e11386801e3576df8688eeeba1e060b64c139
 * Result = "pass"
 */

#include <ligetron/api.h>
#include <ligetron/ecc/curves/secp256k1.hpp>
#include <ligetron/ecc/ecdsa.hpp>

using namespace ligetron::ecc;
using Ctx = ecdsa_context<curves::secp256k1>;

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

