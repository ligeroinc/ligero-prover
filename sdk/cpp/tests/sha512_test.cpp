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

#include <ligetron/sha512.h>
#include <ligetron/api.h>

#include <cassert>
#include <cstring>
#include <string>
#include <vector>


unsigned char hex_char_to_val(char c) {
    if (c >= '0' && c <= '9')
        return static_cast<unsigned char>(c - '0');
    if (c >= 'A' && c <= 'F')
        return static_cast<unsigned char>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f')
        return static_cast<unsigned char>(c - 'a' + 10);
    return 0xFF;
}

std::vector<unsigned char> hex_to_binary(const std::string &hex) {
    assert(hex.size() % 2 == 0 && "invalid hex data size");
    size_t n_bytes = hex.size() / 2;

    std::vector<unsigned char> res;
    res.reserve(n_bytes);

    for (size_t i = 0; i < n_bytes; ++i) {
        unsigned char byte = static_cast<unsigned char>(hex_char_to_val(hex[i * 2]) << 4);
        byte |= hex_char_to_val(hex[i * 2 + 1]);
        res.push_back(byte);
    }

    return res;
}

void test_sha512(const std::string &msg, const std::string &expected_hex) {
    unsigned char out[64];
    const unsigned char *data = reinterpret_cast<const unsigned char *>(msg.data());
    ligetron_sha512(out, data, static_cast<int>(msg.size()));

    auto expected = hex_to_binary(expected_hex);
    assert_one(expected.size() == 64);

    for (size_t i = 0; i < expected.size(); ++i) {
        assert_one(out[i] == expected[i]);
    }
}

int main(int argc, char *argv[]) {
    test_sha512("",
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    test_sha512("abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    test_sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

    return 0;
}
