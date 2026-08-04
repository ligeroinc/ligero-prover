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

#include <ligetron/sha2.h>
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

void test_sha256(const std::string &msg, const std::string &expected_hex) {
    // The message bytes must be witnesses. Hashing the literal directly costs 0 quadratic
    // constraints: the digest is folded at compile time and only the comparisons below
    // survive, so the round function is never traced and this proves nothing about it.
    std::vector<unsigned char> witness;
    witness.reserve(msg.size() + 1);
    for (size_t i = 0; i < msg.size(); ++i) {
        auto byte = static_cast<unsigned char>(msg[i]);
        witness.push_back(
            static_cast<unsigned char>(witness_cast_u32(static_cast<uint32_t>(byte))));
    }
    // Keeps data() valid for the empty-message case.
    witness.push_back(0);

    unsigned char out[32];
    const unsigned char *data = witness.data();
    ligetron_sha2_256(out, data, msg.size());

    auto expected = hex_to_binary(expected_hex);
    assert_one(expected.size() == 32);

    for (size_t i = 0; i < expected.size(); ++i) {
        assert_one(out[i] == expected[i]);
    }
}

int main(int argc, char *argv[]) {
    test_sha256("",
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855");

    test_sha256("abc",
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad");

    // FIPS 180-4 two-block vector: 56 bytes, so the 8-byte length field no longer fits and a
    // second block is required. This is the exact case the padding used to get wrong -- the
    // boundary test was `len > 60` against a length field written at offset 60, where FIPS
    // reserves bytes 56..63, so lengths congruent to 56..59 (mod 64) were squeezed into one
    // block and hashed to the wrong digest.
    test_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039"
                "a33ce45964ff2167f6ecedd419db06c1");

    // Walk the padding boundary a byte at a time. 55 is the largest message that still fits its
    // length field in the same block; 56 is the first that does not.
    test_sha256(std::string(55, 'a'),
                "9f4390f8d30c2dd92ec9f095b65e2b9a"
                "e9b0a925a5258e241c9f1e910f734318");

    test_sha256(std::string(56, 'a'),
                "b35439a4ac6f0948b6d6f9e3c6af0f5f"
                "590ce20f1bde7090ef7970686ec6738a");

    test_sha256(std::string(57, 'a'),
                "f13b2d724659eb3bf47f2dd6af1accc8"
                "7b81f09f59f2b75e5c0bed6589dfe8c6");

    test_sha256(std::string(58, 'a'),
                "d5c039b748aa64665782974ec3dc3025"
                "c042edf54dcdc2b5de31385b094cb678");

    test_sha256(std::string(59, 'a'),
                "111bb261277afd65f0744b247cd3e47d"
                "386d71563d0ed995517807d5ebd4fba3");

    test_sha256(std::string(60, 'a'),
                "11ee391211c6256460b6ed375957fadd"
                "8061cafbb31daf967db875aebd5aaad4");

    test_sha256(std::string(61, 'a'),
                "35d5fc17cfbbadd00f5e710ada39f194"
                "c5ad7c766ad67072245f1fad45f0f530");

    test_sha256(std::string(62, 'a'),
                "f506898cc7c2e092f9eb9fadae7ba503"
                "83f5b46a2a4fe5597dbb553a78981268");

    test_sha256(std::string(63, 'a'),
                "7d3e74a05d7db15bce4ad9ec0658ea98"
                "e3f06eeecf16b4c6fff2da457ddc2f34");

    test_sha256(std::string(64, 'a'),
                "ffe054fe7ae0cb6dc65c3af9b61d5209"
                "f439851db43d0ba5997337df154668eb");

    return 0;
}
