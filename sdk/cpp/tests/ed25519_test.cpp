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
 * Ed25519 curve arithmetic, point encoding, key derivation and EdDSA verification.
 *
 * The signing and derivation vectors are RFC 8032 section 7.1 TEST 1-3, so they check
 * against the standard rather than against this implementation.
 *
 * `eddsa_context` consumes the compressed 32-byte public key and the 64-byte signature
 * directly, which is the shape RFC 8032 publishes -- no coordinate decoding needed here.
 */

#include <ligetron/api.h>
#include <ligetron/ecc/curves/ed25519.hpp>
#include <ligetron/ecc/eddsa.hpp>

#include <array>
#include <string>
#include <vector>

using namespace ligetron;
using namespace ligetron::ecc;

using curve_t   = curves::ed25519;
using Ctx       = eddsa_context<curve_t>;
using point_t   = curve_t::point_type;
using f_element = curve_t::base_field_type;
using s_element = curve_t::scalar_field_type;

static const curve_t& curve() {
    static curve_t c;
    return c;
}

static unsigned char hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned char>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<unsigned char>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<unsigned char>(c - 'a' + 10);
    return 0xFF;
}

static std::vector<std::byte> hex_to_binary(const std::string& hex) {
    assert(hex.size() % 2 == 0 && "invalid hex data size");
    std::vector<std::byte> res;
    res.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size() / 2; ++i) {
        res.push_back(static_cast<std::byte>((hex_char_to_val(hex[2 * i]) << 4) |
                                             hex_char_to_val(hex[2 * i + 1])));
    }
    return res;
}

static std::string bytes_to_hex(const std::byte* bytes, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        auto b = static_cast<unsigned>(bytes[i]);
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

static point_t make_point(const std::string& x_str, const std::string& y_str) {
    return point_t{f_element{x_str.c_str()}, f_element{y_str.c_str()}};
}

static void assert_point_eq(const point_t& got, const point_t& exp) {
    auto eq = got == exp;
    bn254fr_assert_equal_u32(eq.data(), 1u);
}

// Generator, 2G, and the identity.
static const char* G_X  = "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A";
static const char* G_Y  = "0x6666666666666666666666666666666666666666666666666666666666666658";
static const char* G2_X = "0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e";
static const char* G2_Y = "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9";
static const char* ID_X = "0x0";
static const char* ID_Y = "0x1";

// ---------------------------------------------------------------- point encoding

static void do_test_point_encode(const std::string& x, const std::string& y,
                                 const std::string& exp_hex) {
    auto enc = Ctx::point_encode(make_point(x, y));
    assert_one(bytes_to_hex(enc.data(), enc.size()) == exp_hex);
}

void test_point_encode() {
    do_test_point_encode(G_X, G_Y,
        "5866666666666666666666666666666666666666666666666666666666666666");
    do_test_point_encode(G2_X, G2_Y,
        "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022");
    do_test_point_encode(ID_X, ID_Y,
        "0100000000000000000000000000000000000000000000000000000000000000");
    do_test_point_encode(
        "0x3f348ad8e75b7612eabaecef94d73a99fdd28f85bb46ebf17c2ed453356b1687",
        "0x9b5266c18a2be69cb3ebfefa3091020009a8377f21b2ba5339636e759442adc",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589");
}

// ---------------------------------------------------------------- on curve

static void do_test_point_on_curve(const std::string& x, const std::string& y, bool exp) {
    auto res = curve().on_curve(make_point(x, y));
    bn254fr_assert_equal_u32(res.data(), exp ? 1u : 0u);
}

void test_point_on_curve() {
    do_test_point_on_curve(G_X, G_Y, true);
    do_test_point_on_curve(G2_X, G2_Y, true);
    do_test_point_on_curve(ID_X, ID_Y, true);
    // Generator with the last nibble of x altered.
    do_test_point_on_curve(
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51B", G_Y, false);
}

// ---------------------------------------------------------------- group law

void test_point_add() {
    assert_point_eq(curve().point_add(curve().generator(), curve().generator()),
                    make_point(G2_X, G2_Y));

    point_t id = make_point(ID_X, ID_Y);
    assert_point_eq(curve().point_add(id, id), id);
    assert_point_eq(curve().point_add(curve().generator(), id), curve().generator());
    assert_point_eq(curve().point_add(id, curve().generator()), curve().generator());

    // P + (-P) == identity
    assert_point_eq(curve().point_add(curve().generator(),
                                      curve().point_negate(curve().generator())), id);
}

void test_point_double() {
    assert_point_eq(curve().point_double(make_point(G_X, G_Y)), make_point(G2_X, G2_Y));
}

void test_scalar_mul() {
    // NOTE: k = 0 is deliberately not tested here, and is not supported by `scalar_mul`.
    //
    // `scalar_mul` proves [x]P - [z]Q = O with x == z*k (mod n), and constrains both x and z
    // to be non-zero with x < sqrt(n) (curve_base.hpp). For k = 0 that would require
    // x == 0 (mod n) with 0 < x < sqrt(n), which has no solution -- the constraint system is
    // unsatisfiable rather than wrong. `scalar_mul_generator` takes a different path and does
    // handle k = 0; it is covered below.
    //
    // Both callers keep k away from zero in practice: ECDSA's u2 = r/s has r != 0 enforced,
    // and EdDSA's k is a SHA-512 output reduced mod L.
    s_element k1{"1"};
    assert_point_eq(curve().scalar_mul(k1, make_point(G_X, G_Y)), make_point(G_X, G_Y));

    s_element k{"1000"};
    assert_point_eq(
        curve().scalar_mul(k, make_point(G_X, G_Y)),
        make_point("0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                   "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7"));
}

void test_scalar_mul_generator() {
    s_element k0{"0x0"};
    assert_point_eq(curve().scalar_mul_generator(k0), make_point(ID_X, ID_Y));

    // Same vector as test_scalar_mul, through the precomputed-generator path.
    s_element k{"1000"};
    assert_point_eq(
        curve().scalar_mul_generator(k),
        make_point("0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                   "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7"));
}

// ---------------------------------------------------------------- EdDSA verification

static void do_test_verify(const std::string& pk_hex, const std::string& msg_hex,
                           const std::string& sig_hex, bool exp) {
    auto pk  = hex_to_binary(pk_hex);
    auto sig = hex_to_binary(sig_hex);
    auto msg = hex_to_binary(msg_hex);
    assert(pk.size() == Ctx::pubkey_bytes && sig.size() == Ctx::signature_bytes);

    Ctx ctx{std::span<const std::byte, Ctx::pubkey_bytes>{pk.data(), Ctx::pubkey_bytes}};
    auto valid = ctx.verify(
        std::span<const std::byte, Ctx::signature_bytes>{sig.data(), Ctx::signature_bytes},
        std::span<const std::byte>{msg.data(), msg.size()});

    bn254fr_assert_equal_u32(valid.data(), exp ? 1u : 0u);
}

void test_verify() {
    // RFC 8032 section 7.1, TEST 1 (empty message)
    do_test_verify(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc"
        "61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        true);

    // RFC 8032 section 7.1, TEST 2 (1-byte message)
    do_test_verify(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e4"
        "58f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        true);

    // RFC 8032 section 7.1, TEST 3 (2-byte message)
    do_test_verify(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290a"
        "e67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        true);
}

void test_verify_reject() {
    // TEST 1 with the low bit of S flipped.
    do_test_verify(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc"
        "61e39701cf9b46bd25bf5f0595bbe24655141438e7a100a",
        false);

    // TEST 1 signature presented against TEST 2's public key.
    do_test_verify(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc"
        "61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        false);

    // TEST 2's signature against TEST 2's key, but over the wrong message.
    do_test_verify(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "73",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e4"
        "58f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        false);
}

// ---------------------------------------------------------------- key derivation

/// `from_seed` is the only derivation path, so the encoding it produces is checked against
/// the RFC's published public key -- external ground truth rather than this implementation.
static void do_test_from_seed(const std::string& seed_hex, const std::string& exp_hex) {
    auto seed = hex_to_binary(seed_hex);
    assert(seed.size() == Ctx::seed_bytes);
    std::span<const std::byte, Ctx::seed_bytes> s{seed.data(), Ctx::seed_bytes};

    auto enc = Ctx::from_seed(s).encoded_pubkey();
    assert_one(bytes_to_hex(enc.data(), enc.size()) == exp_hex);
}

/// The end-to-end signer-side flow: derive the key from a seed, then check a signature under
/// it. Proves knowledge of the seed and the validity of the signature in one circuit.
static void do_test_from_seed_verify(const std::string& seed_hex, const std::string& msg_hex,
                                     const std::string& sig_hex, bool exp) {
    auto seed = hex_to_binary(seed_hex);
    auto sig  = hex_to_binary(sig_hex);
    auto msg  = hex_to_binary(msg_hex);
    assert(seed.size() == Ctx::seed_bytes && sig.size() == Ctx::signature_bytes);

    auto ctx = Ctx::from_seed(
        std::span<const std::byte, Ctx::seed_bytes>{seed.data(), Ctx::seed_bytes});
    auto valid = ctx.verify(
        std::span<const std::byte, Ctx::signature_bytes>{sig.data(), Ctx::signature_bytes},
        std::span<const std::byte>{msg.data(), msg.size()});

    bn254fr_assert_equal_u32(valid.data(), exp ? 1u : 0u);
}

void test_from_seed() {
    // RFC 8032 section 7.1, TEST 1-3 secret/public key pairs.
    do_test_from_seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    do_test_from_seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    do_test_from_seed("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");

    // TEST 2, verified under the derived key rather than a supplied one. Only one vector is
    // taken this far: each from_seed adds a full scalar_mul_generator.
    do_test_from_seed_verify(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e4"
        "58f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        true);

    // Same, with the low bit of S flipped: the derived key must not rescue a bad signature.
    do_test_from_seed_verify(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e4"
        "58f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c01",
        false);
}

int main(int argc, char* argv[]) {
    test_point_encode();
    test_point_on_curve();
    test_point_add();
    test_point_double();
    test_scalar_mul();
    test_scalar_mul_generator();
    test_verify();
    test_verify_reject();
    test_from_seed();

    return 0;
}
