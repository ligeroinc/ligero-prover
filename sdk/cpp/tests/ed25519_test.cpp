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

#include <ligetron/ec/ed25519.hpp>
#include <ligetron/ec/eddsa.hpp>
#include <string>
#include <vector>
#include <span>
#include <vector>
#include <span>

using namespace ligetron;


using curve = ec::ed25519_curve;
using point_t = ec::ed25519_curve::point;
using f_element_t = ec::ed25519_curve::base_field_element;
using s_element_t = ec::ed25519_curve::scalar_field_element;

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

std::string bytes_to_hex(const unsigned char *bytes, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        unsigned char b = bytes[i];
        out.push_back(hex[(b >> 4) & 0xF]);
        out.push_back(hex[b & 0xF]);
    }
    return out;
}

void do_test_point_encode(const std::string &x_str,
                          const std::string &y_str,
                          const std::string &exp_hex) {
    f_element_t x{x_str.c_str()};
    f_element_t y{y_str.c_str()};
    point_t p{x, y};

    auto enc = ec::ed25519_point_encode(p);
    auto enc_hex = bytes_to_hex(enc.data(), enc.size());
    assert_one(enc_hex == exp_hex);
}

void test_point_encode() {
    // Generator
    do_test_point_encode(
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
        "0x6666666666666666666666666666666666666666666666666666666666666658",
        "5866666666666666666666666666666666666666666666666666666666666666"
    );

    // 2 * Generator
    do_test_point_encode(
        "0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e",
        "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9",
        "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022"
    );

    // Identity
    do_test_point_encode(
        "0x0",
        "0x1",
        "0100000000000000000000000000000000000000000000000000000000000000"
    );

    do_test_point_encode(
        "0x3f348ad8e75b7612eabaecef94d73a99fdd28f85bb46ebf17c2ed453356b1687",
        "0x9b5266c18a2be69cb3ebfefa3091020009a8377f21b2ba5339636e759442adc",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
    );
}

void do_test_point_on_curve(const std::string &x_str,
                            const std::string &y_str,
                            bool exp) {
    f_element_t x{x_str.c_str()};
    f_element_t y{y_str.c_str()};
    point_t p{x, y};

    auto res = ec::ed25519_is_point_on_curve(p);
    bn254fr_assert_equal_u32(res.data(), exp);
}

void test_point_on_curve() {
    // Generator
    do_test_point_on_curve(
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
        "0x6666666666666666666666666666666666666666666666666666666666666658",
        true
    );

    // 2 * Generator
    do_test_point_on_curve(
        "0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e",
        "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9",
        true
    );

    // Identity
    do_test_point_on_curve(
        "0x0",
        "0x1",
        true
    );

    // Generator with typo
    do_test_point_on_curve(
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51B",
        "0x6666666666666666666666666666666666666666666666666666666666666658",
        false
    );
}

void do_test_point_add(const point_t &p1,
                       const point_t &p2,
                       const point_t &exp) {
    auto res = curve::point_add(p1, p2);
    uint256::assert_equal(to_uint256(res.x()), to_uint256(exp.x()));
    uint256::assert_equal(to_uint256(res.y()), to_uint256(exp.y()));
}

void do_test_point_add(const std::string &x1_str, const std::string &y1_str,
                       const std::string &x2_str, const std::string &y2_str,
                       const std::string &exp_x_str, const std::string &exp_y_str) {
    f_element_t x1{x1_str.c_str()};
    f_element_t x2{x2_str.c_str()};
    f_element_t y1{y1_str.c_str()};
    f_element_t y2{y2_str.c_str()};
    f_element_t exp_x{exp_x_str.c_str()};
    f_element_t exp_y{exp_y_str.c_str()};

    point_t p1{x1, y1};
    point_t p2{x2, y2};
    point_t exp{exp_x, exp_y};

    do_test_point_add(p1, p2, exp);
}

void test_point_add() {
    point_t g2{"0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e",
               "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9"};
    do_test_point_add(curve::generator(), curve::generator(), g2);

    point_t id{"0x0", "0x1"};
    do_test_point_add(id, id, id);

    do_test_point_add(curve::generator(), id, curve::generator());
}

void do_test_point_double(point_t &p, point_t &exp) {
    auto res = curve::point_double(p);
    uint256::assert_equal(to_uint256(res.x()), to_uint256(exp.x()));
    uint256::assert_equal(to_uint256(res.y()), to_uint256(exp.y()));
}

void do_test_point_double(const std::string &x_str, const std::string &y_str,
                          const std::string &exp_x_str, const std::string &exp_y_str) {
    f_element_t x{x_str.c_str()};
    f_element_t y{y_str.c_str()};
    f_element_t exp_x{exp_x_str.c_str()};
    f_element_t exp_y{exp_y_str.c_str()};

    point_t p{x, y};
    point_t exp{exp_x, exp_y};

    do_test_point_double(p, exp);
}

void test_point_double() {
    // g * g = g + g
    do_test_point_double("0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
                         "0x6666666666666666666666666666666666666666666666666666666666666658",
                         "0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e",
                         "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9");
}

void do_test_scalar_mul(point_t &p, s_element_t &k, point_t &exp) {
    auto res = curve::scalar_mul(k, p);
    uint256::assert_equal(to_uint256(res.x()), to_uint256(exp.x()));
    uint256::assert_equal(to_uint256(res.y()), to_uint256(exp.y()));
}

void do_test_scalar_mul(const std::string &x_str, const std::string &y_str,
                        const std::string &k_str,
                        const std::string &exp_x_str, const std::string &exp_y_str) {
    f_element_t x{x_str.c_str()};
    f_element_t y{y_str.c_str()};
    s_element_t k{k_str.c_str()};
    f_element_t exp_x{exp_x_str.c_str()};
    f_element_t exp_y{exp_y_str.c_str()};


    point_t p{x, y};
    point_t exp{exp_x, exp_y};

    do_test_scalar_mul(p, k, exp);
}

void test_scalar_mul() {
    do_test_scalar_mul("0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
                       "0x6666666666666666666666666666666666666666666666666666666666666658",
                       "0x0",
                       "0x0",
                       "0x1");

    do_test_scalar_mul("0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
                       "0x6666666666666666666666666666666666666666666666666666666666666658",
                       "1000",
                       "0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                       "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7");
}

void do_test_scalar_mul_generator(s_element_t &k, point_t &exp) {
    auto res = curve::scalar_mul_generator(k);
    uint256::assert_equal(to_uint256(res.x()), to_uint256(exp.x()));
    uint256::assert_equal(to_uint256(res.y()), to_uint256(exp.y()));
}

void do_test_scalar_mul_generator(const std::string &k_str,
                                  const std::string &exp_x_str, const std::string &exp_y_str) {
    s_element_t k{k_str.c_str()};
    f_element_t exp_x{exp_x_str.c_str()};
    f_element_t exp_y{exp_y_str.c_str()};


    point_t exp{exp_x, exp_y};

    do_test_scalar_mul_generator(k, exp);
}

void test_scalar_mul_generator() {
    do_test_scalar_mul_generator("0x0",
                                 "0x0",
                                 "0x1");

    do_test_scalar_mul_generator("1000",
                                 "0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
                                 "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7");
}

void do_test_eddsa_verify(const std::string &k_str,
                          const std::string &r_x_str,
                          const std::string &r_y_str,
                          const std::string &s_str,
                          const std::string &pk_x_str,
                          const std::string &pk_y_str,
                          bool exp) {
    s_element_t k{k_str.c_str()};
    point_t r{r_x_str.c_str(), r_y_str.c_str()};
    s_element_t s{s_str.c_str()};
    point_t pk{pk_x_str.c_str(), pk_y_str.c_str()};

    bool ok = eddsa_verify<curve>(k, r, s, pk);
    assert_one(ok == exp);
}

void test_eddsa_verify() {
    do_test_eddsa_verify(
        "0x454522e167e3e8a132cec316125d8f86cdf00c6e70405293d19964c8ebcea86",
        "0x6218e309d40065fcc338b3127f46837182324bd01ce6f3cf81ab44e62959c82a",
        "0x5501492265e073d874d9e5b81e7f87848a826e80cce2869072ac60c3004356e5",
        "0xb107a8e4341516524be5b59f0f55bd26bb4f91c70391ec6ac3ba3901582b85f",
        "0x55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce",
        "0x1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7",
        true
    );

    do_test_eddsa_verify(
        "0x454522e167e3e8a132cec316125d8f86cdf00c6e70405293d19964c8ebcea86",
        "0x6218e309d40065fcc338b3127f46837182324bd01ce6f3cf81ab44e62959c82a",
        "0x5501492265e073d874d9e5b81e7f87848a826e80cce2869072ac60c3004356e5",
        "0xb107a8e4341516524be5b59f0f55bd26bb4f91c70391ec6ac3ba3901582AAAA", // wrong
        "0x55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce",
        "0x1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7",
        false
    );
}

void do_test_ed25519_verify(const std::string &msg_hex,
                            const std::string &r_x_str,
                            const std::string &r_y_str,
                            const std::string &s_str,
                            const std::string &pk_x_str,
                            const std::string &pk_y_str,
                            bool exp) {
    point_t r{r_x_str.c_str(), r_y_str.c_str()};
    s_element_t s{s_str.c_str()};
    point_t pk{pk_x_str.c_str(), pk_y_str.c_str()};

    auto msg_data = hex_to_binary(msg_hex);
    bool ok = ec::ed25519_verify(msg_data, r, s, pk);
    assert_one(ok == exp);
}

void test_ed25519_verify() {
    do_test_ed25519_verify(
        "",
        "0x6218e309d40065fcc338b3127f46837182324bd01ce6f3cf81ab44e62959c82a",
        "0x5501492265e073d874d9e5b81e7f87848a826e80cce2869072ac60c3004356e5",
        "0xb107a8e4341516524be5b59f0f55bd26bb4f91c70391ec6ac3ba3901582b85f",
        "0x55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce",
        "0x1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7",
        true
    );

    do_test_ed25519_verify(
        "",
        "0x6218e309d40065fcc338b3127f46837182324bd01ce6f3cf81ab44e62959c82a",
        "0x5501492265e073d874d9e5b81e7f87848a826e80cce2869072ac60c3004356e5",
        "0xb107a8e4341516524be5b59f0f55bd26bb4f91c70391ec6ac3ba3901582b000",    // wrong
        "0x55d0e09a2b9d34292297e08d60d0f620c513d47253187c24b12786bd777645ce",
        "0x1a5107f7681a02af2523a6daf372e10e3a0764c9d3fe4bd5b70ab18201985ad7",
        false
    );

    do_test_ed25519_verify(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "0x3f348ad8e75b7612eabaecef94d73a99fdd28f85bb46ebf17c2ed453356b1687",
        "0x9b5266c18a2be69cb3ebfefa3091020009a8377f21b2ba5339636e759442adc",
        "0x4a7317317f1bed97ac18a139c17ca3d30e03164c6c7fbfdecb390acc91f3509",
        "0x58b401b9df6f65a34625400a43fa6e89dd5ae7440e9899c9c96eea995b72fc2f",
        "0x3fe267346819f8eb644dfd2eef6754c3345024e1702c93f43b565ead932b17ec",
        true
    );

    do_test_ed25519_verify(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "0x3f348ad8e75b7612eabaecef94d73a99fdd28f85bb46ebf17c2ed453356b1687",
        "0x9b5266c18a2be69cb3ebfefa3091020009a8377f21b2ba5339636e759442adc",
        "0x4a7317317f1bed97ac18a139c17ca3d30e03164c6c7fbfdecb390acc91f3000",        // wrong
        "0x58b401b9df6f65a34625400a43fa6e89dd5ae7440e9899c9c96eea995b72fc2f",
        "0x3fe267346819f8eb644dfd2eef6754c3345024e1702c93f43b565ead932b17ec",
        false
    );
}

void do_test_ed25519_pubkey_gen_encoded(const std::string &seed_hex,
                                        const std::string &exp_pub_hex) {
    auto seed = hex_to_binary(seed_hex);
    auto enc = ec::ed25519_pubkey_gen_encoded(seed);
    auto enc_hex = bytes_to_hex(enc.data(), enc.size());
    assert_one(enc_hex == exp_pub_hex);
}

void test_ed25519_pubkey_gen_encoded() {
    do_test_ed25519_pubkey_gen_encoded(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );

    do_test_ed25519_pubkey_gen_encoded(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    );

    do_test_ed25519_pubkey_gen_encoded(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    );
}

int main(int argc, char * argv[]) {
    test_point_encode();
    test_point_on_curve();
    test_point_add();
    test_point_double();
    test_scalar_mul();
    test_scalar_mul_generator();
    test_eddsa_verify();
    test_ed25519_verify();
    test_ed25519_pubkey_gen_encoded();

    return 0;
}
