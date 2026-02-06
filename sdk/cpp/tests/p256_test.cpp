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

#include <ligetron/ec/p256.hpp>
#include <string>

using namespace ligetron;


using curve = ec::p256_curve;
using point_t = ec::p256_curve::point;
using f_element_t = ec::p256_curve::base_field_element;
using s_element_t = ec::p256_curve::scalar_field_element;


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

f_element_t field_from_limbs(const std::vector<std::string> & limbs_str,
                             uint32_t n_bits,
                             bool is_norm,
                             bool is_unsign,
                             uint32_t base = 0) {
    uint32_t size = limbs_str.size();

    bn254fr_t *limbs = new bn254fr_t[size];
    for (uint32_t i = 0; i < size; ++i) {
        bn254fr_alloc(limbs[i]);
        bn254fr_set_str(limbs[i], limbs_str[i].c_str(), base);
    }

    bn254fr_bigint val{limbs, uint32_t{limbs_str.size()}, n_bits, is_unsign};
    curve::scalar_field_element::storage_type storage{val, is_norm};

    for (uint32_t i = 0; i < size; ++i) {
        bn254fr_free(limbs[i]);
    }

    delete [] limbs;

    return f_element_t{storage, false};
}


static void print_u32(const std::string &msg, uint32_t x) {
    print_str(msg.c_str(), msg.size());
    bn254fr_t bnx;
    bn254fr_alloc(bnx);
    bn254fr_set_u32(bnx, x);
    bn254fr_print(bnx, 10);
    bn254fr_free(bnx);
}

void do_test_point_add_large() {
    auto p1_x = field_from_limbs (
        {
            "1c0028fc62402d6265bdc1a6b30d1cfa9bb4ee2b6c99e",
            "380061f8707fb6c1911bcd3821add2e588837fac09024",
            "1c0038fc0e3f6fd886e0fbd41ce3498abd3f27c28da30",
            "1c0038fc0e3f324ae19ebf04d7e2595b99a4543707156",
            "1c0038fc0e3f62ab0f2b4592edfd0d88e562a8267ee13",
            "1c0038fc0e3f66e3d39817ce94b73d2fd7fd305292894",
            "1c0038fc0e3f6b32f3790f6dce36fe54cd415fe8806b8"
        },
        190,
        false,
        false,
        16
    );

    print_u32("LIMBS: ", p1_x.data().size());

    auto p1_y = field_from_limbs (
        {
            "5ada38b674336a21",
            "55840f2034730e9b",
            "583f51e85a5eb3a1",
            "b1c14ddfdc8ec1b2",
            "0",
            "0",
            "0",
            "0",
            "0",
            "0"
        },
        206,
        false,
        false,
        16
    );

    auto p2_x = field_from_limbs (
        {
            "50034858989b9aa2fb2ac1b3956b3dbf",
            "5f0064eb905219788911cea5f326f282",
            "2b0a41340b1c620f30155ac805d1f17c",
            "113b4d5871998c7f299047823597341ca",
            "9f228698e227582038baa09c0e496478",
            "18c0650c80f57da48e7644e1a02c77d0",
            "de91aec87820175313a5e7e4064135a4"
        },
        132,
        false,
        false,
        16
    );

    auto p2_y = field_from_limbs (
        {
            "2a850b625a5728ad4f39195c7b816ffbce61183f2c68d5e2f583",
            "15482a09a9af041afd2ca9c9f9bc1122a741dbf21ee43172f4cd",
            "154bcdd097d031866559a726ade09caf4a2399885ae130ba09f4",
            "15556c87896a723086fb9acddba6176197a821a2af63ded3406a",
            "154c4332201ec952c58f32f00e4b8d3e996dfc4fbbc44fc6b5c1",
            "154b30739af696a7d892a605dd94c4a87e6c0ce789ddd992377c",
            "1549196ad21466ecb43453815920a48dd6f2337b912aab08c9f2",
            "1547ce289fcbb63f8732e5c7a7fcb7f3e6208ef456b013671ea5",
            "1549c071a629cfbeb665f36f47ad48822a1842839c64c2da592b",
            "15400c5f046d451713c09a3bf4c2716b61bd651cb0745f1efff3"
        },
        207,
        false,
        false,
        16
    );

    point_t p1{p1_x, p1_y};
    point_t p2{p2_x, p2_y};

    curve::point_add(p1, p2);
}

void test_point_add() {
    point_t g2{"0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
                  "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1"};
    point_t g3{"0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C",
                  "0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032"};
    do_test_point_add(curve::generator(), g2, g3);

    // point_t zero;
    // do_test_point_add(zero, point_t::generator(), point_t::generator());

    // do_test_point_add_large();
}

void test_point_double() {
    // g * 4 = (g * 2) * 2
    do_test_point_double("0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978",
                         "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1",
                         "0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852",
                         "0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6");
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
    do_test_scalar_mul("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                       "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                       "112233445566778899",
                       "0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
                       "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21");
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
    do_test_scalar_mul_generator("112233445566778899",
                                 "0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
                                 "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21");
}

int main(int argc, char * argv[]) {
    test_point_add();
    test_point_double();
    test_scalar_mul();
    test_scalar_mul_generator();

    return 0;
}
