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

#include <ligetron/ff/prime_field_uint256.h>
#include <ligetron/api.h>
#include <array>
#include <string>


using namespace ligetron;


// Using P256 prime for testing uint256 field
class test_field: public ff::prime_field_uint256<test_field> {
public:
    static storage_type &modulus() {
        static storage_type m{"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"};
        return m;
    }
};
    

static_assert(ff::FiniteFieldPolicy<test_field>);
static_assert(ff::HasImportU32<test_field>);
    
    
/// P256 field element
using test_field_element = ff::field_element<test_field>;


void test_ctor_dtor() {
    test_field_element fx;
    auto x = to_uint256(fx);
    uint256 zero;
    uint256::assert_equal(x, zero);
}

void test_set_get_uint256() {
    uint256 x{5};
    test_field_element fx;
    set_uint256(fx, x);
    auto y = to_uint256(fx);
    uint256::assert_equal(x, y);
}

void test_print() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";
    test_field_element val;
    set_uint256(val, uint256{str});
    val.print();
}

void test_ctor_uint256() {
    uint256 x{12312313123ULL};
    test_field_element fx{x};
    uint256 y = to_uint256(fx);
    uint256::assert_equal(x, y);

    // // construction from uint256 with reduction
    // uint256 large{"0xffffffff00000001000000000000000000000001ffffffffffffffffffffffff"};
    // uint256 exp_large{"0x1000000000000000000000000"};
    // test_field_element flarge{large, true};
    // assert_equal(exp_large, to_uint256(flarge));
}

void test_ctor_int() {
    test_field_element fx{1};
    uint256 x = to_uint256(fx);
    uint256 one{1};
    uint256::assert_equal(x, one);
}

void test_copy_ctor() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 x{str};
    test_field_element fx{x};
    test_field_element fy{fx};
    uint256 y = to_uint256(fy);
    uint256::assert_equal(x, y);
}

void do_test_add(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    test_field_element b{uint256{b_str.c_str()}};
    uint256 exp{exp_str.c_str()};

    auto res = a + b;

    uint256::assert_equal(to_uint256(res), exp);
}

void test_add() {
    // no overflow
    do_test_add("10", "20", "30");

    // // no overflow, larger than Prime
    // do_test_add("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffe",   // prime - 1
    //             "2",
    //             "1");

    // // overflow
    // do_test_add("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffe",   // prime - 1
    //             "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd",   // prime - 2
    //             "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc");
}

void do_test_sub(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    test_field_element b{uint256{b_str.c_str()}};
    test_field_element exp{uint256{exp_str.c_str()}};

    auto res = a - b;

    uint256::assert_equal(to_uint256(res), to_uint256(exp));
}

void test_sub() {
    // not underflow
    do_test_sub("500",
                "400",
                "100");

    // underflow
    // do_test_sub("9",
    //             "10",
    //             "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffe");  // prime - 1
}

void do_test_mul(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    test_field_element b{uint256{b_str.c_str()}};
    test_field_element exp{uint256{exp_str.c_str()}};

    auto res = a * b;
    to_uint256(res);

//    assert_equal(to_uint256(res), to_uint256(exp));
}

void test_mul() {
    // no overflow
    do_test_mul("34028236692093846346337460743176821145",
                "1209371987239812739812731728379123812",
                "41152796230584246818469977629329928449168694384595558569076337982534604740");

    // overflow
    do_test_mul("3402823669209384634633746074317682114521412342222222222222222222222222222222",
                "1209371987239812739812731728379123812",
                "58512464492546777013172437578310408470178981375010378539944553533908315921941");
}

void do_test_div(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    test_field_element b{uint256{b_str.c_str()}};
    test_field_element exp{uint256{exp_str.c_str()}};

    auto res = a / b;

    uint256::assert_equal(to_uint256(res), to_uint256(exp));
}

void test_div() {
    do_test_div("34028236692093846346337460743176821145",
                "1209371987239812739812731728379123812123123",
                "52875600598123785107505835260439024755840630830216046830155940773978164657184");
}

void do_test_neg(const std::string &a_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    uint256 exp{exp_str.c_str()};

    auto res = -a;

    uint256::assert_equal(to_uint256(res), exp);
}

void test_neg() {
    // zero
    do_test_neg("0", "0");

    // non zero
    do_test_neg("100", "0xffffffff00000001000000000000000000000000ffffffffffffffffffffff9b");
}

void do_test_inv(const std::string &a_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    uint256 exp{exp_str.c_str()};

    test_field_element res;
    test_field_element::inv(res, a);

    uint256::assert_equal(to_uint256(res), exp);
}

void test_inv() {
    do_test_inv("100", "0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14");
}

void do_test_sqr(const std::string &a_str,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    uint256 exp{exp_str.c_str()};

    test_field_element res;
    test_field_element::sqr(res, a);

    uint256::assert_equal(to_uint256(res), exp);
}

void test_sqr() {
    do_test_sqr("0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14",
                "0xa5182a988ba5e3549ce703afb7e90ff972474539944d013a92a305532617c1bd");
}

void do_test_pow(const std::string &a_str,
                 uint32_t e,
                 const std::string &exp_str) {

    test_field_element a{uint256{a_str.c_str()}};
    uint256 exp{exp_str.c_str()};

    test_field_element res;
    test_field_element::powm_ui(res, a, e);

    uint256::assert_equal(to_uint256(res), exp);
}

void test_pow() {
    do_test_pow("0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14",
                0,
                "1");

    do_test_pow("0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14",
                1,
                "0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14");

    do_test_pow("0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14",
                8726568,
                "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4");
}

void test_import_u32() {
    const char *str = "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    std::array<uint32_t, 8> limbs = {
        0x2826a8b4,
        0x056599a3,
        0x77578e37,
        0xc3b908a4,
        0x8d14e0f8,
        0xce09198a,
        0x70684f6c,
        0xf1bfbae7
    };

    test_field_element x;
    x.import_limbs(limbs);
    uint256::assert_equal(to_uint256(x), uint256{str});

    const char *str2 = "0x70684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    std::array<uint32_t, 7> limbs2 = {
        0x2826a8b4,
        0x056599a3,
        0x77578e37,
        0xc3b908a4,
        0x8d14e0f8,
        0xce09198a,
        0x70684f6c
    };

    test_field_element x2;
    x2.import_limbs(limbs2);
    uint256::assert_equal(to_uint256(x2), uint256{str2});
}

void test_export_u32() {
    const char *str = "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    std::array<uint32_t, 8> exp_limbs = {
        0x2826a8b4,
        0x056599a3,
        0x77578e37,
        0xc3b908a4,
        0x8d14e0f8,
        0xce09198a,
        0x70684f6c,
        0xf1bfbae7
    };

    std::array<uint32_t, 8> limbs;

    test_field_element x;
    set_uint256(x, uint256{str});
    x.export_limbs(limbs);

    for (size_t i = 0; i < limbs.size(); ++i) {
        assert_one(limbs[i] == exp_limbs[i]);
    }
}

void test_import_bytes() {
    const char *str_little = "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    const char *str_big = "0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870e7babff1";
    std::array<unsigned char, 32> bytes = {
        0xb4, 0xa8, 0x26, 0x28,
        0xa3, 0x99, 0x65, 0x05,
        0x37, 0x8e, 0x57, 0x77,
        0xa4, 0x08, 0xb9, 0xc3,
        0xf8, 0xe0, 0x14, 0x8d,
        0x8a, 0x19, 0x09, 0xce,
        0x6c, 0x4f, 0x68, 0x70,
        0xe7, 0xba, 0xbf, 0xf1
    };

    test_field_element x_little;
    x_little.import_bytes_little(bytes);
    uint256::assert_equal(to_uint256(x_little), uint256{str_little});

    test_field_element x_big;
    x_big.import_bytes_big(bytes);
    uint256::assert_equal(to_uint256(x_big), uint256{str_big});

    const char *str2_little = "0x70684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    const char *str2_big = "0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870";
    std::array<unsigned char, 28> bytes2 = {
        0xb4, 0xa8, 0x26, 0x28,
        0xa3, 0x99, 0x65, 0x05,
        0x37, 0x8e, 0x57, 0x77,
        0xa4, 0x08, 0xb9, 0xc3,
        0xf8, 0xe0, 0x14, 0x8d,
        0x8a, 0x19, 0x09, 0xce,
        0x6c, 0x4f, 0x68, 0x70
    };

    test_field_element x2_little;
    x2_little.import_bytes_little(bytes2);
    uint256::assert_equal(to_uint256(x2_little), uint256{str2_little});

    test_field_element x2_big;
    x2_big.import_bytes_big(bytes2);
    uint256::assert_equal(to_uint256(x2_big), uint256{str2_big});


    // test reduction after bytes import

    const char *str3_little = "0x70684f6bce09198a8d14e0f8c3b908a377578e37056599a400000000";
    const char *str3_big = "0xa3996504378e5777a408b9c3f8e0148c8a1909ce6c4f687100000000";
    std::array<unsigned char, 32> bytes3 = {
        0xff, 0xff, 0xff, 0xff,
        0xa3, 0x99, 0x65, 0x05,
        0x37, 0x8e, 0x57, 0x77,
        0xa4, 0x08, 0xb9, 0xc3,
        0xf8, 0xe0, 0x14, 0x8d,
        0x8a, 0x19, 0x09, 0xce,
        0x6c, 0x4f, 0x68, 0x70,
        0xff, 0xff, 0xff, 0xff
    };

    test_field_element x3_little;
    x3_little.import_bytes_little(bytes3);
    uint256::assert_equal(to_uint256(x3_little), uint256{str3_little});

    test_field_element x3_big;
    x3_big.import_bytes_big(bytes3);
    uint256::assert_equal(to_uint256(x3_big), uint256{str3_big});
}

void test_export_bytes() {
    const char *str_little = "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";
    const char *str_big = "0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870e7babff1";
    std::array<unsigned char, 32> exp_bytes = {
        0xb4, 0xa8, 0x26, 0x28,
        0xa3, 0x99, 0x65, 0x05,
        0x37, 0x8e, 0x57, 0x77,
        0xa4, 0x08, 0xb9, 0xc3,
        0xf8, 0xe0, 0x14, 0x8d,
        0x8a, 0x19, 0x09, 0xce,
        0x6c, 0x4f, 0x68, 0x70,
        0xe7, 0xba, 0xbf, 0xf1
    };


    std::array<unsigned char, 32> bytes_little;

    test_field_element x_little;
    set_uint256(x_little, uint256{str_little});
    x_little.export_bytes_little(bytes_little);

    for (size_t i = 0; i < bytes_little.size(); ++i) {
        assert_one(bytes_little[i] == exp_bytes[i]);
    }


    std::array<unsigned char, 32> bytes_big;

    test_field_element x_big;
    set_uint256(x_big, uint256{str_big});
    x_big.export_bytes_big(bytes_big);

    for (size_t i = 0; i < bytes_big.size(); ++i) {
        assert_one(bytes_big[i] == exp_bytes[i]);
    }
}

void test_mux() {
    test_field_element a{10}, b{20};
    bn254fr_class cond_0{0};
    bn254fr_class cond_1{1};

    auto res_0 = test_field_element::mux(cond_0, a, b);
    auto res_1 = test_field_element::mux(cond_1, a, b);

    uint256::assert_equal(to_uint256(res_0), to_uint256(a));
    uint256::assert_equal(to_uint256(res_1), to_uint256(b));
}

void test_eqz() {
    bn254fr_class bn_zero;
    bn254fr_class bn_one{1};

    test_field_element zero;
    test_field_element non_zero{"1231231231123"};

    auto res_true = test_field_element::eqz(zero);
    auto res_false = test_field_element::eqz(non_zero);

    bn254fr_class::assert_equal(res_true, bn_one);
    bn254fr_class::assert_equal(res_false, bn_zero);
}

void test_to_bits() {
    bn254fr_class zero, one{1};

    test_field_element x{"5"};
    std::array<bn254fr_class, test_field::num_rounded_bits> bits;
    x.to_bits(bits.data());

    bn254fr_class::assert_equal(bits[0], one);
    bn254fr_class::assert_equal(bits[1], zero);
    bn254fr_class::assert_equal(bits[2], one);

    for (size_t i = 3; i < test_field::num_rounded_bits; ++i) {
        bn254fr_class::assert_equal(bits[i], zero);
    }
}

int main(int argc, char *argv[]) {
    test_ctor_dtor();
    test_set_get_uint256();
    test_print();
    test_ctor_uint256();
    test_ctor_int();
    test_copy_ctor();

    test_add();
    test_sub();
    test_mul();
    test_div();
    test_neg();
    test_inv();
    test_sqr();
    test_pow();
    test_mux();
    test_eqz();

    test_to_bits();

    test_import_u32();
    test_export_u32();

    test_import_bytes();
    test_export_bytes();

    return 0;
}
