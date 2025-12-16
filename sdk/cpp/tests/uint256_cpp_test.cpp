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

#include <ligetron/uint256_cpp.h>
#include <ligetron/api.h>
#include <array>
#include <string>


using namespace ligetron;


using uint256_words_array = std::array<bn254fr_class, UINT256_NLIMBS>;
using uint256_words_uint_array = std::array<uint64_t, UINT256_NLIMBS>;
using uint256_words_str_array = std::array<std::string, UINT256_NLIMBS>;


void assert_words_equal(uint256 val, uint256_words_array &exp_words) {
    bn254fr_class words[UINT256_NLIMBS];
    val.get_words(&words[0]);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_class::assert_equal(words[i], exp_words[i]);
    }
}

void assert_uint_words_equal(uint256 &val,
                             const uint256_words_uint_array &exp_uint_words) {

    bn254fr_class words[UINT256_NLIMBS];
    bn254fr_class exp_words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        exp_words[i].set_u64(exp_uint_words[i]);
    }

    val.get_words(words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_class::assert_equal(words[i], exp_words[i]);
    }
}

void assert_words_equal(uint256 val,
                        const uint256_words_str_array &exp_words_str,
                        uint32_t base) {
    bn254fr_class words[UINT256_NLIMBS];
    bn254fr_class exp_words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        exp_words[i].set_str(exp_words_str[i].c_str(), base);
    }

    val.get_words(&words[0]);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_class::assert_equal(words[i], exp_words[i]);
    }
}

void test_ctor_dtor() {
    uint256 x;
    assert_uint_words_equal(x, {0ULL, 0ULL, 0ULL, 0ULL});
}

void test_set_u64_get_u64() {
    uint256 x;

    uint64_t uval = 0x3521787ULL;
    x.set_u64(uval);
    auto uval2 = x.get_u64();
    assert_one(uval2 == uval);
    assert_uint_words_equal(x, {uval, 0ULL, 0ULL, 0ULL});

}

void test_set_words() {
    uint256 x;

    std::array<uint64_t, UINT256_NLIMBS> words_u64 =
        {0x1223EA, 0xF781A231, 0x2349871E, 0x22134198};
    bn254fr_class words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        words[i].set_u64(words_u64[i]);
    }

    x.set_words(words);
    assert_uint_words_equal(x, words_u64);
}

void test_set_str() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 val;
    val.set_str(str, 10);

    assert_words_equal(val,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void do_test_set_bytes(const unsigned char *data,
                       uint32_t len,
                       bool checked,
                       int order,
                       const uint256_words_str_array &exp_words_str) {
    
    uint256 val;

    if (checked) {
        if (order == -1) {
            val.set_bytes_little(data, len);
        } else {
            val.set_bytes_big(data, len);
        }
    } else {
        if (order == -1) {
            val.set_bytes_little_unchecked(data, len);
        } else {
            val.set_bytes_big_unchecked(data, len);
        }
    }

    assert_words_equal(val,
                       exp_words_str,
                       10);
}

void test_set_bytes() {
    unsigned char data_little_26[] = {
        0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6,
        0x08, 0x6a, 0xbf, 0x37, 0x6d, 0x51, 0x2d, 0x97,
        0xee, 0x69, 0x27, 0xb0, 0xc9, 0x5f, 0xde, 0x09,
        0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    std::array<std::string, 4> exp_little_26 = {
        "17770160115856198064",
        "10893452603207674376",
        "711111111019555310",
        "48042"
    };

    do_test_set_bytes(data_little_26, 26, false, -1, exp_little_26);
    do_test_set_bytes(data_little_26, 26, true, -1, exp_little_26);

    unsigned char data_little_32[] = {
        0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6,
        0x08, 0x6a, 0xbf, 0x37, 0x6d, 0x51, 0x2d, 0x97,
        0xee, 0x69, 0x27, 0xb0, 0xc9, 0x5f, 0xde, 0x09,
        0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };

    std::array<std::string, 4> exp_little_32 = {
        "17770160115856198064",
        "10893452603207674376",
        "711111111019555310",
        "18446744073709534122"
    };

    do_test_set_bytes(data_little_32, 32, false, -1, exp_little_32);
    do_test_set_bytes(data_little_32, 32, true, -1, exp_little_32);

    unsigned char data_little_3[] = {
        0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6,
    };

    std::array<std::string, 4> exp_little_3 = {
        "7096752",
        "0",
        "0",
        "0"
    };

    do_test_set_bytes(data_little_3, 3, false, -1, exp_little_3);
    do_test_set_bytes(data_little_3, 3, true, -1, exp_little_3);


    unsigned char data_big_28[] = {
        0x10, 0x00, 0x00, 0x00,
        0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69, 0xEE,
        0x97, 0x2D, 0x51, 0x6D, 0x37, 0xBF, 0x6A, 0x08,
        0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0,
        0xFF, 0xFF, 0xFF, 0xFF
    };

    std::array<std::string, 4> exp_big_28 = {
        "17770160115856198064",
        "10893452603207674376",
        "711111111019555310",
        "268435456"
    };

    do_test_set_bytes(data_big_28, 28, false, 1, exp_big_28);
    do_test_set_bytes(data_big_28, 28, true, 1, exp_big_28);

    unsigned char data_big_32[] = {
        0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69, 0xEE,
        0x97, 0x2D, 0x51, 0x6D, 0x37, 0xBF, 0x6A, 0x08,
        0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0,
    };

    std::array<std::string, 4> exp_big_32 = {
        "17770160115856198064",
        "10893452603207674376",
        "711111111019555310",
        "1152921508901814271"
    };

    do_test_set_bytes(data_big_32, 32, false, 1, exp_big_32);
    do_test_set_bytes(data_big_32, 32, true, 1, exp_big_32);

    do_test_set_bytes(data_big_28, 28, false, 1, exp_big_28);
    do_test_set_bytes(data_big_28, 28, true, 1, exp_big_28);

    unsigned char data_big_3[] = {
        0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0,
    };

    std::array<std::string, 4> exp_big_3 = {
        "16161866",
        "0",
        "0",
        "0"
    };

    do_test_set_bytes(data_big_3, 3, false, 1, exp_big_3);
    do_test_set_bytes(data_big_3, 3, true, 1, exp_big_3);
}

void test_to_bytes_little(bool checked) {
    const unsigned char expected_data[] = {
        0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6,
        0x08, 0x6a, 0xbf, 0x37, 0x6d, 0x51, 0x2d, 0x97,
        0xee, 0x69, 0x27, 0xb0, 0xc9, 0x5f, 0xde, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    unsigned char data[32];

    uint256 val;
    bn254fr_class words[UINT256_NLIMBS];

    words[0].set_str("17770160115856198064");
    words[1].set_str("10893452603207674376");
    words[2].set_str("711111111019555310");
    words[3].set_str("0");

    val.set_words(words);

    if (checked) {
        val.to_bytes_little(data);
    } else {
        val.to_bytes_little_unchecked(data);
    }

    for (size_t i = 0; i < sizeof(data); ++i) {
        assert_one(data[i] == expected_data[i]);
    }
}

void test_to_bytes_big(bool checked) {
    const unsigned char expected_data[] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69, 0xEE,
        0x97, 0x2D, 0x51, 0x6D, 0x37, 0xBF, 0x6A, 0x08,
        0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0
    };

    unsigned char data[32];

    uint256 val;
    bn254fr_class words[UINT256_NLIMBS];

    words[0].set_str("17770160115856198064");
    words[1].set_str("10893452603207674376");
    words[2].set_str("711111111019555310");
    words[3].set_str("1152921504606846976");

    val.set_words(words);

    if (checked) {
        val.to_bytes_big(data);
    } else {
        val.to_bytes_big_unchecked(data);
    }

    for (size_t i = 0; i < sizeof(data); ++i) {
        assert_one(data[i] == expected_data[i]);
    }
}

void test_set_bn254() {
    uint256 x;

    uint64_t uval = 0x12378AF62;

    bn254fr_class bn;
    bn.set_u64(uval);
    x.set_bn254(bn);

    assert_uint_words_equal(x, {uval, 0ULL, 0ULL, 0ULL});
}

void test_to_from_bits() {
    const char *str =
        "115792089210356248762697446949407573530086143415211086033018482518360559134033";
    uint256 x{str}, y;
    bn254fr_class bits[256];

    x.to_bits(bits);
    y.from_bits(bits);
    assert_equal(x, y);
}

void test_print() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 val;

    val.set_str(str, 10);
    val.print();
}

void test_ctor_uint256_t() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256_t x;
    uint256_alloc(x);
    uint256_set_str(x, str, 0);

    uint256 y{x};

    uint256_free(x);

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_ctor_bn254() {
    uint64_t uval = 0x12378AF62;
    bn254fr_class bn;
    bn.set_u64(uval);
    uint256 x{bn};

    assert_uint_words_equal(x, {uval, 0ULL, 0ULL, 0ULL});
}

void test_ctor_u64() {
    uint256 x{8381293058128512ULL};

    assert_words_equal(x,
                       {
                            "8381293058128512",
                            "0",
                            "0",
                            "0"
                       },
                       10);
}

void test_ctor_str() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 x{str};

    assert_words_equal(x,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_copy_ctor() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 x{str};
    uint256 y{x};

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_move_ctor() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 x{str};
    uint256 y{std::move(x)};

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_copy() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 x{str};
    uint256 y;
    y.copy(x);

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_move() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 zero;
    uint256 x;
    assert_equal(x, zero);

    uint256 y{str};
    x.move(std::move(y));

    assert_words_equal(x,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_copy_assign() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 zero;
    uint256 x;
    assert_equal(x, zero);

    uint256 y{str};
    x = y;

    assert_words_equal(x,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void test_move_assign() {
    const char *str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256 zero;
    uint256 x;
    assert_equal(x, zero);

    uint256 y{str};
    x = std::move(y);

    assert_words_equal(x,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);
}

void do_test_add_cc(const std::string &a_str,
                    const std::string &b_str,
                    const std::string &exp_str,
                    bool is_exp_carry = false) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};
    bn254fr_class exp_carry;
    exp_carry.set_u64(static_cast<uint64_t>(is_exp_carry ? 1 : 0));

    auto [res, carry] = add_cc(a, b);

    assert_equal(res, exp);
    bn254fr_class::assert_equal(carry, exp_carry);
}

void test_add_cc() {
    do_test_add_cc("1234567890123456789012345678901234567890123456789012345678901234",
                   "987654321098765432109876543210987654321098765432109876543210987",
                   "2222222211222222221122222222112222222211222222221122222222112221",
                   false);

    do_test_add_cc("115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
                   "10",
                   "9",
                   true);
}

void do_test_add(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = a + b;
    assert_equal(res, exp);
}

void test_add() {
    do_test_add("1234567890123456789012345678901234567890123456789012345678901234",
                "987654321098765432109876543210987654321098765432109876543210987",
                "2222222211222222221122222222112222222211222222221122222222112221");

    do_test_add("115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
                "10",
                "9");
}

void do_test_sub_cc(const std::string &a_str,
                    const std::string &b_str,
                    const std::string &exp_str,
                    bool is_exp_underflow = false) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};
    bn254fr_class exp_underflow;
    exp_underflow.set_u64(static_cast<uint64_t>(is_exp_underflow ? 1 : 0));

    auto [res, underflow] = sub_cc(a, b);

    assert_equal(res, exp);
    bn254fr_class::assert_equal(underflow, exp_underflow);
}

void test_sub_cc() {
    do_test_sub_cc("2222222211222222221122222222112222222211222222221122222222112221",
                   "987654321098765432109876543210987654321098765432109876543210987",
                   "1234567890123456789012345678901234567890123456789012345678901234",
                   false);

    do_test_sub_cc("9",
                   "10",
                   // 2^256 - 1 (wrap-around)
                   "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                   true);
}

void do_test_sub(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = a - b;
    assert_equal(res, exp);
}

void test_sub() {
    do_test_sub("2222222211222222221122222222112222222211222222221122222222112221",
                 "987654321098765432109876543210987654321098765432109876543210987",
                 "1234567890123456789012345678901234567890123456789012345678901234");

    do_test_sub("9",
                "10",
                // 2^256 - 1 (wrap-around)
                "115792089237316195423570985008687907853269984665640564039457584007913129639935");
}

void do_test_mul_wide(const std::string &a_str,
                      const std::string &b_str,
                      const std::string &exp_low_str,
                      const std::string &exp_high_str) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp_low{exp_low_str.c_str()};
    uint256 exp_high{exp_high_str.c_str()};

    auto [low, high] = mul_wide(a, b);
    assert_equal(low, exp_low);
    assert_equal(high, exp_high);
}

void test_mul_wide() {
    // Max 128-bit × Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul_wide("340282366920938463463374607431768211455",  // 2^128 - 1
                "340282366920938463463374607431768211455",
                "115792089237316195423570985008687907852589419931798687112530834793049593217025",  // (2^128 - 1)^2
                "0");

    do_test_mul_wide(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        "340282366920938463463374607431768211455",
        "115792089237316195423570985008687907194483322306703698774364344020009872263056",
        "340282366920938463463374607431768211454"
    );
}

void do_test_mul_lo(const std::string &a_str,
                    const std::string &b_str,
                    const std::string &exp_str) {
    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = mul_lo(a, b);
    assert_equal(res, exp);
}

void test_mul_lo() {
    // Max 128-bit × Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul_lo("340282366920938463463374607431768211455",   // 2^128 - 1
                   "340282366920938463463374607431768211455",
                   "115792089237316195423570985008687907852589419931798687112530834793049593217025");

    do_test_mul_lo(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        "340282366920938463463374607431768211455",
        "115792089237316195423570985008687907194483322306703698774364344020009872263056");
}

void do_test_mul_hi(const std::string &a_str,
                    const std::string &b_str,
                    const std::string &exp_str) {
    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = mul_hi(a, b);
    assert_equal(res, exp);
}

void test_mul_hi() {
    // Max 128-bit × Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul_hi("340282366920938463463374607431768211455",  // 2^128 - 1
                   "340282366920938463463374607431768211455",
                   "0");

    do_test_mul_hi(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        "340282366920938463463374607431768211455",
        "340282366920938463463374607431768211454");
}

void do_test_mul(const std::string &a_str,
                 const std::string &b_str,
                 const std::string &exp_str) {
    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = a * b;
    assert_equal(res, exp);
}

void test_mul() {
    // Max 128-bit × Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul("340282366920938463463374607431768211455",   // 2^128 - 1
                "340282366920938463463374607431768211455",
                "115792089237316195423570985008687907852589419931798687112530834793049593217025");

    do_test_mul(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        "340282366920938463463374607431768211455",
        "115792089237316195423570985008687907194483322306703698774364344020009872263056");
}

void do_test_divide_qr(const std::string &a_low_str,
                       const std::string &a_high_str,
                       const std::string &b_str,
                       const std::string &exp_q_low_str,
                       const std::string &exp_q_high_str,
                       const std::string &exp_r_str) {

    uint256_wide a;
    a.lo.set_str(a_low_str.c_str());
    a.hi.set_str(a_high_str.c_str());
    uint256 b{b_str.c_str()};
    uint256 exp_q_low{exp_q_low_str.c_str()};
    bn254fr_class exp_q_high{exp_q_high_str.c_str()};
    uint256 exp_r{exp_r_str.c_str()};

    uint256 q_low;
    bn254fr_class q_high;
    uint256 r;

    a.divide_qr_normalized(q_low, q_high, r, b);

    assert_equal(q_low, exp_q_low);
    bn254fr_class::assert_equal(q_high, exp_q_high);
    assert_equal(r, exp_r);
}

void test_divide_qr() {
    do_test_divide_qr(
        "100", "0", "10",
        "10", "0", "0"
    );

    do_test_divide_qr(
        "100",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
        "115792089237316195423570985008687907853269984665640564039457584007913129639926", // 2^256 - 10
        "9",
        "1",
        "190"
    );
}

void do_test_inv(const std::string &a_str,
                 const std::string &m_str,
                 const std::string &exp_str) {

    uint256 a{a_str.c_str()};
    uint256 m{m_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = invmod(a, m);
    assert_equal(res, exp);
}

void test_inv() {
    do_test_inv(
        "92083353579669972405495757776470670379717099030169638017457449866473924951844",
        "115792089210356248762697446949407573530086143415211086033018482518360559134033",
        "107144220426932500591649118614422298517760573469212118502069469584724027903412"
    );
}

void test_mux() {
    uint256 a{"115792089210356248762697446949407573530086143415211086033018482518360559134033"};
    uint256 b{"21888242871839275222246405745257275088548364400416034343698204186575808495617"};
    bn254fr_class cond1{1ULL};
    bn254fr_class cond2{static_cast<uint64_t>(0ULL)};

    auto res1 = mux(cond1, a, b);
    auto res2 = mux(cond2, a, b);
    assert_equal(res1, b);
    assert_equal(res2, a);
}

void do_test_eq(const std::string &a_str,
                const std::string &b_str,
                bool exp_res) {

    uint256 a{a_str.c_str()};
    uint256 b{b_str.c_str()};
    bn254fr_class exp;
    exp.set_u32(exp_res ? 1U : 0U);

    auto res = a == b;
    bn254fr_class::assert_equal(res, exp);
}

void test_eq() {
    do_test_eq("112", "112", true);
    do_test_eq("122", "3332", false);
}

void do_test_eqz(const std::string &x_str, bool exp_res) {

    uint256 x{x_str.c_str()};
    bn254fr_class exp;
    exp.set_u32(exp_res ? 1U : 0U);

    auto res = eqz(x);
    bn254fr_class::assert_equal(res, exp);
}

void test_eqz() {
    do_test_eqz("123123123", false);
    do_test_eqz("0", true);
}

void do_test_mod(const std::string &a_low_str,
                 const std::string &a_high_str,
                 const std::string &m_str,
                 const std::string &exp_str) {

    uint256 a_low{a_low_str.c_str()};
    uint256_wide a;
    a.lo.set_str(a_low_str.c_str());
    a.hi.set_str(a_high_str.c_str());
    uint256 m{m_str.c_str()};
    uint256 exp{exp_str.c_str()};

    auto res = a % m;
    res.print();
    assert_equal(res, exp);
}

void test_mod() {
    do_test_mod(
        "100",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
        "115792089237316195423570985008687907853269984665640564039457584007913129639926", // 2^256 - 10
        "190"
    );
}

int main(int argc, char *argv[]) {
    test_ctor_dtor();
    test_set_u64_get_u64();
    test_set_words();
    test_set_str();
    test_set_bytes();
    test_to_bytes_little(false);
    test_to_bytes_little(true);
    test_to_bytes_big(false);
    test_to_bytes_big(true);
    test_set_bn254();
    test_to_from_bits();

    test_print();
    test_ctor_uint256_t();
    test_ctor_bn254();
    test_ctor_u64();
    test_ctor_str();
    test_copy_ctor();
    test_move_ctor();
    test_copy();
    test_move();
    test_copy_assign();
    test_move_assign();

    test_add_cc();
    test_add();
    test_sub_cc();
    test_sub();
    test_mul_wide();
    test_mul_lo();
    test_mul_hi();
    test_mul();
    test_divide_qr();
    test_inv();
    test_mod();

    test_eq();
    test_eqz();
    test_mux();

    return 0;
}
