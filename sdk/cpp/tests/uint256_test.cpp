
#include <ligetron/uint256.h>
#include <ligetron/api.h>
#include <array>
#include <string>


using uint256_words_array = std::array<bn254fr_t, UINT256_NLIMBS>;
using uint256_words_uint_array = std::array<uint64_t, UINT256_NLIMBS>;
using uint256_words_str_array = std::array<std::string, UINT256_NLIMBS>;


void assert_words_equal(uint256_t val, const uint256_words_array & exp_words) {
    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    uint256_get_words_checked(words, val);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(words[i], exp_words[i]);
    }

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }
}

void assert_uint_words_equal(uint256_t val,
                             const uint256_words_uint_array & exp_uint_words) {

    bn254fr_t words[UINT256_NLIMBS];
    bn254fr_t exp_words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
        bn254fr_alloc(exp_words[i]);
        bn254fr_set_u64(exp_words[i], exp_uint_words[i]);
    }

    uint256_get_words_checked(words, val);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(words[i], exp_words[i]);
    }

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
        bn254fr_free(exp_words[i]);
    }
}

void assert_words_equal(uint256_t val,
                        const uint256_words_str_array & exp_words_str,
                        uint32_t base) {
    bn254fr_t words[UINT256_NLIMBS];
    bn254fr_t exp_words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
        bn254fr_alloc(exp_words[i]);
        bn254fr_set_str(exp_words[i], exp_words_str[i].c_str(), base);
    }

    uint256_get_words_checked(words, val);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(words[i], exp_words[i]);
    }

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
        bn254fr_free(exp_words[i]);
    }
}

void test_ctor_dtor() {
    uint256_t x;
    uint256_alloc(x);

    assert_uint_words_equal(x, {0ULL, 0ULL, 0ULL, 0ULL});

    uint256_free(x);
}

void test_set_u64_get_u64() {
    uint256_t x;
    uint256_alloc(x);

    uint64_t uval = 0x3521787ULL;
    uint256_set_u64(x, uval);
    auto uval2 = uint256_get_u64(x);
    assert_one(uval2 == uval);
    assert_uint_words_equal(x, {uval, 0ULL, 0ULL, 0ULL});

    uint256_free(x);
}

void test_set_words() {
    uint256_t x;
    uint256_alloc(x);

    std::array<uint64_t, UINT256_NLIMBS> words_u64 =
        {0x1223EA, 0xF781A231, 0x2349871E, 0x22134198};
    bn254fr_t words[UINT256_NLIMBS];

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
        bn254fr_set_u64(words[i], words_u64[i]);
    }

    uint256_set_words_checked(x, words);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }

    bn254fr_free(words[0]);
    bn254fr_free(words[1]);
    bn254fr_free(words[2]);

    assert_uint_words_equal(x, words_u64);

    uint256_free(x);
}

void test_set_str() {
    const char* str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256_t val;
    uint256_alloc(val);

    uint256_set_str(val, str, 10);

    assert_words_equal(val,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);

    uint256_free(val);
}

void do_test_set_bytes(const unsigned char *data,
                       uint32_t len,
                       bool checked,
                       int order,
                       const uint256_words_str_array & exp_words_str) {
    uint256_t val;
    uint256_alloc(val);

    if (checked) {
        if (order == -1) {
            uint256_set_bytes_little_checked(val, data, len);
        } else {
            uint256_set_bytes_big_checked(val, data, len);
        }
    } else {
        if (order == -1) {
            uint256_set_bytes_little(val, data, len);
        } else {
            uint256_set_bytes_big(val, data, len);
        }
    }

    assert_words_equal(val,
                       exp_words_str,
                       10);

    uint256_free(val);
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

    uint256_t val;
    bn254fr_t words[UINT256_NLIMBS];

    uint256_alloc(val);
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    bn254fr_set_str(words[0], "17770160115856198064");
    bn254fr_set_str(words[1], "10893452603207674376");
    bn254fr_set_str(words[2], "711111111019555310");
    bn254fr_set_str(words[3], "0");

    uint256_set_words_checked(val, words);

    if (checked) {
        uint256_to_bytes_little_checked(data, val);
    } else {
        uint256_to_bytes_little(data, val);
    }

    for (size_t i = 0; i < sizeof(data); ++i) {
        assert_one(data[i] == expected_data[i]);
    }

    uint256_free(val);
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
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

    uint256_t val;
    bn254fr_t words[UINT256_NLIMBS];

    uint256_alloc(val);
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    bn254fr_set_str(words[0], "17770160115856198064");
    bn254fr_set_str(words[1], "10893452603207674376");
    bn254fr_set_str(words[2], "711111111019555310");
    bn254fr_set_str(words[3], "1152921504606846976");

    uint256_set_words_checked(val, words);

    if (checked) {
        uint256_to_bytes_big_checked(data, val);
    } else {
        uint256_to_bytes_big(data, val);
    }

    for (size_t i = 0; i < sizeof(data); ++i) {
        assert_one(data[i] == expected_data[i]);
    }

    uint256_free(val);
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }
}

void test_print() {
    const char* str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256_t val;
    uint256_alloc(val);

    uint256_set_str(val, str, 10);
    uint256_print(val);

    uint256_free(val);
}

void test_set_bn254_checked() {
    uint256_t x;
    uint256_alloc(x);

    uint64_t uval = 0x12378AF62;

    bn254fr_t bn;
    bn254fr_alloc(bn);
    bn254fr_set_u64(bn, uval);
    uint256_set_bn254_checked(x, bn);
    bn254fr_free(bn);

    assert_uint_words_equal(x, {uval, 0ULL, 0ULL, 0ULL});

    uint256_free(x);
}

void test_copy_checked() {
    const char* str =
        "241978572001512527289694654294400568637203164540116421040";

    uint256_t x;
    uint256_alloc(x);
    uint256_set_str(x, str, 10);

    uint256_t y;
    uint256_alloc(y);
    uint256_copy_checked(y, x);
    uint256_free(x);

    assert_words_equal(y,
                       {
                            "17770160115856198064",
                            "10893452603207674376",
                            "711111111019555310",
                            "0"
                       },
                       10);

    uint256_free(y);
}

void do_test_add_cc(const std::string& a_str,
                 const std::string& b_str,
                 const std::string& exp_str,
                 bool is_exp_carry = false) {

    uint256_t a, b, exp, res;
    bn254fr_t carry, exp_carry;
    uint256_alloc(a);
    uint256_alloc(b);
    uint256_alloc(exp);
    bn254fr_alloc(exp_carry);
    uint256_alloc(res);
    bn254fr_alloc(carry);

    uint256_set_str(a, a_str.c_str(), 10);
    uint256_set_str(b, b_str.c_str(), 10);
    uint256_set_str(exp, exp_str.c_str(), 10);
    bn254fr_set_u64(exp_carry, static_cast<uint64_t>(is_exp_carry ? 1 : 0));

    uint256_add_checked(res, carry, a, b);
    uint256_assert_equal(res, exp);
    bn254fr_assert_equal(carry, exp_carry);

    uint256_free(a);
    uint256_free(b);
    uint256_free(exp);
    bn254fr_free(exp_carry);
    uint256_free(res);
    bn254fr_free(carry);
}

void test_add_cc() {
    do_test_add_cc("10", "20", "30");

    do_test_add_cc("1234567890123456789012345678901234567890123456789012345678901234",
                "987654321098765432109876543210987654321098765432109876543210987",
                "2222222211222222221122222222112222222211222222221122222222112221",
                false);

    do_test_add_cc("340282366920938463463374607431768211455",
                "999999999999999999999999999999999999",
                "341282366920938463463374607431768211454",
                false);

    do_test_add_cc("11579208923731619542357098500868790785326998466564056403945758400791312963980",
                "1",
                "11579208923731619542357098500868790785326998466564056403945758400791312963981",
                false);

    do_test_add_cc("115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
                "10",
                "9",
                true);
}

void do_test_sub_cc(const std::string& a_str,
                 const std::string& b_str,
                 const std::string& exp_str,
                 bool is_exp_underflow = false) {

    uint256_t a, b, exp, res;
    bn254fr_t underflow, exp_underflow;
    uint256_alloc(a);
    uint256_alloc(b);
    uint256_alloc(exp);
    bn254fr_alloc(exp_underflow);
    uint256_alloc(res);
    bn254fr_alloc(underflow);

    uint256_set_str(a, a_str.c_str(), 10);
    uint256_set_str(b, b_str.c_str(), 10);
    uint256_set_str(exp, exp_str.c_str(), 10);
    bn254fr_set_u64(exp_underflow, static_cast<uint64_t>(is_exp_underflow ? 1 : 0));

    uint256_sub_checked(res, underflow, a, b);
    uint256_assert_equal(res, exp);
    bn254fr_assert_equal(underflow, exp_underflow);

    uint256_free(a);
    uint256_free(b);
    uint256_free(exp);
    bn254fr_free(exp_underflow);
    uint256_free(res);
    bn254fr_free(underflow);
}

void test_sub_cc() {
    do_test_sub_cc("30", "20", "10");

    do_test_sub_cc("2222222211222222221122222222112222222211222222221122222222112221",
                "987654321098765432109876543210987654321098765432109876543210987",
                "1234567890123456789012345678901234567890123456789012345678901234",
                false);

    do_test_sub_cc("341282366920938463463374607431768211454",
                "999999999999999999999999999999999999",
                "340282366920938463463374607431768211455",
                false);

    do_test_sub_cc("11579208923731619542357098500868790785326998466564056403945758400791312963981",
                "1",
                "11579208923731619542357098500868790785326998466564056403945758400791312963980",
                false);

    do_test_sub_cc("9",
                "10",
                // 2^256 - 1 (wrap-around)
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                true);
}

void do_test_mul_wide(const std::string& a_str,
                 const std::string& b_str,
                 const std::string& exp_low_str,
                 const std::string& exp_high_str) {

    uint256_t a, b, exp_low, exp_high, res_low, res_high;
    uint256_alloc(a);
    uint256_alloc(b);
    uint256_alloc(exp_low);
    uint256_alloc(exp_high);
    uint256_alloc(res_low);
    uint256_alloc(res_high);

    uint256_set_str(a, a_str.c_str(), 10);
    uint256_set_str(b, b_str.c_str(), 10);
    uint256_set_str(exp_low, exp_low_str.c_str(), 10);
    uint256_set_str(exp_high, exp_high_str.c_str(), 10);

    uint256_mul_checked(res_low, res_high, a, b);
    uint256_assert_equal(res_low, exp_low);
    uint256_assert_equal(res_high, exp_high);

    uint256_free(a);
    uint256_free(b);
    uint256_free(exp_low);
    uint256_free(exp_high);
    uint256_free(res_low);
    uint256_free(res_high);
}

void test_mul_wide() {
    do_test_mul_wide("2", "3", "6", "0");

    // Max 128-bit × Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul_wide("340282366920938463463374607431768211455",  // 2^128 - 1
                "340282366920938463463374607431768211455",
                "115792089237316195423570985008687907852589419931798687112530834793049593217025",  // (2^128 - 1)^2
                "0");

    // Max 256-bit × 1 = same value
    do_test_mul_wide("115792089237316195423570985008687907853269984665640564039457584007913129639935",  // 2^256 - 1
                "1",
                "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "0");

    // Max 256-bit × 2 = 2^256 - 2 (low) with carry (high = 1)
    do_test_mul_wide("115792089237316195423570985008687907853269984665640564039457584007913129639935",  // 2^256 - 1
                "2",
                "115792089237316195423570985008687907853269984665640564039457584007913129639934",  // 2^256 - 2
                "1");

    // 2^128 × 2^128 = 2^256 (all zeros in low, high = 1)
    do_test_mul_wide("340282366920938463463374607431768211456",  // 2^128
                "340282366920938463463374607431768211456",  // 2^128
                "0",
                "1");

    do_test_mul_wide(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        "340282366920938463463374607431768211455",
        "115792089237316195423570985008687907194483322306703698774364344020009872263056",
        "340282366920938463463374607431768211454"
    );
}

void do_test_divide_qr(const std::string& a_low_str,
                  const std::string& a_high_str,
                  const std::string& b_str,
                  const std::string& exp_q_low_str,
                  const std::string& exp_q_high_str,
                  const std::string& exp_r_str) {

    uint256_t a_low, a_high, b, q_low, r, exp_q_low, exp_r;
    bn254fr_t q_high, exp_q_high;

    uint256_alloc(a_low);
    uint256_alloc(a_high);
    uint256_alloc(b);
    uint256_alloc(q_low);
    uint256_alloc(r);
    uint256_alloc(exp_q_low);
    uint256_alloc(exp_r);

    bn254fr_alloc(q_high);
    bn254fr_alloc(exp_q_high);

    uint256_set_str(a_low, a_low_str.c_str(), 10);
    uint256_set_str(a_high, a_high_str.c_str(), 10);
    uint256_set_str(b, b_str.c_str(), 10);
    uint256_set_str(exp_q_low, exp_q_low_str.c_str(), 10);
    uint256_set_str(exp_r, exp_r_str.c_str(), 10);
    bn254fr_set_str(exp_q_high, exp_q_high_str.c_str(), 10);

    uint512_idiv_normalized_checked(q_low, q_high, r, a_low, a_high, b);
    uint256_assert_equal(q_low, exp_q_low);
    bn254fr_assert_equal(q_high, exp_q_high);
    uint256_assert_equal(r, exp_r);

    uint256_free(a_low);
    uint256_free(a_high);
    uint256_free(b);
    uint256_free(q_low);
    uint256_free(r);
    uint256_free(exp_q_low);
    uint256_free(exp_r);

    bn254fr_free(q_high);
    bn254fr_free(exp_q_high);
}

void test_divide_qr() {
    do_test_divide_qr(
        "100", "0", "10",
        "10", "0", "0"
    );

    do_test_divide_qr(
        "123456789", "0", "100",
        "1234567", "0", "89"
    );

    do_test_divide_qr(
        "0", "1",
        "2",
        "57896044618658097711785492504343953926634992332820282019728792003956564819968", // 2^255
        "0",
        "0"
    );

    do_test_divide_qr(
        "5", "1", "10",
        "11579208923731619542357098500868790785326998466564056403945758400791312963994",
        "0",
        "1"
    );

    do_test_divide_qr(
        "1", "1",
        "1",
        "1",
        "1",
        "0"
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

void do_test_eq(const std::string& a_str,
                const std::string& b_str,
                bool exp_res) {

    uint256_t a, b;
    bn254fr_t res, exp;

    uint256_alloc(a);
    uint256_alloc(b);
    bn254fr_alloc(res);
    bn254fr_alloc(exp);

    uint256_set_str(a, a_str.c_str(), 10);
    uint256_set_str(b, b_str.c_str(), 10);
    bn254fr_set_u32(exp, exp_res ? 1U : 0U);

    uint256_eq_checked(res, a, b);
    bn254fr_assert_equal(res, exp);

    uint256_free(a);
    uint256_free(b);
    bn254fr_free(res);
    bn254fr_free(exp);
}

void test_eq() {
    do_test_eq("1", "1", true);
    do_test_eq("1", "0", false);
    do_test_eq("11579208923731619542357098500868790785326998466564056403945758400791312963994",
               "11579208923731619542357098500868790785326998466564056403945758400791312963994",
               true);
    do_test_eq("11579208923731619542357098500868790785326998466564056403945758400791312963994",
               "11579208923712312312390012380913096564056403945758400791312963994",
               false);
}

void do_test_inv(const std::string& a_str,
                 const std::string& m_str,
                 const std::string& exp_str) {

    uint256_t a, m, exp, res;
    uint256_alloc(a);
    uint256_alloc(m);
    uint256_alloc(exp);
    uint256_alloc(res);

    uint256_set_str(a, a_str.c_str(), 10);
    uint256_set_str(m, m_str.c_str(), 10);
    uint256_set_str(exp, exp_str.c_str(), 10);

    uint256_invmod_checked(res, a, m);
    uint256_assert_equal(res, exp);

    uint256_free(a);
    uint256_free(m);
    uint256_free(exp);
    uint256_free(res);
}

void test_inv() {
    do_test_inv("3", "11", "4");

    do_test_inv("1", "97", "1");

    do_test_inv("17", "97", "40");

    // inverse of 5 mod BN254 scalar field modulus
    do_test_inv(
        "5",
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        "8755297148735710088898562298102910035419345760166413737479281674630323398247"
    );

    // inverse of 3 mod spec256 (secp256k1 field prime)
    do_test_inv(
        "3",
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        "77194726158210796949047323339125271901891709519383269588403442094345440996225"
    );

    do_test_inv(
        "92083353579669972405495757776470670379717099030169638017457449866473924951844",
        "115792089210356248762697446949407573530086143415211086033018482518360559134033",
        "107144220426932500591649118614422298517760573469212118502069469584724027903412"
    );
}

void test_to_from_bits() {
    uint256_t x, y;
    bn254fr_t bits[256];

    uint256_alloc(x);
    uint256_alloc(y);
    for (size_t i = 0; i < 256; ++i) {
        bn254fr_alloc(bits[i]);
    }

    const char *str =
        "115792089210356248762697446949407573530086143415211086033018482518360559134033";
    uint256_set_str(x, str, 10);
    uint256_to_bits(bits, x);
    uint256_from_bits(y, bits);
    uint256_assert_equal(x, y);

    uint256_free(x);
    uint256_free(y);
    for (size_t i = 0; i < 256; ++i) {
        bn254fr_free(bits[i]);
    }
}

void test_uint256_mux() {
    uint256_t a, b, res1, res2;
    bn254fr_t cond1, cond2;

    uint256_alloc(a);
    uint256_alloc(b);
    uint256_alloc(res1);
    uint256_alloc(res2);
    bn254fr_alloc(cond1);
    bn254fr_alloc(cond2);

    uint256_set_str(a, "115792089210356248762697446949407573530086143415211086033018482518360559134033", 10);
    uint256_set_str(b, "21888242871839275222246405745257275088548364400416034343698204186575808495617", 10);
    bn254fr_set_u32(cond1, 1);
    bn254fr_set_u32(cond2, 0);

    uint256_mux(res1, cond1, a, b);
    uint256_mux(res2, cond2, a, b);
    uint256_assert_equal(res1, b);
    uint256_assert_equal(res2, a);

    uint256_free(a);
    uint256_free(b);
    uint256_free(res1);
    uint256_free(res2);
    bn254fr_free(cond1);
    bn254fr_free(cond2);
}

void do_test_uint512_mod(const std::string& a_low_str,
                         const std::string& a_high_str,
                         const std::string& m_str,
                         const std::string& exp_out_str) {

    uint256_t a_low, a_high, m, exp_out, out;

    uint256_alloc(a_low);
    uint256_alloc(a_high);
    uint256_alloc(m);
    uint256_alloc(exp_out);
    uint256_alloc(out);

    uint256_set_str(a_low, a_low_str.c_str(), 10);
    uint256_set_str(a_high, a_high_str.c_str(), 10);
    uint256_set_str(m, m_str.c_str(), 10);
    uint256_set_str(exp_out, exp_out_str.c_str(), 10);

    uint512_mod_checked(out, a_low, a_high, m);
    uint256_assert_equal(out, exp_out);

    uint256_free(a_low);
    uint256_free(a_high);
    uint256_free(m);
    uint256_free(exp_out);
    uint256_free(out);
}

void test_uint512_mod() {
    do_test_uint512_mod(
        "100",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935", // 2^256 - 1
        "115792089237316195423570985008687907853269984665640564039457584007913129639926", // 2^256 - 10
        "190"
    );
}

int main(int argc, char * argv[]) {
    test_ctor_dtor();
    test_set_u64_get_u64();
    test_set_words();
    test_set_str();
    test_set_bytes();
    test_to_bytes_little(false);
    test_to_bytes_little(true);
    test_to_bytes_big(false);
    test_to_bytes_big(true);
    test_set_bn254_checked();
    test_print();
    test_copy_checked();
    test_add_cc();
    test_sub_cc();
    test_mul_wide();
    test_divide_qr();
    test_eq();
    test_inv();
    test_to_from_bits();
    test_uint256_mux();
    test_uint512_mod();

    return 0;
}
