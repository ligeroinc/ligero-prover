// tests/util/test_mpz_get.cpp
#define BOOST_TEST_MODULE MPZ_Get_Tests
#include <boost/test/included/unit_test.hpp>
#include <gmp.h>
#include <gmpxx.h>
#include <util/mpz_get.hpp>
#include <cstdint>

using namespace ligero;

// ============================================================================
// Test Suite: mpz_get_u64
// ============================================================================

BOOST_AUTO_TEST_SUITE(MPZ_Get_U64_Tests)

BOOST_AUTO_TEST_CASE(zero_value) {
    mpz_class val(0);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0ULL);
}

BOOST_AUTO_TEST_CASE(small_value_fits_in_32_bits) {
    mpz_class val(0x12345678);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0x12345678ULL);
}

BOOST_AUTO_TEST_CASE(value_needs_full_64_bits) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "357c83864f2833cb", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0x357c83864f2833cbULL);
}

BOOST_AUTO_TEST_CASE(upper_32_bits_only) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "deadbeef00000000", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0xdeadbeef00000000ULL);
}

BOOST_AUTO_TEST_CASE(lower_32_bits_only) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "00000000cafebabe", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0x00000000cafebabeULL);
}

BOOST_AUTO_TEST_CASE(max_uint64) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "ffffffffffffffff", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0xffffffffffffffffULL);
}

BOOST_AUTO_TEST_CASE(one) {
    mpz_class val(1);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 1ULL);
}

BOOST_AUTO_TEST_CASE(power_of_two_boundaries) {
    // 2^32 - 1 (max 32-bit)
    mpz_class val1;
    mpz_set_str(val1.get_mpz_t(), "ffffffff", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val1), 0xffffffffULL);

    // 2^32 (first 33-bit value)
    mpz_class val2;
    mpz_set_str(val2.get_mpz_t(), "100000000", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val2), 0x100000000ULL);

    // 2^63
    mpz_class val3;
    mpz_set_str(val3.get_mpz_t(), "8000000000000000", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val3), 0x8000000000000000ULL);
}

BOOST_AUTO_TEST_CASE(sha512_regression_values) {
    // These are actual values from the SHA512 bug
    mpz_class state0;
    mpz_set_str(state0.get_mpz_t(), "357c83864f2833cb", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(state0), 0x357c83864f2833cbULL);

    // Another SHA512 state value
    mpz_class state1;
    mpz_set_str(state1.get_mpz_t(), "6a09e667f3bcc908", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(state1), 0x6a09e667f3bcc908ULL);
}

BOOST_AUTO_TEST_CASE(value_larger_than_64_bits_returns_lower_64) {
    // Values larger than 64 bits should return lower 64 bits
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "123456789abcdef0fedcba9876543210", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0xfedcba9876543210ULL);
}

BOOST_AUTO_TEST_CASE(mpz_t_variant) {
    mpz_t val;
    mpz_init(val);
    mpz_set_str(val, "357c83864f2833cb", 16);
    BOOST_CHECK_EQUAL(mpz_get_u64(val), 0x357c83864f2833cbULL);
    mpz_clear(val);
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// Test Suite: mpz_get_u32
// ============================================================================

BOOST_AUTO_TEST_SUITE(MPZ_Get_U32_Tests)

BOOST_AUTO_TEST_CASE(zero_value) {
    mpz_class val(0);
    BOOST_CHECK_EQUAL(mpz_get_u32(val), 0U);
}

BOOST_AUTO_TEST_CASE(small_value) {
    mpz_class val(0x12345678);
    BOOST_CHECK_EQUAL(mpz_get_u32(val), 0x12345678U);
}

BOOST_AUTO_TEST_CASE(max_uint32) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "ffffffff", 16);
    BOOST_CHECK_EQUAL(mpz_get_u32(val), 0xffffffffU);
}

BOOST_AUTO_TEST_CASE(value_larger_than_32_bits_truncates) {
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "123456789abcdef0", 16);
    BOOST_CHECK_EQUAL(mpz_get_u32(val), 0x9abcdef0U);
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// Test Suite: Platform Consistency
// ============================================================================

BOOST_AUTO_TEST_SUITE(Platform_Consistency_Tests)

BOOST_AUTO_TEST_CASE(sizeof_unsigned_long_awareness) {
    // Document what platform we're on
    BOOST_TEST_MESSAGE("sizeof(unsigned long) = " << sizeof(unsigned long));

#ifdef __EMSCRIPTEN__
    BOOST_TEST_MESSAGE("Platform: WASM/Emscripten");
    // On WASM, unsigned long should be 4 bytes
    BOOST_CHECK_EQUAL(sizeof(unsigned long), 4);
#else
    BOOST_TEST_MESSAGE("Platform: Native");
    // On most modern 64-bit platforms, it's 8 bytes
    // (though this can vary - we're just documenting the expectation)
#endif
}

BOOST_AUTO_TEST_CASE(mpz_get_u64_works_regardless_of_platform) {
    // This test ensures mpz_get_u64 works correctly
    // whether unsigned long is 32 or 64 bits

    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "357c83864f2833cb", 16);

    // mpz_get_u64 should ALWAYS return the full 64-bit value
    uint64_t result = mpz_get_u64(val);
    BOOST_CHECK_EQUAL(result, 0x357c83864f2833cbULL);

    // In contrast, mpz_get_ui() would truncate on 32-bit platforms
    unsigned long ui_result = mpz_get_ui(val.get_mpz_t());

    if (sizeof(unsigned long) == 4) {
        // On 32-bit platforms, this would be truncated
        BOOST_CHECK_EQUAL(ui_result, 0x4f2833cbUL);
        BOOST_CHECK_NE(static_cast<uint64_t>(ui_result), result);
    } else if (sizeof(unsigned long) == 8) {
        // On 64-bit platforms, they should match
        BOOST_CHECK_EQUAL(ui_result, 0x357c83864f2833cbUL);
        BOOST_CHECK_EQUAL(static_cast<uint64_t>(ui_result), result);
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ============================================================================
// Test Suite: Regression Tests for ED25519 Bug
// ============================================================================

BOOST_AUTO_TEST_SUITE(ED25519_Bug_Regression_Tests)

BOOST_AUTO_TEST_CASE(sha512_state_values) {
    // These are the actual SHA512 initial state values
    struct TestCase {
        const char* hex;
        uint64_t expected;
    };

    TestCase cases[] = {
        {"6a09e667f3bcc908", 0x6a09e667f3bcc908ULL},
        {"bb67ae8584caa73b", 0xbb67ae8584caa73bULL},
        {"3c6ef372fe94f82b", 0x3c6ef372fe94f82bULL},
        {"a54ff53a5f1d36f1", 0xa54ff53a5f1d36f1ULL},
        {"510e527fade682d1", 0x510e527fade682d1ULL},
        {"9b05688c2b3e6c1f", 0x9b05688c2b3e6c1fULL},
        {"1f83d9abfb41bd6b", 0x1f83d9abfb41bd6bULL},
        {"5be0cd19137e2179", 0x5be0cd19137e2179ULL},
    };

    for (const auto& tc : cases) {
        mpz_class val;
        mpz_set_str(val.get_mpz_t(), tc.hex, 16);
        BOOST_CHECK_EQUAL(mpz_get_u64(val), tc.expected);
    }
}

BOOST_AUTO_TEST_CASE(reproduce_original_bug) {
    // This reproduces the exact bug scenario
    mpz_class val;
    mpz_set_str(val.get_mpz_t(), "357c83864f2833cb", 16);

    // The OLD buggy way (would fail on WASM):
    uint64_t buggy_result = static_cast<uint64_t>(mpz_get_ui(val.get_mpz_t()));

    // The CORRECT way:
    uint64_t correct_result = mpz_get_u64(val);

    BOOST_CHECK_EQUAL(correct_result, 0x357c83864f2833cbULL);

    // On 32-bit platforms (WASM), these would differ
    if (sizeof(unsigned long) == 4) {
        BOOST_CHECK_EQUAL(buggy_result, 0x4f2833cbULL);  // Truncated!
        BOOST_CHECK_NE(buggy_result, correct_result);
    } else {
        // On 64-bit platforms, both should work
        BOOST_CHECK_EQUAL(buggy_result, correct_result);
    }
}

BOOST_AUTO_TEST_SUITE_END()
