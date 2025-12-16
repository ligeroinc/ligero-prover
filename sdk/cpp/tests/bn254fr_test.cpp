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

#include <ligetron/bn254fr.h>
#include <ligetron/api.h>


void test_set_get_u32(uint32_t priv_x) {
    uint32_t pub_x = 10;

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_u32(pub_bn, pub_x);
    uint64_t pub_y = bn254fr_get_u64(pub_bn);
    assert_one(pub_y == 10);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_u32(priv_bn, priv_x);
    uint64_t priv_y = bn254fr_get_u64(priv_bn);
    assert_one(priv_y == priv_x);
    bn254fr_free(priv_bn);
}

void test_set_get_u64(uint64_t priv_x) {
    uint64_t pub_x = 20;

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_u32(pub_bn, pub_x);
    uint64_t pub_y = bn254fr_get_u64(pub_bn);
    assert_one(pub_y == 20);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_u32_checked(priv_bn, priv_x);
    uint64_t priv_y = bn254fr_get_u64(priv_bn);
    assert_one(priv_y == priv_x);
    bn254fr_free(priv_bn);
}

void test_set_get_u64_checked(uint64_t priv_x) {
    uint64_t pub_x = 20;

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_u64(pub_bn, pub_x);
    uint64_t pub_y = bn254fr_get_u64_checked(pub_bn);
    assert_one(pub_y == 20);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_u64_checked(priv_bn, priv_x);
    uint64_t priv_y = bn254fr_get_u64_checked(priv_bn);
    assert_one(priv_y == priv_x);
    bn254fr_free(priv_bn);
}

void test_to_bytes() {
    bn254fr_t x;

    unsigned char x_bytes[32];
    for (size_t i = 0; i < sizeof(x_bytes); ++i) {
        x_bytes[i] = 1;
    }

    bn254fr_alloc(x);
    bn254fr_set_str(x, "0x127788238591756923AF8211934512AABB");
    bn254fr_to_bytes(x_bytes, x, sizeof(x_bytes), -1);
    auto word_0 = *reinterpret_cast<uint64_t*>(&x_bytes[0]);
    auto word_1 = *reinterpret_cast<uint64_t*>(&x_bytes[8]);
    auto word_2 = *reinterpret_cast<uint64_t*>(&x_bytes[16]);
    auto word_3 = *reinterpret_cast<uint64_t*>(&x_bytes[24]);
    assert_one(word_0 == 0xAF8211934512AABBULL);
    assert_one(word_1 == 0x7788238591756923ULL);
    assert_one(word_2 == 0x12ULL);
    assert_one(word_3 == 0x0ULL);

    bn254fr_free(x);
}

void test_to_bytes_checked() {
    bn254fr_t x;

    unsigned char x_bytes[32];
    for (size_t i = 0; i < sizeof(x_bytes); ++i) {
        x_bytes[i] = 1;
    }

    bn254fr_alloc(x);
    bn254fr_set_str(x, "0x127788238591756923AF8211934512AABB");
    bn254fr_to_bytes_checked(x_bytes, x, sizeof(x_bytes), -1);
    auto word_0 = *reinterpret_cast<uint64_t*>(&x_bytes[0]);
    auto word_1 = *reinterpret_cast<uint64_t*>(&x_bytes[8]);
    auto word_2 = *reinterpret_cast<uint64_t*>(&x_bytes[16]);
    auto word_3 = *reinterpret_cast<uint64_t*>(&x_bytes[24]);
    assert_one(word_0 == 0xAF8211934512AABBULL);
    assert_one(word_1 == 0x7788238591756923ULL);
    assert_one(word_2 == 0x12ULL);
    assert_one(word_3 == 0x0ULL);

    bn254fr_free(x);
}

void test_set_bytes_checked() {
    bn254fr_t x, y;

    unsigned char x_bytes[32];
    *reinterpret_cast<uint64_t*>(&x_bytes[0]) = 0xAF8211934512AABBULL;
    *reinterpret_cast<uint64_t*>(&x_bytes[8]) = 0x7788238591756923ULL;
    *reinterpret_cast<uint64_t*>(&x_bytes[16]) = 0x12ULL;
    *reinterpret_cast<uint64_t*>(&x_bytes[24]) = 0x0ULL;

    bn254fr_alloc(x);
    bn254fr_set_bytes_checked(x, x_bytes, sizeof(x_bytes), -1);

    bn254fr_alloc(y);
    bn254fr_set_str(y, "0x127788238591756923AF8211934512AABB");
    bn254fr_assert_equal(x, y);

    bn254fr_free(x);
    bn254fr_free(y);
}

void test_assert_equal_u32(uint32_t priv_u32) {
    uint32_t pub_u32 = 20;

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_u32(pub_bn, pub_u32);
    bn254fr_assert_equal_u32(pub_bn, pub_u32);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_u32(priv_bn, priv_u32);
    bn254fr_assert_equal_u32(priv_bn, priv_u32);
    bn254fr_free(priv_bn);
}

void test_assert_equal_u64(uint32_t priv_u64) {
    uint64_t pub_u64 = 0xAB12332222ULL;

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_u64(pub_bn, pub_u64);
    bn254fr_assert_equal_u64(pub_bn, pub_u64);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_u64(priv_bn, priv_u64);
    bn254fr_assert_equal_u64(priv_bn, priv_u64);
    bn254fr_free(priv_bn);
}

void test_assert_equal_bytes(uint64_t priv_u64) {
    uint64_t pub_u64 = 0xA728D82287F823;
    auto pub_bytes = reinterpret_cast<unsigned char*>(&pub_u64);
    auto priv_bytes = reinterpret_cast<unsigned char*>(&priv_u64);

    bn254fr_t pub_bn;
    bn254fr_alloc(pub_bn);
    bn254fr_set_bytes(pub_bn, pub_bytes, sizeof(pub_bytes), -1);
    bn254fr_assert_equal_bytes(pub_bn, pub_bytes, sizeof(pub_bytes), -1);
    bn254fr_free(pub_bn);

    bn254fr_t priv_bn;
    bn254fr_alloc(priv_bn);
    bn254fr_set_bytes(priv_bn, priv_bytes, sizeof(priv_u64), -1);
    bn254fr_assert_equal_bytes(priv_bn, priv_bytes, sizeof(priv_u64), -1);
    bn254fr_free(priv_bn);
}

template <uint32_t Count>
void do_test_to_bits(uint64_t val, bool constrained) {
    // initializing bn254 for value
    bn254fr_t x;
    bn254fr_alloc(x);
    bn254fr_set_u64(x, val);

    // initializing bn254 for bits
    bn254fr_t bits[Count];
    for (size_t i = 0; i < Count; i++) {
        bn254fr_alloc(bits[i]);
    }

    // decomposing value into bits
    if (constrained) {
        bn254fr_to_bits_checked(bits, x, Count);
    } else {
        bn254fr_to_bits(bits, x, Count);
    }

    // checking bit values
    for (size_t i = 0; i < Count; i++) {
        uint64_t bit_val = (val >> i) & 0x1;
        bn254fr_t bit;
        bn254fr_alloc(bit);
        bn254fr_set_u64(bit, bit_val);
        bn254fr_assert_equal(bits[i], bit);
        bn254fr_free(bit);
    }

    // deallocating value and bits
    bn254fr_free(x);
    for (size_t i = 0; i < Count; i++) {
        bn254fr_free(bits[i]);
    }
}

template <uint32_t Count>
void do_test_from_bits(uint64_t val, bool constrained) {
    // initializing bn254 for result
    bn254fr_t res;
    bn254fr_alloc(res);

    // initializing bn254 for bits
    bn254fr_t bits[Count];
    for (size_t i = 0; i < Count; i++) {
        bn254fr_alloc(bits[i]);
        uint64_t bit_val = (val >> i) & 0x1;
        bn254fr_set_u64(bits[i], bit_val);
    }

    // composing value from bits
    if (constrained) {
        bn254fr_from_bits_checked(res, bits, Count);
    } else {
        bn254fr_from_bits(res, bits, Count);
    }

    // checking result value
    bn254fr_t expected;
    bn254fr_alloc(expected);
    bn254fr_set_u64(expected, val);
    bn254fr_assert_equal(res, expected);
    bn254fr_free(expected);

    // deallocating result value and bits
    bn254fr_free(res);
    for (size_t i = 0; i < Count; i++) {
        bn254fr_free(bits[i]);
    }
}

void test_to_bits() {
    do_test_to_bits<64>(0xF8334AA820F1D23, false);
}

void test_from_bits() {
    do_test_from_bits<64>(0xF8123AA820F1D23, false);
}

void test_to_bits_checked() {
    do_test_to_bits<64>(0xF8334AA820F1D23, true);
}

void test_from_bits_checked() {
    do_test_from_bits<64>(0xF8123AA820F1D23, true);
}

void test_mux() {
    bn254fr_t cond_0, cond_1, a, b, res_0, res_1;
    bn254fr_alloc(cond_0);
    bn254fr_alloc(cond_1);
    bn254fr_alloc(a);
    bn254fr_alloc(b);
    bn254fr_alloc(res_0);
    bn254fr_alloc(res_1);

    bn254fr_set_str(a, "72177213123123123");
    bn254fr_set_str(b, "2819237812312312312738123");
    bn254fr_set_u32(cond_1, 1);

    bn254fr_mux(res_0, cond_0, a, b);
    bn254fr_mux(res_1, cond_1, a, b);
    bn254fr_assert_equal(res_0, a);
    bn254fr_assert_equal(res_1, b);

    bn254fr_free(cond_0);
    bn254fr_free(cond_1);
    bn254fr_free(a);
    bn254fr_free(b);
    bn254fr_free(res_0);
    bn254fr_free(res_1);
}

void test_mux2() {
    bn254fr_t s0_0, s0_1, s1_0, s1_1;
    bn254fr_t a0, a1, a2, a3, res_0_0, res_0_1, res_1_0, res_1_1;
    bn254fr_alloc(s0_0);
    bn254fr_alloc(s0_1);
    bn254fr_alloc(s1_0);
    bn254fr_alloc(s1_1);
    bn254fr_alloc(a0);
    bn254fr_alloc(a1);
    bn254fr_alloc(a2);
    bn254fr_alloc(a3);
    bn254fr_alloc(res_0_0);
    bn254fr_alloc(res_0_1);
    bn254fr_alloc(res_1_0);
    bn254fr_alloc(res_1_1);

    bn254fr_set_str(a0, "72177213123123123");
    bn254fr_set_str(a1, "2819237812312312312738123");
    bn254fr_set_str(a2, "882381231231");
    bn254fr_set_str(a3, "69912812737727232");
    bn254fr_set_u32(s0_1, 1);
    bn254fr_set_u32(s1_1, 1);

    bn254fr_mux2(res_0_0, s0_0, s1_0, a0, a1, a2, a3);
    bn254fr_mux2(res_0_1, s0_0, s1_1, a0, a1, a2, a3);
    bn254fr_mux2(res_1_0, s0_1, s1_0, a0, a1, a2, a3);
    bn254fr_mux2(res_1_1, s0_1, s1_1, a0, a1, a2, a3);

    bn254fr_assert_equal(res_0_0, a0);
    bn254fr_assert_equal(res_0_1, a2);
    bn254fr_assert_equal(res_1_0, a1);
    bn254fr_assert_equal(res_1_1, a3);

    bn254fr_free(s0_0);
    bn254fr_free(s0_1);
    bn254fr_free(s1_0);
    bn254fr_free(s1_1);
    bn254fr_free(a0);
    bn254fr_free(a1);
    bn254fr_free(a2);
    bn254fr_free(a3);
    bn254fr_free(res_0_0);
    bn254fr_free(res_0_1);
    bn254fr_free(res_1_0);
    bn254fr_free(res_1_1);

}

int main(int argc, char * argv[]) {
    uint32_t u32_priv = static_cast<uint32_t>(*reinterpret_cast<uint64_t*>(argv[1]));
    uint32_t u64_priv = *reinterpret_cast<uint64_t*>(argv[1]);

    test_to_bits();
    test_from_bits();
    test_to_bits_checked();
    test_from_bits_checked();
    test_set_get_u32(u32_priv);
    test_set_get_u64(u64_priv);
    test_set_get_u64_checked(u64_priv);
    test_to_bytes();
    test_to_bytes_checked();
    test_set_bytes_checked();
    test_assert_equal_u32(u32_priv);
    test_assert_equal_u64(u64_priv);
    test_assert_equal_bytes(u64_priv);
    test_mux();
    test_mux2();

    return 0;
}
