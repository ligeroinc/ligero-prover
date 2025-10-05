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

int main() {
    test_to_bits();
    test_from_bits();
    test_to_bits_checked();
    test_from_bits_checked();
    return 0;
}
