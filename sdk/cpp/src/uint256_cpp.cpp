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

/*
 * uint256_cpp.cpp
 *
 * C++ API implementation for uint256 operations.
 *
 */

#include <ligetron/uint256_cpp.h>


namespace ligetron {


uint256::uint256() {
    uint256_alloc(handle_);
}

uint256::uint256(const bn254fr_t val):
uint256{} {
    uint256_set_bn254_checked(data(), val);
}

uint256::uint256(const bn254fr_class &val):
uint256{} {
    uint256_set_bn254_checked(data(), val.data());
}

uint256::uint256(uint64_t val):
uint256{} {
    set_u64(val);
}

uint256::uint256(const char *str, int base):
uint256{} {
    uint256_set_str(handle_, str, base);
}

uint256::uint256(const unsigned char *bytes, uint32_t len, int order):
uint256{} {
    if (order == -1) {
        set_bytes_little_unchecked(bytes, len);
    } else {
        set_bytes_big_unchecked(bytes, len);
    }
}

uint256::~uint256() {
    uint256_free(handle_);
}

uint256::uint256(const uint256 &other):
uint256{} {
    uint256_copy_checked(data(), other.data());
}

uint256::uint256(uint256 &&other):
uint256{} {
    move(std::move(other));
}

uint256::uint256(const uint256_t &ui):
uint256{} {
    uint256_copy_checked(data(), ui);
}

uint256 &uint256::operator=(const uint256 &other) {
    realloc();
    copy(other);
    return *this;
}

uint256 &uint256::operator=(uint256 &&other) {
    swap(*this, other);
    return *this;
}

void uint256::realloc() {
    uint256_free(data());
    uint256_alloc(data());
}

void uint256::copy(const uint256 &other) {
    uint256_copy_checked(data(), other.data());
}

void uint256::move(uint256 &&other) {
    swap(*this, other);
}

void swap(uint256 &first, uint256 &second) {
    __uint256 tmp = first.handle_[0];
    first.handle_[0] = second.handle_[0];
    second.handle_[0] = tmp;
}

/// Adds equality constraints for two uint256 values
void assert_equal(const uint256 &x, const uint256 &y) {
    uint256_assert_equal(x.data(), y.data());
}

void uint256::print() const {
    uint256_print(data());
}

__uint256 *uint256::data() {
    return handle_;
}

const __uint256 *uint256::data() const {
    return handle_;
}

void uint256::set_words(const bn254fr_class *words) {
    bn254fr_t words_handles[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words_handles[i]);
        bn254fr_copy(words_handles[i], words[i].data());
        bn254fr_assert_equal(words_handles[i], words[i].data());
    }

    uint256_set_words_checked(data(), words_handles);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words_handles[i]);
    }
}

void uint256::get_words(bn254fr_class *words) const {
    bn254fr_t words_copies[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words_copies[i]);
    }

    uint256_get_words_checked(words_copies, data());

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        words[i] = words_copies[i];
        bn254fr_assert_equal(words[i].data(), words_copies[i]);
        bn254fr_free(words_copies[i]);
    }
}

void uint256::set_bytes_little(const unsigned char *bytes, uint32_t sz) {
    uint256_set_bytes_little_checked(data(), bytes, sz);
}

void uint256::set_bytes_big(const unsigned char *bytes, uint32_t sz) {
    uint256_set_bytes_big_checked(data(), bytes, sz);
}

void uint256::set_bytes_little_unchecked(const unsigned char *bytes,
                                         uint32_t sz) {
    uint256_set_bytes_little(data(), bytes, sz);
}

void uint256::set_bytes_big_unchecked(const unsigned char *bytes, uint32_t sz) {
    uint256_set_bytes_big(data(), bytes, sz);
}

void uint256::to_bytes_little(unsigned char *bytes) const {
    uint256_to_bytes_little_checked(bytes, const_cast<__uint256*>(data()));
}

void uint256::to_bytes_big(unsigned char *bytes) const {
    uint256_to_bytes_big_checked(bytes, const_cast<__uint256*>(data()));
}

void uint256::to_bytes_little_unchecked(unsigned char *bytes) const {
    uint256_to_bytes_little(bytes, const_cast<__uint256*>((data())));
}

void uint256::to_bytes_big_unchecked(unsigned char *bytes) const {
    uint256_to_bytes_big(bytes, const_cast<__uint256*>((data())));
}

void uint256::set_str(const char *str, int base) {
    uint256_set_str(data(), str, base);
}

void uint256::set_bn254(const bn254fr_class &bn254) {
    uint256_set_bn254_checked(data(), bn254.data());
}

void uint256::set_u64(uint64_t x) {
    bn254fr_t bn254;
    bn254fr_alloc(bn254);
    bn254fr_set_u64_checked(bn254, x);
    uint256_set_bn254_checked(data(), bn254);
    bn254fr_free(bn254);
}

void uint256::set_u64_unchecked(uint64_t x) {
    uint256_set_u64(data(), x);
}

uint64_t uint256::get_u64() const {
    bn254fr_t words[UINT256_NLIMBS];
    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_alloc(words[i]);
    }

    uint256_get_words_checked(words, data());

    bn254fr_t zero;
    bn254fr_alloc(zero);

    for (size_t i = 1; i < UINT256_NLIMBS; ++i) {
        bn254fr_assert_equal(words[i], zero);
    }

    auto res = bn254fr_get_u64_checked(words[0]);
    
    bn254fr_free(zero);

    for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
        bn254fr_free(words[i]);
    }

    return res;
}

uint64_t uint256::get_u64_unchecked() const {
    return uint256_get_u64(const_cast<__uint256*>(data()));
}

void uint256::set_u32(uint32_t x) {
    bn254fr_t bn254;
    bn254fr_alloc(bn254);
    bn254fr_set_u32_checked(bn254, x);
    uint256_set_bn254_checked(data(), bn254);
    bn254fr_free(bn254);
}

void uint256::from_bits(const bn254fr_class *bits) {
    bn254fr_t bits_copies[256];
    for (size_t i = 0; i < 256; ++i) {
        bn254fr_alloc(bits_copies[i]);
    }

    for (size_t i = 0; i < 256; ++i) {
        bn254fr_copy(bits_copies[i], bits[i].data());
        bn254fr_assert_equal(bits_copies[i], bits[i].data());
    }

    uint256_from_bits(data(), bits_copies);

    for (size_t i = 0; i < 256; ++i) {
        bn254fr_free(bits_copies[i]);
    }
}

void uint256::to_bits(bn254fr_class *out) const {
    bn254fr_t bits[256];
    for (size_t i = 0; i < 256; ++i) {
        bn254fr_alloc(bits[i]);
    }

    uint256_to_bits(bits, data());

    for (size_t i = 0; i < 256; ++i) {
        out[i] = bits[i];
        bn254fr_assert_equal(out[i].data(), bits[i]);
    }

    for (size_t i = 0; i < 256; ++i) {
        bn254fr_free(bits[i]);
    }
}

void uint256_wide::divide_qr_normalized(uint256 &q_low,
                                        bn254fr_class &q_high,
                                        uint256 &r,
                                        const uint256 &b) {
    uint512_idiv_normalized_checked(q_low.data(),
                                    const_cast<__bn254fr*>(q_high.data()),
                                    r.data(),
                                    lo.data(),
                                    hi.data(),
                                    b.data());
}

void uint256_wide::mod(uint256 &out, const uint256 &m) {
    uint512_mod_checked(out.data(), lo.data(), hi.data(), m.data());
}

uint256 uint256_wide::operator%(const uint256 &m) {
    uint256 res;
    mod(res, m);
    return res;
}

void add(uint256_cc &out, const uint256 &a, const uint256 &b) {
    uint256_add_checked(out.val.data(),
                        const_cast<__bn254fr*>(out.carry.data()),
                        a.data(),
                        b.data());
}

uint256_cc add_cc(const uint256 &a, const uint256 &b) {
    uint256_cc res;
    add(res, a, b);
    return res;
}

uint256 operator+(const uint256 &a, const uint256 &b) {
    return add_cc(a, b).val;
}

void sub_cc(uint256_cc &out, const uint256 &a, const uint256 &b) {
    uint256_sub_checked(out.val.data(),
                        const_cast<__bn254fr*>(out.carry.data()),
                        a.data(),
                        b.data());
}

uint256_cc sub_cc(const uint256 &a, const uint256 &b) {
    uint256_cc res;
    bn254fr_class underflow;
    sub_cc(res, a, b);
    return res;
}

uint256 operator-(const uint256 &a, const uint256 &b) {
    return sub_cc(a, b).val;
}

void mul_wide(uint256_wide &out, const uint256 &a, const uint256 &b) {
    uint256_mul_checked(out.lo.data(), out.hi.data(), a.data(), b.data());
}

uint256_wide mul_wide(const uint256 &a, const uint256 &b) {
    uint256_wide res;
    mul_wide(res, a, b);
    return res;
}

uint256 mul_lo(const uint256 &a, const uint256 &b) {
    return mul_wide(a, b).lo;
}

uint256 mul_hi(const uint256 &a, const uint256 &b) {
    return mul_wide(a, b).hi;
}

uint256 operator*(const uint256 &a, const uint256 &b) {
    return mul_lo(a, b);
}

void invmod(uint256 &out, const uint256 &x, const uint256 &m) {
    uint256_invmod_checked(out.data(), x.data(), m.data());
}

uint256 invmod(const uint256 &x, const uint256 &m) {
    uint256 res;
    uint256_invmod_checked(res.data(), x.data(), m.data());
    return res;
}

void eq(bn254fr_class &out, const uint256 &x, const uint256 &y) {
    uint256_eq_checked(const_cast<__bn254fr*>(out.data()),
                       x.data(),
                       y.data());
}

bn254fr_class operator==(const uint256 &x, const uint256 &y) {
    bn254fr_class res;
    eq(res, x, y);
    return res;
}

void eqz(bn254fr_class &out, const uint256 &x) {
    static uint256 zero;
    eq(out, x, zero);
}

bn254fr_class eqz(const uint256 &x) {
    bn254fr_class res;
    eqz(res, x);
    return res;
}

void mux(uint256 &out,
         const bn254fr_class &cond,
         const uint256 &a,
         const uint256 &b) {
    uint256_mux(out.data(), cond.data(), a.data(), b.data());
}

uint256 mux(const bn254fr_class &cond, const uint256 &a, const uint256 &b) {
    uint256 res;
    mux(res, cond, a, b);
    return res;
}


}
