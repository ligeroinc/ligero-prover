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

#pragma once

#include <array>
#include <algorithm>
#include <cstdint>
#include <type_traits>

#include <gmpxx.h>

namespace ligero {
namespace webgpu {

template <uint32_t NumLimbs>
struct device_bignum {
    using limb_type = uint32_t;
    static constexpr uint32_t num_limbs = NumLimbs;
    static constexpr uint32_t limb_size = sizeof(limb_type);
    static constexpr uint32_t limb_bits = std::numeric_limits<limb_type>::digits;
    static constexpr uint32_t num_bytes = num_limbs * limb_size;
    static constexpr uint32_t num_bits = num_limbs * limb_bits;

    device_bignum() : limbs_() { }

    template <typename I>
    requires std::is_integral_v<I>
    explicit device_bignum(I i) : limbs_() {
        set_u64(static_cast<uint64_t>(i));
    }

    explicit device_bignum(const mpz_class& val) : limbs_() {
        set_mpz(val);
    }

    template <typename I>
    requires std::is_integral_v<I>
    device_bignum& operator=(I i) {
        set_u64(static_cast<uint64_t>(i));
        return *this;
    }

    device_bignum& operator=(const mpz_class& val) {
        set_mpz(val);
        return *this;
    }

    uint32_t operator[](size_t i) const {
        return limbs_[i];
    }

    void clear() {
        std::fill_n(limbs_.begin(), num_limbs, 0u);
    }

    void set_u64(uint64_t u) {
        clear();
        limbs_[0] = u & 0xFFFFFFFFu;
        limbs_[1] = u >> 32;
    }

    void set_mpz(const mpz_class& val) {
        std::fill_n(limbs_.begin(), num_limbs, 0u);
        size_t words;
        mpz_export(limbs_.data(), &words, -1, sizeof(uint32_t), -1, 0, val.get_mpz_t());
    }

    mpz_class to_mpz() const {
        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), num_limbs, -1, sizeof(uint32_t), -1, 0, limbs_.data());
        return tmp;
    }

private:
    std::array<uint32_t, num_limbs> limbs_;
};

extern template struct device_bignum<4>;
extern template struct device_bignum<8>;

using device_uint128_t = device_bignum<4>;
using device_uint256_t = device_bignum<8>;

}  // namespace webgpu
}  // namespace ligero

