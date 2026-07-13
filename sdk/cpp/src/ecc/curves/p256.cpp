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

#include <ligetron/ecc/curves/p256.hpp>

namespace {

constexpr size_t generator_table_bit_width      = 8;
constexpr size_t generator_table_window_count   = 32;
constexpr size_t generator_table_window_entries = 1u << generator_table_bit_width;
constexpr size_t generator_table_total_entries  = 8192;

const char* generator_precomp[generator_table_total_entries][2] = {
    #include "p256_precomp.inc"
};

} // namespace

namespace ligetron::ecc::curves {

p256::p256()
    : p256::base_type(
          p256::base_field_type{"0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"},
          p256::base_field_type{"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"},
          p256::point_type{
              p256::base_field_type{
                  "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"},
              p256::base_field_type{
                  "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}})
{
    for (size_t i = 0; i < generator_table_total_entries; i++) {
        g_precomp_.emplace_back(p256::base_field_type{generator_precomp[i][0]},
                                p256::base_field_type{generator_precomp[i][1]});
    }
}

ECCCurveType p256::curve_type() const noexcept {
    return ECCCurveType_P256;
} 

std::span<const std::byte> p256::order_bytes() const noexcept {
    static constexpr unsigned char order_bytes[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    };
    return std::as_bytes(std::span{order_bytes});
}

std::span<const std::byte> p256::base_field_bytes() const noexcept {
    static constexpr unsigned char base_bytes[32] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    return std::as_bytes(std::span{base_bytes});
}

p256::point_type p256::scalar_mul_generator(const p256::scalar_field_type& s) const {
    bn254fr_class bits[256];
    s.to_bits(bits);

    auto acc = infinity();
    for (size_t w = 0; w < generator_table_window_count; w++) {
        const size_t i    = w * generator_table_bit_width;
        const size_t base = w * generator_table_window_entries;

        auto q = point_select(generator_table_bit_width, bits + i, g_precomp_.data() + base);
        acc = point_add(acc, q);
    }
    return acc;
}

} // namespace ligetron::ecc::curves
