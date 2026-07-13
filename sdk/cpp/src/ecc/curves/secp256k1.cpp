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

#include <ligetron/ecc/curves/secp256k1.hpp>

namespace {

constexpr size_t generator_table_bit_width      = 8;
constexpr size_t generator_table_window_count   = 32;
constexpr size_t generator_table_window_entries = 1u << generator_table_bit_width;
constexpr size_t generator_table_total_entries  = 8192;

const char* generator_precomp[generator_table_total_entries][2] = {
    #include "secp256k1_precomp.inc"
};

} // namespace

namespace ligetron::ecc::curves {

secp256k1::secp256k1()
    : secp256k1::base_type(
          secp256k1::base_field_type{0u},
          secp256k1::base_field_type{7u},
          secp256k1::point_type{
              secp256k1::base_field_type{
                  "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"},
              secp256k1::base_field_type{
                  "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"}})
{
    for (size_t i = 0; i < generator_table_total_entries; i++) {
        g_precomp_.emplace_back(secp256k1::base_field_type{generator_precomp[i][0]},
                                secp256k1::base_field_type{generator_precomp[i][1]});
    }
}

ECCCurveType secp256k1::curve_type() const noexcept {
    return ECCCurveType_Secp256k1;
}

std::span<const std::byte> secp256k1::order_bytes() const noexcept {
    static constexpr unsigned char order_bytes[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
    };
    return std::as_bytes(std::span{order_bytes});
}

std::span<const std::byte> secp256k1::base_field_bytes() const noexcept {
    static constexpr unsigned char base_bytes[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
    };
    return std::as_bytes(std::span{base_bytes});
}

secp256k1::point_type secp256k1::scalar_mul_generator(const secp256k1::scalar_field_type& s) const {
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

