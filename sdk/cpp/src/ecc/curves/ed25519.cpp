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

#include <ligetron/ecc/curves/ed25519.hpp>

namespace {

constexpr size_t generator_table_bit_width      = 8;
constexpr size_t generator_table_window_count   = 32;
constexpr size_t generator_table_window_entries = 1u << generator_table_bit_width;
constexpr size_t generator_table_total_entries  = 8192;

const char* generator_precomp[generator_table_total_entries][2] = {
    #include "ed25519_precomp.inc"
};

} // namespace

namespace ligetron::ecc::curves {

ed25519::ed25519()
    : ed25519::base_type(
          ed25519::base_field_type{"0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"},
          ed25519::point_type{
              ed25519::base_field_type{
                  "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"},
              ed25519::base_field_type{
                  "0x6666666666666666666666666666666666666666666666666666666666666658"}})
{
    for (size_t i = 0; i < generator_table_total_entries; i++) {
        g_precomp_.emplace_back(ed25519::base_field_type{generator_precomp[i][0]},
                                ed25519::base_field_type{generator_precomp[i][1]});
    }
}

ECCCurveType ed25519::curve_type() const noexcept {
    return ECCCurveType_Ed25519;
} 

std::span<const std::byte> ed25519::order_bytes() const noexcept {
    static constexpr unsigned char order_bytes[32] = {
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
        0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
    };
    return std::as_bytes(std::span{order_bytes});
}

std::span<const std::byte> ed25519::base_field_bytes() const noexcept {
    static constexpr unsigned char base_bytes[32] = {
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
    };
    return std::as_bytes(std::span{base_bytes});
}

ed25519::point_type ed25519::scalar_mul_generator(const ed25519::scalar_field_type& s) const {
    bn254fr_class bits[256]{};
    s.to_bits(bits);

    auto acc = point_select(generator_table_bit_width, bits, g_precomp_.data());
    for (size_t w = 1; w < generator_table_window_count; w++) {
        const size_t i    = w * generator_table_bit_width;
        const size_t base = w * generator_table_window_entries;

        auto q = point_select(generator_table_bit_width, bits + i, g_precomp_.data() + base);
        acc = point_add(acc, q);
    }
    return acc;
}

} // namespace ligetron::ecc::curves

