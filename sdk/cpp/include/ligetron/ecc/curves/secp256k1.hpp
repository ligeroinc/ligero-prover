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

#pragma once

#include <vector>
#include <ligetron/api.h>
#include <ligetron/ecc/curves/weierstrass.hpp>
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/prime_field_uint256.h>

namespace ligetron::ecc::curves {

/// Secp256k1 base field
struct secp256k1_base_field : public ff::prime_field_uint256<secp256k1_base_field> {
    static storage_type& modulus() {
        static storage_type m{"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"};
        return m;
    }
};

/// Secp256k1 scalar (order) field
struct secp256k1_scalar_field : public ff::prime_field_uint256<secp256k1_scalar_field> {
    static storage_type& modulus() {
        static storage_type m{"0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"};
        return m;
    }
};

struct secp256k1 : short_weierstrass<ff::field_element<secp256k1_base_field>,
                                     ff::field_element<secp256k1_scalar_field>>
{
    using base_type = short_weierstrass<ff::field_element<secp256k1_base_field>,
                                        ff::field_element<secp256k1_scalar_field>>;
    secp256k1();

    ECCCurveType curve_type() const noexcept override final;
    std::span<const std::byte> order_bytes() const noexcept override final;
    std::span<const std::byte> base_field_bytes() const noexcept override final;
    point_type scalar_mul_generator(const scalar_field_type& s) const override final;
    
private:
    std::vector<point_type> g_precomp_;
};

} // namespace ligetron::ecc::curves
