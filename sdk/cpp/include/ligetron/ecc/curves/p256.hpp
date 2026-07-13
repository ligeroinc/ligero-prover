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
#include <ligetron/ecc/curves/weierstrass.hpp>
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/prime_field_uint256.h>

namespace ligetron::ecc::curves {

/// P256 base field
struct p256_base_field : public ff::prime_field_uint256<p256_base_field> {
    static storage_type& modulus() {
        static storage_type m{"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"};
        return m;
    }
};

/// P256 scalar (order) field
struct p256_scalar_field : public ff::prime_field_uint256<p256_scalar_field> {
    static storage_type& modulus() {
        static storage_type m{"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"};
        return m;
    }
};

struct p256 : short_weierstrass<ff::field_element<p256_base_field>,
                                ff::field_element<p256_scalar_field>>
{
    using base_type = short_weierstrass<ff::field_element<p256_base_field>,
                                        ff::field_element<p256_scalar_field>>;
    using typename base_type::base_field_type;
    using typename base_type::scalar_field_type;
    using typename base_type::point_type;
    
    static constexpr size_t num_base_field_bytes = ff::field_element<p256_base_field>::num_rounded_bits / 8;
    
    p256();

    ECCCurveType curve_type() const noexcept override final;
    std::span<const std::byte> order_bytes() const noexcept override final;
    std::span<const std::byte> base_field_bytes() const noexcept override final;
    point_type scalar_mul_generator(const scalar_field_type& s) const override final;

private:
    std::vector<point_type> g_precomp_;
};

} // namespace ligetron::ecc::curves
