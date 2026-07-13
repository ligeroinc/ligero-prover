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
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/prime_field_uint256.h>
#include <ligetron/ecc/curves/twisted_edwards.hpp>

namespace ligetron::ecc::curves {

/// Ed25519 base field
struct ed25519_base_field : public ff::prime_field_uint256<ed25519_base_field> {
    static storage_type& modulus() {
        static storage_type m{"0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"};
        return m;
    }
};

/// Ed25519 scalar (order) field
struct ed25519_scalar_field : public ff::prime_field_uint256<ed25519_scalar_field> {
    static storage_type& modulus() {
        static storage_type m{"0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"};
        return m;
    }
};

struct ed25519 : am1_twisted_edwards<ff::field_element<ed25519_base_field>,
                                     ff::field_element<ed25519_scalar_field>>
{
    using base_type = am1_twisted_edwards<ff::field_element<ed25519_base_field>,
                                        ff::field_element<ed25519_scalar_field>>;
    using typename base_type::base_field_type;
    using typename base_type::scalar_field_type;
    using typename base_type::point_type;
    
    static constexpr size_t num_base_field_bytes = ff::field_element<ed25519_base_field>::num_rounded_bits / 8;
    
    ed25519();

    ECCCurveType curve_type() const noexcept override final;
    std::span<const std::byte> order_bytes() const noexcept override final;
    std::span<const std::byte> base_field_bytes() const noexcept override final;
    point_type scalar_mul_generator(const scalar_field_type& s) const override final;

private:
    std::vector<point_type> g_precomp_;
};

} // namespace ligetron::ecc::curves
