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
 * P-256 curve definition
 */

#ifndef __LIGETRON_EC_DETAIL_P256_HPP__
#define __LIGETRON_EC_DETAIL_P256_HPP__

#include "detail/concepts.hpp"
#include "detail/elliptic_curve.hpp"
#include "detail/weierstrass.hpp"
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/prime_field_uint256.h>


namespace ligetron::ec {


/// P256 base field
struct p256_base_field: public ff::prime_field_uint256<p256_base_field> {
    static storage_type &modulus() {
        static storage_type m {
            "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
        };
        return m;
    }
};


/// P256 scalar (order) field
struct p256_scalar_field: public ff::prime_field_uint256<p256_scalar_field> {
    static storage_type &modulus() {
        static storage_type m {
            "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
        };
        return m;
    }
};


struct p256_curve_def {
    using base_field_element = ff::field_element<p256_base_field>;
    using scalar_field_element = ff::field_element<p256_scalar_field>;
    
    /// Curve a cosntant
    static base_field_element &coeff_a() {
        static base_field_element res {
            "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
        };

        return res;
    }

    /// Curve b cosntant
    static base_field_element &coeff_b() {
        static base_field_element res {
            "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
        };

        return res;
    }


    /// Curve generator point x coordinate
    static base_field_element &generator_x() {
        static base_field_element res {
            "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        };

        return res;
    }

    /// Curve generator point y coordinate
    static base_field_element &generator_y() {
        static base_field_element res {
            "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        };

        return res;
    }

    static constexpr size_t generator_table_window_bit_size = 8;
    static constexpr size_t generator_table_size =
        2 << generator_table_window_bit_size;

    using generator_table_point =
        std::tuple<base_field_element, base_field_element>;

    using generator_table_window =
        std::array<generator_table_point, generator_table_size>;

    using generator_table_t = std::array <
        generator_table_window,
        256 / generator_table_window_bit_size
    >;

    /// Returns reference to generator precomputer table
    static generator_table_t &generator_table();
};

using p256_curve = detail::elliptic_curve <
    detail::weierstrass_affine_curve <
        p256_curve_def
    >
>;

static_assert(detail::EllipticCurve<p256_curve>);


}


#endif // __LIGETRON_EC_P256_HPP__
