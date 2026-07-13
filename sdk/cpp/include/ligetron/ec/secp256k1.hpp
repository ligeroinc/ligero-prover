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


/// secp256k1 base field
struct secp256k1_base_field:
        public ff::prime_field_uint256<secp256k1_base_field> {

    static storage_type &modulus() {
        static storage_type m {
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        };
        return m;
    }
};


/// secp256k1 scalar (order) field
struct secp256k1_scalar_field:
        public ff::prime_field_uint256<secp256k1_scalar_field> {

    static storage_type &modulus() {
        static storage_type m {
            "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
        };
        return m;
    }
};


struct secp256k1_curve_def {
    using base_field_element = ff::field_element<secp256k1_base_field>;
    using scalar_field_element = ff::field_element<secp256k1_scalar_field>;

    /// Curve a cosntant
    static base_field_element &coeff_a() {
        static base_field_element res {
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        };

        return res;
    }

    /// Curve b cosntant
    static base_field_element &coeff_b() {
        static base_field_element res {
            "0x0000000000000000000000000000000000000000000000000000000000000007"
        };

        return res;
    }


    /// Curve generator point x coordinate
    static base_field_element &generator_x() {
        static base_field_element res {
            "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        };

        return res;
    }

    /// Curve generator point y coordinate
    static base_field_element &generator_y() {
        static base_field_element res {
            "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        };

        return res;
    }

    struct generator_table:
            public detail::affine_generator_table_def<base_field_element, 8> {
        static table_t &table();
    };
};

using secp256k1_curve = detail::elliptic_curve <
    detail::weierstrass_affine_curve <
        secp256k1_curve_def
    >
>;

static_assert(detail::EllipticCurve<secp256k1_curve>);


}


#endif // __LIGETRON_EC_P256_HPP__
