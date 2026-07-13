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
 * EdDSA implementation
 */


#ifndef __LIGETRON_EC_EDDSA_HPP__
#define __LIGETRON_EC_EDDSA_HPP__

#include <ligetron/curve.h>
#include <ligetron/sha512.h>
#include <ligetron/api.h>
#include <ligetron/bn254fr.h>
#include <ligetron/bn254fr_bigint.hpp>
#include <ligetron/uint256_cpp.h>
#include <cassert>
#include <array>
#include <span>
#include <vector>
#include <iostream>


namespace ligetron::ec {


/// Verifies EdDSA equation
template <ec::detail::EllipticCurve EC>
bool eddsa_verify(const typename EC::scalar_field_element &k,
                  const typename EC::point &r,
                  const typename EC::scalar_field_element &s,
                  const typename EC::point &pub_key) {

    using scalar_field_element = EC::scalar_field_element;
    using curve_point = typename EC::point;

    // lhs = s x G
    curve_point lhs;
    if constexpr (ec::detail::EllipticCurveWithScalarMulGenerator<EC>) {
        lhs = EC::scalar_mul_generator(s);
    } else {
        lhs = EC::scalar_mul(s, EC::generator());
    }

    // rhs = r + k * pub_key
    auto rhs = EC::point_add(r, EC::scalar_mul(k, pub_key));

    // verify lhs == rhs
    return curve_point::eq(lhs, rhs);
}

/// Generates public key from private
template <ec::detail::EllipticCurve EC>
auto eddsa_pubkey_gen(const typename EC::scalar_field_element &priv) {
    if constexpr (ec::detail::EllipticCurveWithScalarMulGenerator<EC>) {
        return EC::scalar_mul_generator(priv);
    } else {
        return EC::scalar_mul(priv, EC::generator());
    }
}


}


#endif // __LIGETRON_EC_EDDSA_HPP__
