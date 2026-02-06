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
 * ECDSA implementation
 */


#ifndef __LIGETRON_EC_ECDSA_HPP__
#define __LIGETRON_EC_ECDSA_HPP__

#include <ligetron/curve.h>


namespace ligetron {


/// Verifies ECDSA signature
template <ec::detail::EllipticCurve EC>
void ecdsa_verify(const typename EC::scalar_field_element &msg_hash,
                  const typename EC::scalar_field_element &r,
                  const typename EC::scalar_field_element &s,
                  typename EC::point &pub_key) {

    using scalar_field_element = EC::scalar_field_element;
    using curve_point = typename EC::point;

    auto u1 = msg_hash / s;
    auto u2 = r / s;

    // P1 = u1 x G
    curve_point P1;
    if constexpr (ec::detail::EllipticCurveWithScalarMulGenerator<EC>) {
        P1 = EC::scalar_mul_generator(u1);
    } else {
        P1 = EC::scalar_mul(u1, EC::generator());
    }

    // P1 = u2 x pub_key
    auto P2 = EC::scalar_mul(u2, pub_key);

    // X = (x, y)= P1 + P2
    auto X = EC::point_add(P1, P2);

    // verify x == r
    scalar_field_element::assert_equal(EC::point_x_to_scalar(X), r);
}

/// Verifies ECDSA signature for message hash as binary data
template <ec::detail::EllipticCurve EC>
void ecdsa_verify(std::span<const unsigned char> msg_hash_data,
                  const typename EC::scalar_field_element &r,
                  const typename EC::scalar_field_element &s,
                  typename EC::point &pub_key) {

    using scalar_field_element = EC::scalar_field_element;

    scalar_field_element msg_hash;

    static_assert(scalar_field_element::num_rounded_bits % 8 == 0);
    size_t num_rounded_bytes = scalar_field_element::num_rounded_bits / 8;
    size_t msg_hash_size = std::min(msg_hash_data.size(), num_rounded_bytes);
    msg_hash.import_bytes_big(msg_hash_data.first(msg_hash_size));

    ecdsa_verify<EC>(msg_hash, r, s, pub_key);
}


}


#endif // __LIGETRON_EC_ECDSA_HPP__
