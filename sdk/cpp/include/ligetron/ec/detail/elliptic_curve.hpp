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
 * Elliptic curve API implementation
 */

#ifndef __LIGETRON_EC_DETAIL_ELLIPTIC_CURVE_HPP__
#define __LIGETRON_EC_DETAIL_ELLIPTIC_CURVE_HPP__

#include <ligetron/bn254fr_class.h>
#include <array>


namespace ligetron::ec::detail {


template <typename Backend>
concept EllipticCurveBackend =
        requires(const typename Backend::point& p1,
                 const typename Backend::point& p2,
                 const bn254fr_class& b,
                 const typename Backend::scalar_field_element& s) {
    typename Backend::base_field_element;
    typename Backend::scalar_field_element;
    typename Backend::point;

    { Backend::point_add(p1, p2) } ->
        std::convertible_to<typename Backend::point>;
    { Backend::point_double(p1) } ->
        std::convertible_to<typename Backend::point>;
    { Backend::generator() } ->
        std::convertible_to<typename Backend::point>;
    { Backend::point_mux(b, p1, p2) } ->
        std::convertible_to<typename Backend::point>;
    { Backend::point_x_to_scalar(p1) } ->
        std::convertible_to<typename Backend::scalar_field_element>;
};

template <typename Backend>
concept EllipticCurveBackendHasGeneratorTable =
        requires(size_t window_index, bn254fr_class &index) {

    { Backend::generator_table_window_bit_size } ->
        std::convertible_to<size_t>;

    { Backend::generator_table_lookup(window_index, index) } ->
        std::convertible_to<typename Backend::point>;
};

template <EllipticCurveBackend Backend>
struct elliptic_curve {
    using base_field_element   = typename Backend::base_field_element;
    using scalar_field_element = typename Backend::scalar_field_element;
    using point                = typename Backend::point;

    static point point_add(const point& p1, const point& p2) {
        return Backend::point_add(p1, p2);
    }

    static point point_double(const point& p) {
        return Backend::point_double(p);
    }

    static scalar_field_element point_x_to_scalar(const point& p) {
        return Backend::point_x_to_scalar(p);
    }

    static point scalar_mul(const scalar_field_element& s, const point& p) {
        // decompose s value into bits
        std::array<bn254fr_class, scalar_field_element::num_rounded_bits> bits;
        s.to_bits(bits.data());

        point sum;
        point p_pow = p;

        // iterating over bits and performing point addition and double
        for (size_t i = 0; i < scalar_field_element::num_rounded_bits; ++i) {
            auto point_add_res = point_add(sum, p_pow);
            auto new_sum = Backend::point_mux(bits[i], sum, point_add_res);
            auto p_pow_2 = point_double(p_pow);
            p_pow = p_pow_2;
            sum = new_sum;

            sum.x().reduce();
            sum.y().reduce();
            p_pow.x().reduce();
            p_pow.y().reduce();
        }

        return sum;
    }

    static point scalar_mul_generator(const scalar_field_element& s)
    requires EllipticCurveBackendHasGeneratorTable<Backend> {
        constexpr auto num_rounded_bits =
            scalar_field_element::num_rounded_bits;
        constexpr auto window_bit_size =
            Backend::generator_table_window_bit_size;
        constexpr auto n_windows = num_rounded_bits / window_bit_size +
            (num_rounded_bits % window_bit_size == 0 ? 0 : 1);
        constexpr auto last_window_bit_size =
            num_rounded_bits % window_bit_size == 0 ?
            window_bit_size :
            num_rounded_bits % window_bit_size;

        // decompose s value into bits
        std::array<bn254fr_class, scalar_field_element::num_rounded_bits> bits;
        s.to_bits(bits.data());

        bn254fr_class index0;
        index0.from_bits(&bits[0], window_bit_size);
        point res = Backend::generator_table_lookup(0, index0);

        for (size_t i = 1; i < n_windows; ++i) {
            size_t index_bit_size = (i == n_windows - 1) ?
                                    last_window_bit_size :
                                    window_bit_size;

            bn254fr_class index;
            index.from_bits(&bits[i * window_bit_size], index_bit_size);
            point g_power = Backend::generator_table_lookup(i, index);
            res = point_add(g_power, res);
        }

        return res;
    }

    static point generator() {
        return Backend::generator();
    }
};


}


#endif // __LIGETRON_EC_DETAIL_ELLIPTIC_CURVE_HPP__
