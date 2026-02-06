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
 * Weierstrass elliptic curves implementation
 */

#ifndef __LIGETRON_EC_DETAIL_WEIERSTRASS_HPP__
#define __LIGETRON_EC_DETAIL_WEIERSTRASS_HPP__

#include "coordinates.hpp"
#include <ligetron/bn254fr_class.h>


namespace ligetron::ec::detail {


template <typename CurveDef>
concept WeierstrassAffineCurveDef = requires {
    typename CurveDef::base_field_element;
    typename CurveDef::scalar_field_element;

    { CurveDef::coeff_a() } ->
        std::convertible_to<typename CurveDef::base_field_element>;

    { CurveDef::coeff_b() } ->
        std::convertible_to<typename CurveDef::base_field_element>;

    { CurveDef::generator_x() } ->
        std::convertible_to<typename CurveDef::base_field_element>;

    { CurveDef::generator_y() } ->
        std::convertible_to<typename CurveDef::base_field_element>;
};

template <typename CurveDef>
concept WeierstrassAffineCurveDefHasGeneratorTable =
        requires(size_t window_index, size_t index) {

    { CurveDef::generator_table_window_bit_size } ->
        std::convertible_to<size_t>;

    { CurveDef::generator_table()[window_index][index] } ->
        std::convertible_to <
            std::tuple <
                typename CurveDef::base_field_element,
                typename CurveDef::base_field_element
            >
        >;
};

template <typename CurveDef>
concept WeierstrassAffineCurveDefWithGeneratorTable =
    WeierstrassAffineCurveDef<CurveDef> &&
    WeierstrassAffineCurveDefHasGeneratorTable<CurveDef>;

template <WeierstrassAffineCurveDefWithGeneratorTable CurveDef>
struct weierstrass_affine_curve_generator_table {
    using base_field_element   = typename CurveDef::base_field_element;
    using scalar_field_element = typename CurveDef::scalar_field_element;
    using point                = affine_coordinate<base_field_element>;

    static constexpr size_t window_bit_size =
        CurveDef::generator_table_window_bit_size;

    static constexpr size_t window_size = 2 << (window_bit_size - 1);

    /// Performs oblivious table lookup for specified window index
    /// and index in window
    static point lookup(size_t window_index, bn254fr_class &index) {
        // decode index into array of selectors
        std::array<bn254fr_class, window_size> selectors;
        decompose_index(selectors, index);

        base_field_element zero;

        // the result is the sum of products of selectors and table items
        base_field_element sum_x;
        base_field_element sum_y;

        for (int i = 0; i < window_size; ++i) {
            auto [x, y] = CurveDef::generator_table()[window_index][i];

            auto mux_res_x = base_field_element::mux(selectors[i], zero, x);
            auto mux_res_y = base_field_element::mux(selectors[i], zero, y);

            sum_x = sum_x + mux_res_x;
            sum_y = sum_y + mux_res_y;
        }

        return point{sum_x, sum_y};
    }

    /// Decomposes index into selector bits.
    /// Assumes selectors array is initialized with zeros.
    static void decompose_index(
            std::array<bn254fr_class, window_size> &selectors,
            bn254fr_class &index) {

        bn254fr_class bn254fr_index{index};
        bn254fr_class bn254fr_zero;

        bn254fr_class sum;      // sum of all selectors

        for (int i = 0; i < window_size; ++i) {
            // calculate value of selector without constraints
            if (i == bn254fr_index) {
                selectors[i].set_u32(1);
            } else {
                // selectors[i] should be previously initialized to zero
            }

            // add selectors[i] * (index - i) === 0 constraint
            bn254fr_class bn254fr_i{i};
            bn254fr_class index_minus_i;
            submod(index_minus_i, bn254fr_index, bn254fr_i);
            bn254fr_class mul_res;
            mulmod(mul_res, selectors[i], index_minus_i);
            bn254fr_class::assert_equal(mul_res, bn254fr_zero);

            addmod(sum, sum, selectors[i]);
        }

        // sum of all selectors must be 1
        bn254fr_class one{1};
        bn254fr_class::assert_equal(sum, one);
    }
};

template <WeierstrassAffineCurveDef CurveDef>
struct weierstrass_affine_curve {
    using base_field_element   = typename CurveDef::base_field_element;
    using scalar_field_element = typename CurveDef::scalar_field_element;
    using point                = affine_coordinate<base_field_element>;

    static point &generator() {
        static point g {CurveDef::generator_x(), CurveDef::generator_y()};
        return g;
    }

    static bn254fr_class point_is_zero(const point &p) {
        auto x_zero = base_field_element::eqz(p.x());
        auto y_zero = base_field_element::eqz(p.y());
        bn254fr_class res;
        mulmod(res, x_zero, y_zero);
        return res;
    }

    static point point_add(const point &p1, const point &p2) {
        auto u1 = p2.y() - p1.y();
        auto u2 = p2.x() - p1.x();
        auto lam = u1 / u2;
        auto lam2 = lam * lam;
        auto t1 = lam2 - p1.x();
        auto x3 = t1 - p2.x();
        auto t2 = p1.x() - x3;
        auto t3 = lam * t2;
        auto y3 = t3 - p1.y();

        // checking if p1 is zero
        bn254fr_class p1_is_zero = point_is_zero(p1);

        // result is equal to p2 if p1 is zero
        auto res_x = base_field_element::mux(p1_is_zero, x3, p2.x());
        auto res_y = base_field_element::mux(p1_is_zero, y3, p2.y());
        return point{res_x, res_y};
    }

    static point point_double(const point &p) {
        auto x12 = p.x() * p.x();
        auto u1 = x12 + x12 + x12;
        auto u2 = u1 + CurveDef::coeff_a();
        auto u3 = p.y() + p.y();
        auto lam = u2 / u3;
        auto lam2 = lam * lam;
        auto t1 = lam2 - p.x();
        auto x3 = t1 - p.x();
        auto t2 = p.x() - x3;
        auto t3 = lam * t2;
        auto y3 = t3 - p.y();
        return point{x3, y3};
    }

    static point point_mux(const bn254fr_class &c,
                           const point &p1,
                           const point &p2) {
        return point {
            base_field_element::mux(c, p1.x(), p2.x()),
            base_field_element::mux(c, p1.y(), p2.y())
        };
    }

    static scalar_field_element point_x_to_scalar(const point &p) {
        return scalar_field_element{p.x().data()};
    }

    static constexpr size_t generator_table_window_bit_size =
         WeierstrassAffineCurveDefHasGeneratorTable<CurveDef> ?
         CurveDef::generator_table_window_bit_size :
         0;

    static point generator_table_lookup(size_t window_index,
                                        bn254fr_class &index)
    requires WeierstrassAffineCurveDefHasGeneratorTable<CurveDef> {
        using table_t = weierstrass_affine_curve_generator_table<CurveDef>;
        return table_t::lookup(window_index, index);
    }
};


}


#endif // __LIGETRON_EC_DETAIL_WEIERSTRASS_HPP__
