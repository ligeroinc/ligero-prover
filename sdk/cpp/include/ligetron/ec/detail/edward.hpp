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
 * Edward elliptic curves implementation
 */

#ifndef __LIGETRON_EC_DETAIL_EDWARD_HPP__
#define __LIGETRON_EC_DETAIL_EDWARD_HPP__

#include "coordinates.hpp"
#include "generator_table.hpp"


namespace ligetron::ec::detail {


template <typename CurveDef>
concept EdwardAffineCurveDef = requires {
    typename CurveDef::base_field_element;
    typename CurveDef::scalar_field_element;

    { CurveDef::coeff_d() } ->
        std::convertible_to<typename CurveDef::base_field_element>;

    { CurveDef::generator_x() } ->
        std::convertible_to<typename CurveDef::base_field_element>;

    { CurveDef::generator_y() } ->
        std::convertible_to<typename CurveDef::base_field_element>;
};

template <EdwardAffineCurveDef CurveDef>
struct edward_affine_curve {
    using base_field_element   = typename CurveDef::base_field_element;
    using scalar_field_element = typename CurveDef::scalar_field_element;
    using point                = affine_coordinate<base_field_element>;

    static point &generator() {
        static point g {CurveDef::generator_x(), CurveDef::generator_y()};
        return g;
    }

    static base_field_element &coeff_d() {
        return CurveDef::coeff_d();
    }

    static point identity() {
        return point{0, 1};
    }

    static point point_add(const point &p1, const point &p2) {
        auto x1y2 = p1.x() * p2.y();
        auto x2y1 = p2.x() * p1.y();
        auto y1y2 = p1.y() * p2.y();
        auto x1x2 = p1.x() * p2.x();
        auto x1x2y1y2 = x1x2 * y1y2;
        auto dxy = CurveDef::coeff_d() * x1x2y1y2;
        auto t1 = x1y2 + x2y1;
        auto t2 = base_field_element{1} + dxy;
        auto x3 = t1 / t2;
        auto t3 = y1y2 + x1x2;
        auto t4 = base_field_element{1} - dxy;
        auto y3 = t3 / t4;

        return point{x3, y3};
    }

    static point point_double(const point &p) {
        auto xx = p.x() * p.x();
        auto yy = p.y() * p.y();
        auto xy = p.x() * p.y();
        auto t1 = xy + xy;
        auto t2 = yy - xx;
        auto u = t1 / t2;
        auto t3 = xx + yy;
        auto t4 = base_field_element{2} - t2;
        auto v = t3 / t4;

        return point{u, v};
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

    static auto is_point_on_curve(const point &p) {
        auto xx = p.x() * p.x();
        auto yy = p.y() * p.y();

        auto lhs = yy - xx;
        auto rhs = base_field_element{1} + CurveDef::coeff_d() * xx * yy;

        return base_field_element::eq(lhs, rhs);
    }

    static constexpr size_t generator_table_window_bit_size =
         EllipticCurveDefWithGeneratorTable<CurveDef> ?
         CurveDef::generator_table::window_bit_size :
         0;

    static point generator_table_lookup(size_t window_index,
                                        bn254fr_class &index)
    requires EllipticCurveDefWithGeneratorTable<CurveDef> {
        using table_t = generator_table<typename CurveDef::generator_table>;
        return table_t::lookup(window_index, index);
    }
};


}


#endif // __LIGETRON_EC_DETAIL_WEIERSTRASS_HPP__
