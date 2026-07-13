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

#include <ligetron/api.h>
#include <ligetron/bn254fr_bigint.hpp>
#include <ligetron/bn254fr_class.h>
#include <ligetron/ecc/curves/coordinates.hpp>
#include <ligetron/ecc/curves/curve_base.hpp>
#include <ligetron/ecc/utils.hpp>

namespace ligetron::ecc::curves {

/*
 * Generic Twisted Edwards curve implementation with a = -1
 */
template <typename BaseField, typename ScalarField>
struct am1_twisted_edwards : affine_curve_base<BaseField, ScalarField> {
    using base_type = affine_curve_base<BaseField, ScalarField>;
    using typename base_type::base_field_type;
    using typename base_type::point_type;
    using typename base_type::scalar_field_type;

    am1_twisted_edwards(base_field_type d, point_type generator)
        : d_(std::move(d)), zero_(0u), one_(1u), generator_(std::move(generator)) {}

    const point_type& infinity() const override final {
        static point_type inf{zero_, one_};
        return inf;
    }

    bn254fr_class is_inf(const point_type& p) const override final {
        bn254fr_class xz = base_field_type::eqz(p.x);
        bn254fr_class yz = base_field_type::eq(p.y, one_);
        bn254fr_class out;
        bn254fr_land_checked(out.data(), xz.data(), yz.data());
        return out;
    }

    const point_type& generator() const override final { return generator_; }

    bn254fr_class on_curve(const point_type& p) const override final {
        auto xx = p.x * p.x;
        auto yy = p.y * p.y;
        auto xxyy = xx * yy;
        return base_field_type::eq(yy - xx, base_field_type{1u} + d_ * xxyy);
    }

    /*
     * Generic affine negation formula for twisted edwards curve:
     *     -(x, y) = (-x, y)
     */
    point_type point_negate(const point_type& p) const override final {
        base_field_type neg_x;
        base_field_type::neg(neg_x, p.x);
        return point_type{std::move(neg_x), p.y};
    }

    /*
     * Complete affine point addition formula
     */
    point_type point_add(const point_type& p1, const point_type& p2) const override final {
        static const base_field_type one{1u};
        auto x1y2 = p1.x * p2.y;
        auto x2y1 = p2.x * p1.y;
        auto y1y2 = p1.y * p2.y;
        auto x1x2 = p1.x * p2.x;
        auto x1x2y1y2 = x1x2 * y1y2;
        auto dxy = d_ * x1x2y1y2;
        auto t1 = x1y2 + x2y1;
        auto t2 = one + dxy;
        auto x3 = t1 / t2;
        auto t3 = y1y2 + x1x2;
        auto t4 = one - dxy;
        auto y3 = t3 / t4;
        return point_type{std::move(x3), std::move(y3)};
    }

    point_type point_double(const point_type& p) const override final {
        static const base_field_type two{2u};
        auto xx = p.x * p.x;
        auto yy = p.y * p.y;
        auto xy = p.x * p.y;
        auto t1 = xy + xy;
        auto t2 = yy - xx;
        auto x3 = t1 / t2;
        auto t3 = xx + yy;
        auto t4 = two - t2;
        auto y3 = t3 / t4;
        return point_type{std::move(x3), std::move(y3)};
    }

protected:
    base_field_type d_, zero_, one_;
    point_type generator_;
};

} // namespace ligetron::ecc::curves
