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
#include <ligetron/bn254fr_class.h>
#include <ligetron/bn254fr_bigint.hpp>
#include <ligetron/ecc/curves/coordinates.hpp>
#include <ligetron/ecc/utils.hpp>
#include <ligetron/ecc/curves/curve_base.hpp>

namespace ligetron::ecc::curves {

template <typename BaseField, typename ScalarField>
struct short_weierstrass : affine_curve_base<BaseField, ScalarField> {
    using base_type = affine_curve_base<BaseField, ScalarField>;
    using typename base_type::base_field_type;
    using typename base_type::scalar_field_type;
    using typename base_type::point_type;

    short_weierstrass(base_field_type a, base_field_type b, point_type generator)
        : a_(std::move(a)), b_(std::move(b)), generator_(std::move(generator)) {}

    /*
     * Sentinel representation of the curve identity element, encoded as (0:0).
     *
     * This value is NOT a point on the curve. However, all point operations in this
     * class treat it as the neutral element and preserve the group identity semantics.
     */
    const point_type& infinity() const override final {
        static point_type inf{base_field_type{0}, base_field_type{0}};
        return inf;
    }

    bn254fr_class is_inf(const point_type& p) const override final {
        bn254fr_class xz = base_field_type::eqz(p.x);
        bn254fr_class yz = base_field_type::eqz(p.y);
        bn254fr_class out;
        bn254fr_land_checked(out.data(), xz.data(), yz.data());
        return out;
    }
    
    const point_type& generator() const override final {
        return generator_;
    }
    
    const base_field_type& param_a() const { return a_; }
    const base_field_type& param_b() const { return b_; }
    
    bn254fr_class on_curve(const point_type& p) const override final {
        auto yy = p.y * p.y;
        auto rhs = p.x * p.x * p.x + a_ * p.x + b_;
        return base_field_type::eq(yy, rhs);
    }
    
    /*
     * Generic affine negation formula for short weierstrass curve:
     *     -(x, y) = (x, -y)
     */
    point_type point_negate(const point_type& p) const override final {
        const auto& [x, y] = p;
        base_field_type neg_y;
        base_field_type::neg(neg_y, y);
        return point_type{x, std::move(neg_y)};
    }
    
    /*
     * Partial affine point addition formula.
     *
     * This routine handles the identity and inverse cases:
     *   - p1 is the sentinel identity element (0 : 0)
     *   - p2 is the sentinel identity element (0 : 0)
     *   - p1 == -p2 (output the identity)
     *
     * Point doubling, i.e. the case p1 == p2, is intentionally not handled here.
     */
    point_type point_add(const point_type& p1, const point_type& p2) const override final {
        auto p1_zero = is_inf(p1);
        auto p2_zero = is_inf(p2);
        auto x_eq = base_field_type::eq(p1.x, p2.x);
        auto y_neg = base_field_type::eqz(p1.y + p2.y);
        bn254fr_class p1_add_p2_zero;
        bn254fr_land_checked(p1_add_p2_zero.data(), x_eq.data(), y_neg.data());
        auto u1   = p2.y - p1.y;
        auto u2   = p2.x - p1.x;
        auto div  = base_field_type::mux(base_field_type::eqz(u2), u2, u1);
        auto lam  = u1 / div;
        auto lam2 = lam * lam;
        auto t1   = lam2 - p1.x;
        auto x3   = t1 - p2.x;
        auto t2   = p1.x - x3;
        auto t3   = lam * t2;
        auto y3   = t3 - p1.y;

        auto q0 = point_type::select(p1_add_p2_zero,
                                       point_type{std::move(x3), std::move(y3)},
                                       infinity());
        auto q1 = point_type::select(p2_zero, q0, p1);
        return point_type::select(p1_zero, q1, p2);
    }
    
    /*
     * Affine point doubling formula.
     *
     * This routine handles the sentinel identity element (0:0). For all other
     * valid affine points, it computes 2p using the standard formula.
     */
    point_type point_double(const point_type& P) const override final {
        const auto& [X1, Y1] = P;
        auto x12     = X1 * X1;
        auto u1      = x12 + x12 + x12;
        auto u2      = u1 + a_;
        auto u3      = Y1 + Y1;
        // Use a dummy value to perform the division to avoid divide by 0 error
        auto eqz     = is_inf(P);
        auto divisor = base_field_type::mux(eqz, u3, u2);
        auto lam     = u2 / divisor;
        auto lam2    = lam * lam;
        auto t1      = lam2 - X1;
        auto x3      = t1 - X1;
        auto t2      = X1 - x3;
        auto t3      = lam * t2;
        auto y3      = t3 - Y1;
        // Replace the value to 0 to make sure the (x3, y3) is also (0, 0)
        return point_type::select(eqz, point_type{std::move(x3), std::move(y3)}, P);
    }
    
protected:
    base_field_type a_, b_;
    point_type generator_;
};

} // namespace ligetron::ecc::curves
