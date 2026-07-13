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
#include <ligetron/ecc/utils.hpp>

namespace ligetron::ecc::curves {

template <typename BaseField, typename ScalarField>
struct affine_curve_base {
    using base_field_type   = BaseField;
    using scalar_field_type = ScalarField;
    using point_type        = affine_coordinate<base_field_type>;

    static constexpr size_t num_base_field_bytes   = base_field_type::num_rounded_bits / 8;
    static constexpr size_t num_scalar_field_bytes = scalar_field_type::num_rounded_bits / 8;

    virtual const point_type& infinity() const = 0;
    virtual bn254fr_class is_inf(const point_type&) const = 0;
    virtual const point_type& generator() const = 0;
    virtual bn254fr_class on_curve(const point_type&) const = 0;
    
    virtual point_type point_negate(const point_type&) const = 0;
    virtual point_type point_double(const point_type&) const = 0;
    virtual point_type point_add(const point_type&, const point_type&) const = 0;

    virtual ECCCurveType curve_type() const noexcept = 0;
    virtual std::span<const std::byte> order_bytes() const noexcept = 0;
    virtual std::span<const std::byte> base_field_bytes() const noexcept = 0;
    virtual point_type scalar_mul_generator(const scalar_field_type&) const = 0;

    void assert_on_curve(const point_type& p) const {
        bn254fr_assert_equal_u32(on_curve(p).data(), 1u);
    }

    point_type scalar_mul(const scalar_field_type& k, const point_type& point) const {        
        unsigned char point_bytes[2 * num_base_field_bytes]{};
        point.x.export_bytes_little({point_bytes, num_base_field_bytes});
        point.y.export_bytes_little({point_bytes + num_base_field_bytes, num_base_field_bytes});

        unsigned char k_bytes[num_scalar_field_bytes]{};
        k.export_bytes_little(k_bytes);

        unsigned char out_bytes[2 * num_base_field_bytes]{};
        ecc_scalar_mul(curve_type(), out_bytes, point_bytes, k_bytes, sizeof(k_bytes));

        bn254fr_bigint rx_storage, ry_storage;
        rx_storage.set_bytes_little(out_bytes, num_base_field_bytes);
        ry_storage.set_bytes_little(out_bytes + num_base_field_bytes, num_base_field_bytes);

        point_type result{base_field_type{std::move(rx_storage)},
                          base_field_type{std::move(ry_storage)}};

        // Instead of proving [k]P = Q, which requires 256 point-double,
        // we cheat by letting the backend compute Q and prove
        // [x]P - [z]Q = O, where x - zk = 0 mod n and x, z < sqrt(n).
        // This can be done with MSM and reduce the point-doubling by half
        unsigned char x_bytes[num_base_field_bytes]{}, z_bytes[num_base_field_bytes]{};
        int x_positive, z_positive;

        ecc_scalar_decompose(curve_type(),
                             x_bytes, &x_positive,
                             z_bytes, &z_positive,
                             k_bytes, sizeof(k_bytes));

        bn254fr_bigint x_storage, z_storage;
        x_storage.set_bytes_little(x_bytes, num_base_field_bytes / 2);
        z_storage.set_bytes_little(z_bytes, num_base_field_bytes / 2);

        // Constrain `x_positive` and `z_positive` to be either 0 or 1
        assert_one(x_positive * x_positive == x_positive);
        assert_one(z_positive * z_positive == z_positive);
        // Constrain `x` and `z` to be not zero
        bn254fr_assert_equal_u32(x_storage.eqz().data(), 0);
        bn254fr_assert_equal_u32(z_storage.eqz().data(), 0);
        // Bound the host-computed x, z value to x == z * k mod n
        // where x, z must not equal 0
        scalar_field_type x{std::move(x_storage)}, z{std::move(z_storage)};
        scalar_field_type negx, negz;
        scalar_field_type::neg(negx, x);
        scalar_field_type::neg(negz, z);
        auto x_signed = scalar_field_type::mux(x_positive, negx, x);
        auto z_signed = scalar_field_type::mux(z_positive, negz, z);
        bn254fr_class x_eq_zk = scalar_field_type::eq(x_signed, z_signed * k);
        bn254fr_assert_equal_u32(x_eq_zk.data(), 1);

        auto P = point_type::select(bn254fr_class{x_positive}, point_negate(point), point);
        auto Q = point_type::select(bn254fr_class{z_positive}, result, point_negate(result));

        // Prepare a 4x4 MSM precompute table
        // |   | 0  | 1      | 2       | 3       |
        // | 0 | O  | P      | 2P      | 3P      |
        // | 1 | Q  | Q + P  | Q + 2P  | Q + 3P  |
        // | 2 | 2Q | 2Q + P | 2Q + 2P | 2Q + 3P |
        // | 3 | 3Q | 3Q + P | 3Q + 2P | 3Q + 3P |
        constexpr int window_bit_width = 2;
        constexpr int window_count     = (scalar_field_type::num_rounded_bits / 2) / window_bit_width;

        point_type precomp[16];
        precomp[0]  = infinity();
        precomp[1]  = P;
        precomp[2]  = point_double(P);
        precomp[3]  = point_add(precomp[2], P);
        precomp[4]  = Q;
        precomp[8]  = point_double(Q);
        precomp[12] = point_add(precomp[8], Q);

        for (int row = 1; row < 4; ++row) {
            for (int col = 1; col < 4; ++col) {
                const int idx = row * 4 + col;
                const int prev_idx = idx - 4; // previous row
                precomp[idx] = point_type::select(precomp[prev_idx] == Q,
                                                  point_add(precomp[prev_idx], Q),
                                                  point_double(Q));
            }
        }

        for (int i = 1; i < 16; i++) {
            precomp[i].x.reduce();
            precomp[i].y.reduce();
        }

        bn254fr_class x_bits[scalar_field_type::num_rounded_bits];
        bn254fr_class z_bits[scalar_field_type::num_rounded_bits];
        x.to_bits(x_bits);
        z.to_bits(z_bits);

        int offset = (window_count - 1) * window_bit_width;
        auto acc = point_select_2d(window_bit_width, x_bits + offset, z_bits + offset, precomp);
        for (int i = window_count - 2; i >= 0; --i) {
            for (int j = 0; j < window_bit_width; j++) {
                acc = point_double(acc);
                acc.x.reduce();
                acc.y.reduce();
            }
            
            offset = i * window_bit_width;
            auto t = point_select_2d(window_bit_width, x_bits + offset, z_bits + offset, precomp);
            acc = point_add(t, acc);
            acc.x.reduce();
            acc.y.reduce();
        }
        bn254fr_assert_equal_u32(is_inf(acc).data(), 1);

        return result;
    }
};

} // namespace ligetron::ecc::curves
