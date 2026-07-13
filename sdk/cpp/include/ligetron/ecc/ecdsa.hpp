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

#include <cassert>
#include <cstddef>
#include <span>
#include <vector>

#include <ligetron/sha2.h>

namespace ligetron::ecc {

template <typename Curve>
struct ecdsa_context {
    using curve_type   = Curve;
    using base_field   = typename curve_type::base_field_type;
    using scalar_field = typename curve_type::scalar_field_type;
    using point_type   = typename curve_type::point_type;

    static constexpr size_t field_bytes     = base_field::num_rounded_bits / 8;
    static constexpr size_t scalar_bytes    = scalar_field::num_rounded_bits / 8;
    static constexpr size_t pubkey_bytes    = 2 * field_bytes;
    static constexpr size_t signature_bytes = 2 * scalar_bytes;

    ecdsa_context(std::span<const std::byte, pubkey_bytes> pubkey) {
        auto x_bytes = pubkey.template first<field_bytes>();
        auto y_bytes = pubkey.template subspan<field_bytes, field_bytes>();
        pubkey_.x.import_bytes_big(
            {reinterpret_cast<const unsigned char*>(x_bytes.data()), x_bytes.size()});
        pubkey_.y.import_bytes_big(
            {reinterpret_cast<const unsigned char*>(y_bytes.data()), y_bytes.size()});
    }

    bn254fr_class verify(std::span<const std::byte, signature_bytes> sig,
                         std::span<const std::byte> msg) {

        bn254fr_class pubkey_valid = curve().on_curve(pubkey_);
        
        auto r_bytes = sig.template first<scalar_bytes>();
        auto s_bytes = sig.template subspan<scalar_bytes, scalar_bytes>();

        // Check imported (r, s) are in range [1, n-1], otherwise fail
        bn254fr_bigint upper_bound;
        bn254fr_bigint r_storage, s_storage;
        
        auto order_bytes = curve().order_bytes();
        upper_bound.set_bytes_big(reinterpret_cast<const unsigned char*>(order_bytes.data()),
                                  order_bytes.size());

        r_storage.set_bytes_big(reinterpret_cast<const unsigned char*>(r_bytes.data()),
                                r_bytes.size());
        s_storage.set_bytes_big(reinterpret_cast<const unsigned char*>(s_bytes.data()),
                                s_bytes.size());

        bn254fr_class r_is_zero  = r_storage.eqz();
        bn254fr_class r_is_small = bn254fr_bigint::lt(r_storage, upper_bound);
        bn254fr_class s_is_zero  = s_storage.eqz();
        bn254fr_class s_is_small = bn254fr_bigint::lt(s_storage, upper_bound);

        bn254fr_class one{1u};
        bn254fr_class rs_valid;
        {
            bn254fr_class r_not_zero;
            bn254fr_submod_checked(r_not_zero.data(), one.data(), r_is_zero.data());
            bn254fr_class s_not_zero;
            bn254fr_submod_checked(s_not_zero.data(), one.data(), s_is_zero.data());
            bn254fr_class tmp1;
            bn254fr_land_checked(tmp1.data(), r_not_zero.data(), s_not_zero.data());
            bn254fr_class tmp2;
            bn254fr_land_checked(tmp2.data(), r_is_small.data(), s_is_small.data());
            bn254fr_land_checked(rs_valid.data(), tmp1.data(), tmp2.data());
        }

        // Replace r, s with dummy value if zero to avoid division by zero
        scalar_field imported_r{r_storage}, imported_s{s_storage};
        scalar_field r{1u}, s{1u};
        r = scalar_field::mux(rs_valid, r, imported_r);
        s = scalar_field::mux(rs_valid, s, imported_s);

        // Hardcode sha256 for now
        unsigned char digest[32]{};
        ligetron_sha2_256(digest, reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
        
        scalar_field z;
        z.import_bytes_big(digest);
        z.reduce();

        scalar_field invs;
        scalar_field::inv(invs, s);

        scalar_field u1 = z * invs;
        scalar_field u2 = r * invs;

        point_type P1 = curve().scalar_mul_generator(u1);
        point_type P2 = curve().scalar_mul(u2, pubkey_);
        point_type Psum = point_type::select(P1 == P2,
                                             curve().point_add(P1, P2), curve().point_double(P1));
        
        bn254fr_class is_not_inf;
        bn254fr_submod_checked(is_not_inf.data(), one.data(), curve().is_inf(Psum).data());
        
        scalar_field scalar_x{Psum.x.data()};
        scalar_x.reduce();
        bn254fr_class sig_valid = scalar_field::eq(scalar_x, r);
    
        bn254fr_class valid;
        {
            bn254fr_class tmp1, tmp2;
            bn254fr_land_checked(tmp1.data(), pubkey_valid.data(), rs_valid.data());
            bn254fr_land_checked(tmp2.data(), is_not_inf.data(), sig_valid.data());
            bn254fr_land_checked(valid.data(), tmp1.data(), tmp2.data());
        }

        return valid;
    }

private:
    const curve_type& curve() const {
        static curve_type c;
        return c;
    }

    point_type pubkey_;
};

} // namespace ligetron::ecc
