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
#include <iostream>

#include <ligetron/api.h>
#include <ligetron/sha512.h>

namespace ligetron::ecc {

template <typename Curve>
struct eddsa_context {
    using curve_type        = Curve;
    using base_field_type   = typename curve_type::base_field_type;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using point_type        = typename curve_type::point_type;

    static constexpr size_t base_field_bytes    = base_field_type::num_rounded_bits / 8;
    static constexpr size_t scalar_field_bytes  = scalar_field_type::num_rounded_bits / 8;
    static constexpr size_t encoded_point_bytes = base_field_type::num_rounded_bits / 8;
    static constexpr size_t pubkey_bytes        = encoded_point_bytes;
    static constexpr size_t signature_bytes     = 2 * scalar_field_bytes;

    eddsa_context(std::span<const std::byte, pubkey_bytes> pk) : enc_pubkey_bytes_{} {
        std::memcpy(enc_pubkey_bytes_.data(), pk.data(), pk.size());

        auto p_view = curve().base_field_bytes().data();
        bn_p_.set_bytes_big(reinterpret_cast<const unsigned char*>(p_view), base_field_bytes);
        pubkey_valid_ = point_decomporess(pubkey_, pk);
    }

    bn254fr_class point_decomporess(point_type& out,
                                    std::span<const std::byte, encoded_point_bytes> bytes) {
        unsigned char x_bytes[base_field_bytes]{}, y_bytes[base_field_bytes]{};
        bn254fr_class errc = ecc_point_decompress(ECCCurveType_Ed25519, x_bytes, y_bytes, bytes.data());

        // Build constraints after decompressing the point by showing:
        //   - (x, y) is on curve
        //   - 0 <= x, y < p
        //   - encoding[255] == x[0] && encoding[0..255] == y[0..255]
        uint256 enc_storage, x_storage, y_storage;
        enc_storage.set_bytes_little(reinterpret_cast<const unsigned char*>(bytes.data()), encoded_point_bytes);
        x_storage.set_bytes_little(x_bytes, base_field_bytes);
        y_storage.set_bytes_little(y_bytes, base_field_bytes);

        bn254fr_class enc_bits[256], x_bits[256], y_bits[256];
        enc_storage.to_bits(enc_bits);
        x_storage.to_bits(x_bits);
        y_storage.to_bits(y_bits);

        bn254fr_class bit_eq;
        bn254fr_eq_checked(bit_eq.data(), x_bits[0].data(), enc_bits[255].data());
        for (int i = 0; i < 255; i++) {
            bn254fr_class i_eq, land;
            bn254fr_eq_checked(i_eq.data(), y_bits[i].data(), enc_bits[i].data());
            bn254fr_land_checked(land.data(), bit_eq.data(), i_eq.data());
            bit_eq = land;
        }

        bn254fr_bigint bn_x, bn_y;
        bn_x.set_bytes_little(reinterpret_cast<const unsigned char*>(x_bytes), base_field_bytes);
        bn_y.set_bytes_little(reinterpret_cast<const unsigned char*>(y_bytes), base_field_bytes);

        const bn254fr_class x_in_range = bn254fr_bigint::lt(bn_x, bn_p_);
        const bn254fr_class y_in_range = bn254fr_bigint::lt(bn_y, bn_p_);

        out.x = bn_x;
        out.y = bn_y;

        const bn254fr_class is_valid_point = curve().on_curve(out);
        
        bn254fr_class verdict, t1, t2, t3, t4;
        bn254fr_land_checked(t1.data(), x_in_range.data(), y_in_range.data());
        bn254fr_land_checked(t2.data(), is_valid_point.data(), bit_eq.data());
        bn254fr_eqz_checked(t3.data(), errc.data());
        bn254fr_land_checked(t4.data(), t1.data(), t2.data());
        bn254fr_land_checked(verdict.data(), t3.data(), t4.data());
        return verdict;
    }

    bn254fr_class verify(std::span<const std::byte, signature_bytes> sig,
                         std::span<const std::byte> msg) {
        auto R_bytes = sig.template first<base_field_bytes>();
        auto S_bytes = sig.template subspan<scalar_field_bytes, base_field_bytes>();

        point_type R;
        auto R_valid = point_decomporess(R, R_bytes);
        
        // Check imported S is in range [1, n-1], otherwise fail
        bn254fr_bigint upper_bound, s_storage;
        auto order_bytes = curve().order_bytes();
        upper_bound.set_bytes_big(reinterpret_cast<const unsigned char*>(order_bytes.data()),
                                  order_bytes.size());
        s_storage.set_bytes_little(reinterpret_cast<const unsigned char*>(S_bytes.data()),
                                   S_bytes.size());

        bn254fr_class s_valid = bn254fr_bigint::lt(s_storage, upper_bound);
        scalar_field_type s{s_storage};

        // Hardcode SHA512
        const size_t hash_input_size = 2 * encoded_point_bytes + msg.size();
        std::vector<unsigned char> input(hash_input_size);
        unsigned char digest[64]{};
        
        std::memcpy(input.data(), R_bytes.data(), encoded_point_bytes);
        std::memcpy(input.data() + base_field_bytes,
                    enc_pubkey_bytes_.data(), encoded_point_bytes);
        std::memcpy(input.data() + 2 * encoded_point_bytes, msg.data(), msg.size());
        ligetron_sha512(digest, input.data(), hash_input_size);

        scalar_field_type k;
        k.import_bytes_little(digest);

        point_type lhs = curve().scalar_mul_generator(s);
        point_type rhs = curve().point_add(R, curve().scalar_mul(k, pubkey_));

        auto equation_hold = lhs == rhs;
        
        bn254fr_class verdict, t1, t2;
        bn254fr_land_checked(t1.data(), pubkey_valid_.data(), R_valid.data());
        bn254fr_land_checked(t2.data(), s_valid.data(), equation_hold.data());
        bn254fr_land_checked(verdict.data(), t1.data(), t2.data());
        return verdict;
    }
    
private:
    const curve_type& curve() const {
        static curve_type c;
        return c;
    }

    bn254fr_bigint bn_p_;
    std::array<std::byte, pubkey_bytes> enc_pubkey_bytes_; 
    point_type pubkey_;
    bn254fr_class pubkey_valid_;
};

} // namespace ligetron::ecc
