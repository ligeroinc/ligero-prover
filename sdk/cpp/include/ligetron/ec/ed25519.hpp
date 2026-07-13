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
 * Ed25519 Curve definition and verification
 */

#ifndef __LIGETRON_EC_ED25519_HPP__
#define __LIGETRON_EC_ED25519_HPP__

#include "eddsa.hpp"
#include "detail/concepts.hpp"
#include "detail/elliptic_curve.hpp"
#include "detail/edward.hpp"
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/prime_field_uint256.h>
#include <ligetron/sha512.h>
#include <vector>
#include <string>


namespace ligetron::ec {


/// Ed25519 base field
struct ed25519_base_field:
        public ff::prime_field_uint256<ed25519_base_field> {

    static storage_type &modulus() {
        static storage_type m {
            "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
        };
        return m;
    }
};


/// Ed25519 scalar (order) field
struct ed25519_scalar_field:
        public ff::prime_field_uint256<ed25519_scalar_field> {

    static storage_type &modulus() {
        static storage_type m {
            "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
        };
        return m;
    }
};


struct ed25519_curve_def {
    using base_field_element = ff::field_element<ed25519_base_field>;
    using scalar_field_element = ff::field_element<ed25519_scalar_field>;
    
    /// Curve d cosntant
    static base_field_element &coeff_d() {
        static base_field_element res {
            "0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"
        };

        return res;
    }


    /// Curve generator point x coordinate
    static base_field_element &generator_x() {
        static base_field_element res {
            "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"
        };

        return res;
    }

    /// Curve generator point y coordinate
    static base_field_element &generator_y() {
        static base_field_element res {
            "0x6666666666666666666666666666666666666666666666666666666666666658"
        };

        return res;
    }

    struct generator_table:
            public detail::affine_generator_table_def<base_field_element, 8> {
        static table_t &table();
    };
};

static_assert(detail::EllipticCurveDefWithGeneratorTable<ed25519_curve_def>);

using ed25519_curve = detail::elliptic_curve <
    detail::edward_affine_curve <
        ed25519_curve_def
    >
>;

static_assert(detail::EllipticCurve<ed25519_curve>);


using ed25519_base_field_element = ed25519_curve::base_field_element;
using ed25519_scalar_field_element = ed25519_curve::scalar_field_element;
using ed25519_point = ed25519_curve::point;


/// Encodes ed25519 point
inline
std::array<unsigned char, 32> ed25519_point_encode(const ed25519_point &p) {
    std::array<bn254fr_class, 256> y_bits;
    p.y().to_bits(y_bits.data());

    std::array<bn254fr_class, 256> x_bits;
    p.x().to_bits(x_bits.data());

    std::array<bn254fr_class, 256> enc_bits;
    for (size_t i = 0; i < 255; ++i) {
        enc_bits[i] = y_bits[i];
        bn254fr_assert_equal(enc_bits[i].data(), y_bits[i].data());
    }

    bn254fr_lor_checked(const_cast<__bn254fr*>(enc_bits[255].data()),
                        y_bits[255].data(),
                        x_bits[0].data());

    uint256 enc;
    enc.from_bits(enc_bits.data());
    std::array<unsigned char, 32> enc_data;
    enc.to_bytes_little(enc_data.data());
    return enc_data;
}

/// Returns true if specified point is on curve
inline auto ed25519_is_point_on_curve(const ed25519_point &p) {
    return ed25519_curve::is_point_on_curve(p);
}

/// Performs Ed25519 verification
/// msg -- message
/// (r, s) -- signature (decoded r point and s value)
/// pub_key -- decoded public key point
inline bool ed25519_verify(const std::span<const unsigned char> &msg,
                           const ed25519_point &r,
                           const ed25519_scalar_field_element &s,
                           const ed25519_point &pub_key) {
    // verify that r and pub_key points are on curve
    bn254fr_assert_equal_u32(ed25519_curve::is_point_on_curve(r).data(), 1u);
    bn254fr_assert_equal_u32(ed25519_curve::is_point_on_curve(pub_key).data(), 1u);

    // encode r point
    auto r_enc = ed25519_point_encode(r);

    // encode public key
    auto pub_key_enc = ed25519_point_encode(pub_key);

    // concatenate r_enc + pub_key_enc + msg to make sha512 input
    std::vector<unsigned char> hash_input;
    hash_input.reserve(r_enc.size() + pub_key_enc.size() + msg.size());
    hash_input.insert(hash_input.end(), r_enc.begin(), r_enc.end());
    hash_input.insert(hash_input.end(), pub_key_enc.begin(), pub_key_enc.end());
    hash_input.insert(hash_input.end(), msg.begin(), msg.end());

    // compute sha512 hash
    std::array<unsigned char, 64> hash;
    ligetron_sha512(hash.data(), hash_input.data(), hash_input.size());

    // compute k scalar field element from hash
    ed25519_scalar_field_element k;
    k.import_bytes_little(std::span{hash.data(), 64});

    // verify eddsa equation
    return eddsa_verify<ed25519_curve>(k, r, s, pub_key);
}

/// Generates Ed25519 public key point from private key
inline ed25519_point
ed25519_pubkey_gen(const std::span<const unsigned char> &data) {
    assert(data.size() == 32);

    std::array<unsigned char, 64> hash{};
    ligetron_sha512(hash.data(), data.data(), data.size());

    // clamp lower 32 bytes
    hash[0] &= 248;
    hash[31] &= 63;
    hash[31] |= 64;

    ed25519_scalar_field_element key;
    key.import_bytes_little(std::span<const unsigned char>(hash.data(), 32));

    return eddsa_pubkey_gen<ed25519_curve>(key);
}

/// Generates 25519 encoded public key from private key
inline std::array<unsigned char, 32>
ed25519_pubkey_gen_encoded(const std::span<const unsigned char> &data) {
    return ed25519_point_encode(ed25519_pubkey_gen(data));
}


}


#endif // __LIGETRON_EC_ED25519_HPP__
