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

#include <array>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <span>
#include <vector>

#include <ligetron/api.h>
#include <ligetron/bn254fr_bigint.hpp>
#include <ligetron/bn254fr_class.h>
#include <ligetron/ecc/curves/ed25519.hpp>
#include <ligetron/sha2.h>
#include <ligetron/uint256_cpp.h>

namespace ligetron::ecc {

/*
 * EdDSA instantiation parameters fixed by RFC 8032 (EdDSA) document per curve.
 *
 * Only Ed25519 is specialized today. Ed448 would need SHAKE256 with a 114-byte output and a
 * different pruning rule (low two bits for cofactor 4, high bit at 447 of a 57-byte buffer),
 * so Ed448 is currently documented here only as the contrast that shows which constants are
 * genuinely per-curve, not as a curve this header could serve today.
 */
template <typename Curve>
struct eddsa_params;

template <>
struct eddsa_params<curves::ed25519> {
    using curve_type = curves::ed25519;

    /// RFC 8032's b/8: the width of a point encoding, of a secret seed, and of each half of a
    /// signature. Deliberately not derived from the base field -- the two coincide at 32 for
    /// Ed25519 (b = 256), but Ed448 has a 56-byte field and a 57-byte encoding (b = 456).
    static constexpr size_t encoded_bytes = 32;

    /// H() for Ed25519 is plain SHA-512 (RFC 8032 section 5.1),
    /// used both to derive the challenge scalar and to expand the secret seed.
    static constexpr size_t hash_bytes = 64;

    static void hash(std::span<unsigned char, hash_bytes> out,
                     std::span<const unsigned char> in) {
        ligetron_sha2_512(out.data(), in.data(), in.size());
    }

    /// dom(): the domain-separation prefix hashed ahead of R || A || M. Empty for pure
    /// Ed25519, which is the exception rather than the rule -- Ed25519ctx and Ed25519ph
    /// prepend dom2, and Ed448 always prepends dom4("SigEd448" || phflag || len(ctx) || ctx).
    static std::span<const unsigned char> domain_prefix() { return {}; }

    /// RFC 8032 Section 5.1.5 step 2, "prune the buffer":
    /// clear the low three bits so the scalar is a multiple of the cofactor 8,
    /// clear the top bit, and set the second-highest. Operates on the low b/8 bytes
    /// of the expanded seed, not on the scalar field width.
    static void clamp_scalar(std::span<unsigned char, encoded_bytes> s) {
        constexpr size_t hi = encoded_bytes - 1;
        s[0]  &= 248;
        s[hi] &= 63;
        s[hi] |= 64;
    }
};

/*
 * Generic EdDSA verifier. The curve supplies the arithmetic; `eddsa_params<Curve>` above
 * supplies the wire parameters fixed by RFC 8032 per curve.
 */
template <typename Curve>
struct eddsa_context {
    using curve_type        = Curve;
    using params            = eddsa_params<curve_type>;

    static_assert(params::hash_bytes > 0,
                  "eddsa_context<Curve> needs an eddsa_params<Curve> specialization");

    using base_field_type   = typename curve_type::base_field_type;
    using scalar_field_type = typename curve_type::scalar_field_type;
    using point_type        = typename curve_type::point_type;

    // Widths of the curve's own arithmetic.
    static constexpr size_t base_field_bytes    = base_field_type::num_rounded_bits / 8;
    static constexpr size_t scalar_field_bytes  = scalar_field_type::num_rounded_bits / 8;

    // Widths of the wire format, all b/8 in RFC 8032's notation. These come from the curve
    // rather than from `base_field_bytes`: the two agree for Ed25519 but not for Ed448, whose
    // field is 56 bytes and whose encoding is 57.
    static constexpr size_t encoded_point_bytes = params::encoded_bytes;
    static constexpr size_t pubkey_bytes        = encoded_point_bytes;
    static constexpr size_t signature_bytes     = 2 * encoded_point_bytes;
    static constexpr size_t seed_bytes          = encoded_point_bytes;
    static constexpr size_t hash_bytes          = params::hash_bytes;

    /// RFC 8032's b. The encoding is b bits: y in bits 0..b-2, zero-padded, and the sign of x
    /// in bit b-1.
    static constexpr size_t encoded_point_bits = 8 * encoded_point_bytes;

    /// How many entries `to_bits` writes for a base field element.
    ///
    /// This is a property of the *field backend*, not of the curve's EdDSA parameters, which
    /// is why it comes from `base_field_type` rather than from `eddsa_params`.
    static constexpr size_t field_storage_bits = base_field_type::num_rounded_bits;

    /// `point_encode` and `point_decompress` below decompose the coordinates through the
    /// base field's own bit width, so the encoding width has to match it.
    /// Both `encoded_point_bit` and `field_storage_bits` are 256 for Ed25519 on prime_field_uint256.
    /// Ed448 would not fit: a 456-bit encoding over a 448-bit field stored in a wider policy.
    static_assert(encoded_point_bits == field_storage_bits,
                  "encoding width must match base field's bit width");

    /// Binds the context to a compressed public key received from the wire. The key is
    /// untrusted: `point_decompress` establishes whether it is a well-formed curve point, and
    /// that verdict gates every `verify()` result.
    eddsa_context(std::span<const std::byte, pubkey_bytes> pk) : enc_pubkey_bytes_{} {
        std::memcpy(enc_pubkey_bytes_.data(), pk.data(), pk.size());

        init_modulus();
        pubkey_valid_ = point_decompress(pubkey_, pk);
    }

    bn254fr_class point_decompress(point_type& out,
                                   std::span<const std::byte, encoded_point_bytes> bytes) {
        unsigned char x_bytes[base_field_bytes]{}, y_bytes[base_field_bytes]{};
        bn254fr_class errc =
            ecc_point_decompress(curve().curve_type(), x_bytes, y_bytes, bytes.data());

        // Build constraints after decompressing the point by showing:
        //   - (x, y) is on curve
        //   - 0 <= x, y < p
        //   - encoding[b-1] == x[0] && encoding[0..b-2] == y[0..b-2]
        uint256 enc_storage, x_storage, y_storage;
        enc_storage.set_bytes_little(reinterpret_cast<const unsigned char*>(bytes.data()), encoded_point_bytes);
        x_storage.set_bytes_little(x_bytes, base_field_bytes);
        y_storage.set_bytes_little(y_bytes, base_field_bytes);

        bn254fr_class enc_bits[field_storage_bits], x_bits[field_storage_bits],
                      y_bits[field_storage_bits];
        enc_storage.to_bits(enc_bits);
        x_storage.to_bits(x_bits);
        y_storage.to_bits(y_bits);

        bn254fr_class bit_eq;
        bn254fr_eq_checked(bit_eq.data(), x_bits[0].data(),
                           enc_bits[encoded_point_bits - 1].data());
        for (size_t i = 0; i < encoded_point_bits - 1; i++) {
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

    /// The compressed public key this context verifies against: the wire bytes for the
    /// constructor above, the derived encoding for `from_seed`. Assert it against a public
    /// input to prove ownership of the seed without deriving the key a second time.
    std::array<std::byte, pubkey_bytes> encoded_pubkey() const { return enc_pubkey_bytes_; }

    bn254fr_class verify(std::span<const std::byte, signature_bytes> sig,
                         std::span<const std::byte> msg) {
        // RFC 8032 section 3.4: a signature is ENC(R) || S, each exactly b/8 bytes.
        auto R_bytes = sig.template first<encoded_point_bytes>();
        auto S_bytes = sig.template subspan<encoded_point_bytes, encoded_point_bytes>();

        point_type R;
        auto R_valid = point_decompress(R, R_bytes);
        
        // Check imported S is in range [1, n-1], otherwise fail
        bn254fr_bigint upper_bound, s_storage;
        auto order_bytes = curve().order_bytes();
        upper_bound.set_bytes_big(reinterpret_cast<const unsigned char*>(order_bytes.data()),
                                  order_bytes.size());
        s_storage.set_bytes_little(reinterpret_cast<const unsigned char*>(S_bytes.data()),
                                   S_bytes.size());

        bn254fr_class s_valid = bn254fr_bigint::lt(s_storage, upper_bound);
        scalar_field_type s{s_storage};

        // Challenge scalar k = H(dom || R || A || M), reduced mod the group order on import.
        // Both H and dom belong to the curve: Ed25519 uses SHA-512 with no prefix, Ed448
        // SHAKE256 with dom4.
        const auto   dom             = params::domain_prefix();
        const size_t hash_input_size = dom.size() + 2 * encoded_point_bytes + msg.size();
        std::vector<unsigned char> input(hash_input_size);
        unsigned char digest[hash_bytes]{};

        size_t off = 0;
        if (!dom.empty()) {
            std::memcpy(input.data() + off, dom.data(), dom.size());
            off += dom.size();
        }
        std::memcpy(input.data() + off, R_bytes.data(), encoded_point_bytes);
        off += encoded_point_bytes;
        std::memcpy(input.data() + off, enc_pubkey_bytes_.data(), encoded_point_bytes);
        off += encoded_point_bytes;
        std::memcpy(input.data() + off, msg.data(), msg.size());
        params::hash(digest, std::span<const unsigned char>{input.data(), hash_input_size});

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

    /// Encodes a point into its compressed form: y little-endian, with the low bit of x
    /// folded into the top bit (RFC 8032 section 5.1.2). Inverse of `point_decompress`.
    static std::array<std::byte, encoded_point_bytes> point_encode(const point_type& p) {
        bn254fr_class x_bits[field_storage_bits], y_bits[field_storage_bits],
                      enc_bits[field_storage_bits];
        p.x.to_bits(x_bits);
        p.y.to_bits(y_bits);

        for (size_t i = 0; i < encoded_point_bits - 1; ++i) {
            enc_bits[i] = y_bits[i];
        }

        // y < p < 2^(b-1), so bit b-1 of y is always zero and the OR just deposits the sign
        // of x there.
        bn254fr_lor_checked(enc_bits[encoded_point_bits - 1].data(),
                            y_bits[encoded_point_bits - 1].data(), x_bits[0].data());

        uint256 enc;
        enc.from_bits(enc_bits);

        std::array<std::byte, encoded_point_bytes> out{};
        enc.to_bytes_little(reinterpret_cast<unsigned char*>(out.data()));
        return out;
    }

    /// Derives the key pair from a secret seed per RFC 8032
    /// and binds the context to the derived public key
    static eddsa_context from_seed(std::span<const std::byte, seed_bytes> seed) {
        unsigned char h[hash_bytes]{};
        params::hash(h, std::span<const unsigned char>{
                            reinterpret_cast<const unsigned char*>(seed.data()), seed.size()});

        params::clamp_scalar(
            std::span<unsigned char, encoded_point_bytes>{h, encoded_point_bytes});

        scalar_field_type s;
        s.import_bytes_little(std::span<const unsigned char>{h, encoded_point_bytes});
        
        const point_type pk = curve().scalar_mul_generator(s);

        return eddsa_context{pk, point_encode(pk), curve().on_curve(pk)};
    }

private:
    /// Binds an already-derived point to its canonical encoding. `valid` is the caller's
    /// well-formedness verdict for `pk`; it gates every `verify()` result exactly as the
    /// wire-key path's `point_decompress` verdict does.
    eddsa_context(const point_type& pk,
                  const std::array<std::byte, pubkey_bytes>& enc,
                  const bn254fr_class& valid)
        : enc_pubkey_bytes_{enc}, pubkey_{pk}, pubkey_valid_{valid} {
        init_modulus();
    }

    /// Loads the base field modulus used by `point_decompress`'s range checks. Needed on both
    /// construction paths: `verify()` decompresses R even when the public key was derived.
    void init_modulus() {
        auto p_view = curve().base_field_bytes().data();
        bn_p_.set_bytes_big(reinterpret_cast<const unsigned char*>(p_view), base_field_bytes);
    }

    static const curve_type& curve() {
        static curve_type c;
        return c;
    }

    bn254fr_bigint bn_p_;
    std::array<std::byte, pubkey_bytes> enc_pubkey_bytes_; 
    point_type pubkey_;
    bn254fr_class pubkey_valid_;
};

} // namespace ligetron::ecc
