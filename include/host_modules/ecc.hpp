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

#include <gmpxx.h>
#include <host_modules/host_interface.hpp>
#include <iostream>
#include <unordered_map>
#include <util/log.hpp>

namespace ligero::vm {

// TODO: Unify with the SDK header
typedef enum ECCCurveType {
    ECCCurveType_P256      = 0x00000001,
    ECCCurveType_Secp256k1 = 0x00000002,
    ECCCurveType_Ed25519   = 0x00000003,
    ECCCurveType_Force32   = 0x7FFFFFFF
} ECCCurveType;

template <typename Context>
struct ecc_module : public host_module {
    using Self = ecc_module<Context>;
    using witness_type = typename Context::witness_type;
    typedef void (Self::*host_function_type)();

    static constexpr auto module_name = "ecc";

    struct affine_point {
        mpz_class x, y;
    };
    
    struct projective_point {
        mpz_class x, y, z;
    };

    ecc_module(Context* ctx) : ctx_(ctx) {}

    void scalar_decompose() {
        u32 num_k_bytes = ctx_->stack_pop().as_u32();
        u32 k_bytes_addr = ctx_->stack_pop().as_u32();
        u32 z_sgn_addr = ctx_->stack_pop().as_u32();
        u32 z_abs_addr = ctx_->stack_pop().as_u32();
        u32 x_sgn_addr = ctx_->stack_pop().as_u32();
        u32 x_abs_addr = ctx_->stack_pop().as_u32();
        u32 curve_type = ctx_->stack_pop().as_u32();

        mpz_class k, r;
        switch(curve_type) {
            case ECCCurveType_P256:
                r = p256_n_; break;
            case ECCCurveType_Secp256k1:
                r = secp256k1_n_; break;
            case ECCCurveType_Ed25519:
                r = ed25519_n_; break;
            default:
                LIGERO_LOG_FATAL << "Unexpected curve type: " << curve_type;
        }
        
        mpz_import(k.get_mpz_t(), num_k_bytes, -1, sizeof(u8), -1, 0,
                   ctx_->memory_data().data() + k_bytes_addr);

        /*
         * Perform partial Extended Euclidean algorithm with early stop
         * (r1 >= sqrt(r)) to find r1 < sqrt(r) and t1 < sqrt(r)
         */
        mpz_class r0 = r, s0 = 1, t0 = 0;
        mpz_class r1 = k, s1 = 0, t1 = 1;

        mpz_class limit;
        mpz_sqrt(limit.get_mpz_t(), r.get_mpz_t());

        mpz_class tmp;
        while (r1 >= limit) {
            mpz_class q = r0 / r1;

            tmp = r0 - q * r1;
            std::swap(r0, r1);
            std::swap(r1, tmp);

            tmp = s0 - q * s1;
            std::swap(s0, s1);
            std::swap(s1, tmp);

            tmp = t0 - q * t1;
            std::swap(t0, t1);
            std::swap(t1, tmp);
        }
        
        // Export r1 to x bytes addr
        ctx_->template memory_store<uint32_t>(x_sgn_addr, r1 >= 0);
        mpz_export(ctx_->memory_data().data() + x_abs_addr, nullptr, -1, 1, -1, 0, r1.get_mpz_t());
        ctx_->memory().mark_secret_n(x_sgn_addr, 4);
        ctx_->memory().mark_secret_n(x_abs_addr, 16);

        // Export t1 to z bytes addr
        ctx_->template memory_store<uint32_t>(z_sgn_addr, t1 >= 0);
        mpz_export(ctx_->memory_data().data() + z_abs_addr, nullptr, -1, 1, -1, 0, t1.get_mpz_t());
        ctx_->memory().mark_secret_n(z_sgn_addr, 4);
        ctx_->memory().mark_secret_n(z_abs_addr, 16);
    }

    projective_point p256_point_add(const projective_point& p1, const projective_point& p2) const {
        auto p256_mod = [this](mpz_class x) -> mpz_class {
            mpz_mod(x.get_mpz_t(), x.get_mpz_t(), p256_p_.get_mpz_t());
            return x;
        };

        const auto& [X1, Y1, Z1] = p1;
        const auto& [X2, Y2, Z2] = p2;

        mpz_class t0 = p256_mod(X1 * X2);
        mpz_class t1 = p256_mod(Y1 * Y2);
        mpz_class t2 = p256_mod(Z1 * Z2);
        mpz_class t3 = p256_mod(X1 + Y1);
        mpz_class t4 = p256_mod(X2 + Y2);
        t3 = p256_mod(t3 * t4);
        t4 = p256_mod(t0 + t1);
        t3 = p256_mod(t3 - t4);
        t4 = p256_mod(Y1 + Z1);
        mpz_class X3 = p256_mod(Y2 + Z2);
        t4 = p256_mod(t4 * X3);
        X3 = p256_mod(t1 + t2);
        t4 = p256_mod(t4 - X3);
        X3 = p256_mod(X1 + Z1);
        mpz_class Y3 = p256_mod(X2 + Z2);
        X3 = p256_mod(X3 * Y3);
        Y3 = p256_mod(t0 + t2);
        Y3 = p256_mod(X3 - Y3);
        mpz_class Z3 = p256_mod(p256_b_ * t2);
        X3 = p256_mod(Y3 - Z3);
        Z3 = p256_mod(X3 + X3);
        X3 = p256_mod(X3 + Z3);
        Z3 = p256_mod(t1 - X3);
        X3 = p256_mod(t1 + X3);
        Y3 = p256_mod(p256_b_ * Y3);
        t1 = p256_mod(t2 + t2);
        t2 = p256_mod(t1 + t2);
        Y3 = p256_mod(Y3 - t2);
        Y3 = p256_mod(Y3 - t0);
        t1 = p256_mod(Y3 + Y3);
        Y3 = p256_mod(t1 + Y3);
        t1 = p256_mod(t0 + t0);
        t0 = p256_mod(t1 + t0);
        t0 = p256_mod(t0 - t2);
        t1 = p256_mod(t4 * Y3);
        t2 = p256_mod(t0 * Y3);
        Y3 = p256_mod(X3 * Z3);
        Y3 = p256_mod(Y3 + t2);
        X3 = p256_mod(t3 * X3);
        X3 = p256_mod(X3 - t1);
        Z3 = p256_mod(t4 * Z3);
        t1 = p256_mod(t3 * t0);
        Z3 = p256_mod(Z3 + t1);
        return projective_point{std::move(X3), std::move(Y3), std::move(Z3)};
    }

    affine_point p256_scalar_mul(mpz_class s, affine_point P) const {
        projective_point acc{0, 1, 0};
        projective_point point{P.x, P.y, 1};
        for (int i = 255; i >= 0; --i) {
            acc = p256_point_add(acc, acc);
            if (mpz_tstbit(s.get_mpz_t(), i)) {
                acc = p256_point_add(acc, point);
            }
        }

        mpz_class inv;
        mpz_invert(inv.get_mpz_t(), acc.z.get_mpz_t(), p256_p_.get_mpz_t());
        acc.x = (acc.x * inv) % p256_p_;
        acc.y = (acc.y * inv) % p256_p_;
        return affine_point{ std::move(acc.x), std::move(acc.y) };
    }

    projective_point secp256k1_point_add(const projective_point& p1, const projective_point& p2) const {
        auto secp256k1_mod = [&](const mpz_class& x) -> mpz_class {
            mpz_class r;
            mpz_mod(r.get_mpz_t(), x.get_mpz_t(), secp256k1_p_.get_mpz_t());
            return r;
        };

        const auto& [X1, Y1, Z1] = p1;
        const auto& [X2, Y2, Z2] = p2;

        mpz_class t0 = secp256k1_mod(X1 * X2);
        mpz_class t1 = secp256k1_mod(Y1 * Y2);
        mpz_class t2 = secp256k1_mod(Z1 * Z2);
        mpz_class t3 = secp256k1_mod(X1 + Y1);
        mpz_class t4 = secp256k1_mod(X2 + Y2);
        t3 = secp256k1_mod(t3 * t4);
        t4 = secp256k1_mod(t0 + t1);
        t3 = secp256k1_mod(t3 - t4);
        t4 = secp256k1_mod(Y1 + Z1);
        
        mpz_class X3 = secp256k1_mod(Y2 + Z2);
        t4 = secp256k1_mod(t4 * X3);
        X3 = secp256k1_mod(t1 + t2);
        t4 = secp256k1_mod(t4 - X3);
        X3 = secp256k1_mod(X1 + Z1);
        
        mpz_class Y3 = secp256k1_mod(X2 + Z2);
        X3 = secp256k1_mod(X3 * Y3);
        Y3 = secp256k1_mod(t0 + t2);
        Y3 = secp256k1_mod(X3 - Y3);
        X3 = secp256k1_mod(t0 + t0);
        t0 = secp256k1_mod(X3 + t0);
        t2 = secp256k1_mod(secp256k1_b3_ * t2);
        
        mpz_class Z3 = secp256k1_mod(t1 + t2);
        t1 = secp256k1_mod(t1 - t2);
        Y3 = secp256k1_mod(secp256k1_b3_ * Y3);
        X3 = secp256k1_mod(t4 * Y3);
        t2 = secp256k1_mod(t3 * t1);
        X3 = secp256k1_mod(t2 - X3);
        Y3 = secp256k1_mod(Y3 * t0);
        t1 = secp256k1_mod(t1 * Z3);
        Y3 = secp256k1_mod(t1 + Y3);
        t0 = secp256k1_mod(t0 * t3);
        Z3 = secp256k1_mod(Z3 * t4);
        Z3 = secp256k1_mod(Z3 + t0);

        return {X3, Y3, Z3};
    }

    affine_point secp256k1_scalar_mul(mpz_class s, affine_point P) const {
        projective_point acc{0, 1, 0};
        projective_point point{P.x, P.y, 1};
        for (int i = 255; i >= 0; --i) {
            acc = secp256k1_point_add(acc, acc);
            if (mpz_tstbit(s.get_mpz_t(), i)) {
                acc = secp256k1_point_add(acc, point);
            }
        }

        mpz_class inv;
        mpz_invert(inv.get_mpz_t(), acc.z.get_mpz_t(), secp256k1_p_.get_mpz_t());
        acc.x = (acc.x * inv) % secp256k1_p_;
        acc.y = (acc.y * inv) % secp256k1_p_;
        return affine_point{ std::move(acc.x), std::move(acc.y) };
    }

    affine_point ed25519_point_add(const affine_point& p1, const affine_point& p2) const {
        auto ed25519_mod = [&](const mpz_class& x) -> mpz_class {
            mpz_class r;
            mpz_mod(r.get_mpz_t(), x.get_mpz_t(), ed25519_p_.get_mpz_t());
            return r;
        };
        auto x1y2 = ed25519_mod(p1.x * p2.y);
        auto x2y1 = ed25519_mod(p2.x * p1.y);
        auto y1y2 = ed25519_mod(p1.y * p2.y);
        auto x1x2 = ed25519_mod(p1.x * p2.x);
        auto x1x2y1y2 = ed25519_mod(x1x2 * y1y2);
        auto dxy = ed25519_mod(ed25519_d_ * x1x2y1y2);
        auto t1 = ed25519_mod(x1y2 + x2y1);
        auto t2 = ed25519_mod(1 + dxy);
        mpz_class t2_inv;
        mpz_invert(t2_inv.get_mpz_t(), t2.get_mpz_t(), ed25519_p_.get_mpz_t());
        auto x3 = ed25519_mod(t1 * t2_inv);
        auto t3 = ed25519_mod(y1y2 + x1x2);
        auto t4 = ed25519_mod(1 - dxy);
        mpz_class t4_inv;
        mpz_invert(t4_inv.get_mpz_t(), t4.get_mpz_t(), ed25519_p_.get_mpz_t());
        auto y3 = ed25519_mod(t3 * t4_inv);
        return affine_point{std::move(x3), std::move(y3)};
    }

    affine_point ed25519_scalar_mul(mpz_class s, affine_point point) const {
        affine_point acc{0, 1};
        for (int i = 255; i >= 0; --i) {
            acc = ed25519_point_add(acc, acc);
            if (mpz_tstbit(s.get_mpz_t(), i)) {
                acc = ed25519_point_add(acc, point);
            }
        }
        return affine_point{ std::move(acc.x), std::move(acc.y) };
    }

    void scalar_mul() {
        u32 num_s_bytes = ctx_->stack_pop().as_u32();
        u32 s_addr      = ctx_->stack_pop().as_u32();
        u32 p_addr      = ctx_->stack_pop().as_u32();
        u32 out_addr    = ctx_->stack_pop().as_u32();
        u32 curve_type  = ctx_->stack_pop().as_u32();
        
        size_t field_byte_size;
        switch (curve_type) {
            case ECCCurveType_P256:
            case ECCCurveType_Secp256k1:
            case ECCCurveType_Ed25519:
                field_byte_size = 32;
                break;
            default:
                LIGERO_LOG_FATAL << "Unexpected curve type " << curve_type;
        }
        
        mpz_class s, px, py;
        mpz_import(px.get_mpz_t(), field_byte_size, -1, sizeof(u8), -1, 0,
                   ctx_->memory_data().data() + p_addr);
        mpz_import(py.get_mpz_t(), field_byte_size, -1, sizeof(u8), -1, 0,
                   ctx_->memory_data().data() + p_addr + field_byte_size);

        mpz_import(s.get_mpz_t(), num_s_bytes, -1, sizeof(u8), -1, 0,
                   ctx_->memory_data().data() + s_addr);

        affine_point res;
        switch (curve_type) {
            case ECCCurveType_P256:
                res = p256_scalar_mul(s, {std::move(px), std::move(py)});
                break;
            case ECCCurveType_Secp256k1:
                res = secp256k1_scalar_mul(s, {std::move(px), std::move(py)});
                break;
            case ECCCurveType_Ed25519:
                res = ed25519_scalar_mul(s, {std::move(px), std::move(py)});
                break;
            default:
                LIGERO_LOG_FATAL << "Unexpected curve type " << curve_type;            
        }

        mpz_export(ctx_->memory_data().data() + out_addr,
                   nullptr, -1, 1, -1, 0, res.x.get_mpz_t());
        mpz_export(ctx_->memory_data().data() + out_addr + field_byte_size,
                   nullptr, -1, 1, -1, 0, res.y.get_mpz_t());

        // Mark output buffer as secrets
        ctx_->memory().mark_secret_n(out_addr, 2 * field_byte_size);
    }

    std::optional<affine_point> ed25519_point_decompress(const mpz_class& enc) const {
        // enc must be the little-endian integer value of the 32-byte encoding.
        // bit 255 is the x sign bit.
        const bool x0 = mpz_tstbit(enc.get_mpz_t(), 255) != 0;

        mpz_class y = enc;
        mpz_clrbit(y.get_mpz_t(), 255);

        // RFC 8032: reject if recovered y is not in F_p
        if (y >= ed25519_p_) {
            return std::nullopt;
        }

        mpz_class yy = (y * y) % ed25519_p_;
        mpz_class u = yy - 1;
        mpz_mod(u.get_mpz_t(), u.get_mpz_t(), ed25519_p_.get_mpz_t());

        mpz_class v = ed25519_d_ * yy + 1;
        mpz_mod(v.get_mpz_t(), v.get_mpz_t(), ed25519_p_.get_mpz_t());

        mpz_class v_inv;
        if (mpz_invert(v_inv.get_mpz_t(), v.get_mpz_t(), ed25519_p_.get_mpz_t()) == 0) {
            return std::nullopt;
        }

        mpz_class u_over_v = u * v_inv;
        mpz_mod(u_over_v.get_mpz_t(), u_over_v.get_mpz_t(), ed25519_p_.get_mpz_t());
        mpz_class exp = (ed25519_p_ + 3) / 8;
        mpz_class x;
        mpz_powm(x.get_mpz_t(), u_over_v.get_mpz_t(), exp.get_mpz_t(), ed25519_p_.get_mpz_t());
        mpz_class vxx = v * x * x;
        mpz_mod(vxx.get_mpz_t(), vxx.get_mpz_t(), ed25519_p_.get_mpz_t());
        mpz_class neg_u = -u;
        mpz_mod(neg_u.get_mpz_t(), neg_u.get_mpz_t(), ed25519_p_.get_mpz_t());

        if (vxx == u) {
            // x is already correct
        } else if (vxx == neg_u) {
            // x *= sqrt(-1) mod p
            mpz_class sqrt_m1_base = 2;
            mpz_class sqrt_m1_exp = (ed25519_p_ - 1) / 4;

            mpz_class sqrt_m1;
            mpz_powm(sqrt_m1.get_mpz_t(), sqrt_m1_base.get_mpz_t(), sqrt_m1_exp.get_mpz_t(),
                     ed25519_p_.get_mpz_t());

            x *= sqrt_m1;
            mpz_mod(x.get_mpz_t(), x.get_mpz_t(), ed25519_p_.get_mpz_t());

            // Verify again
            vxx = v * x * x;
            mpz_mod(vxx.get_mpz_t(), vxx.get_mpz_t(), ed25519_p_.get_mpz_t());

            if (vxx != u) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }

        // RFC 8032 special case:
        // x = 0 cannot have sign bit 1
        if (x == 0 && x0) {
            return std::nullopt;
        }

        // Choose the root whose LSB matches x0
        const bool x_is_odd = mpz_tstbit(x.get_mpz_t(), 0) != 0;
        if (x_is_odd != x0) {
            x = ed25519_p_ - x;
            mpz_mod(x.get_mpz_t(), x.get_mpz_t(), ed25519_p_.get_mpz_t());
        }

        return affine_point{x, y};
    }

    void point_decompress() {
        u32 enc_addr   = ctx_->stack_pop().as_u32();
        u32 y_addr     = ctx_->stack_pop().as_u32();
        u32 x_addr     = ctx_->stack_pop().as_u32();
        u32 curve_type = ctx_->stack_pop().as_u32();

        size_t field_byte_size = 32;
        
        mpz_class enc;
        mpz_import(enc.get_mpz_t(), field_byte_size, -1, sizeof(u8), -1, 0,
                   ctx_->memory_data().data() + enc_addr);

        auto errc = ctx_->backend().acquire_witness();
        *errc->value_ptr() = 0;
        switch(curve_type) {
            case ECCCurveType_Ed25519: {
                auto point = ed25519_point_decompress(enc);

                if (point) {
                    // std::cout << "x: " << (*point).x << std::endl;
                    // std::cout << "y: " << (*point).y << std::endl;
                    
                    mpz_export(ctx_->memory_data().data() + x_addr,
                               nullptr, -1, 1, -1, 0, (*point).x.get_mpz_t());
                    mpz_export(ctx_->memory_data().data() + y_addr,
                               nullptr, -1, 1, -1, 0, (*point).y.get_mpz_t());
                }
                else {
                    *errc->value_ptr() = EINVAL;
                }
                break;
            }
            default:
                LIGERO_LOG_FATAL << "Unexpected curve type " << curve_type;
        }

        ctx_->stack_push(std::move(errc));
        ctx_->memory().mark_secret_n(x_addr, field_byte_size);
        ctx_->memory().mark_secret_n(y_addr, field_byte_size);
    }

    exec_result call_host(address_t global_id, std::string_view name) override {
        (this->*call_lookup_table_[name])();
        return exec_ok();
    }

    void initialize() override {
        call_lookup_table_ = {
            {"scalar_decompose",  &Self::scalar_decompose },
            {"scalar_mul",        &Self::scalar_mul       },
            {"point_decompress",  &Self::point_decompress}
        };

        // P256 curve parameters
        p256_p_ = mpz_class("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
        p256_n_ = mpz_class("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        p256_b_ = mpz_class("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");

        // Secp256k1 curve parameters
        secp256k1_p_ = mpz_class("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
        secp256k1_n_ = mpz_class("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        secp256k1_b3_ = 21;  // b = 7

        // Ed25519 curve parameters
        ed25519_p_ = mpz_class("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
        ed25519_n_ = mpz_class("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
        ed25519_d_ = mpz_class("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3");
    }

    void finalize() override {}

protected:
    Context* ctx_;
    std::unordered_map<std::string_view, host_function_type> call_lookup_table_;

    mpz_class p256_p_, p256_n_, p256_b_;
    mpz_class secp256k1_p_, secp256k1_n_, secp256k1_b3_;
    mpz_class ed25519_p_, ed25519_n_, ed25519_d_;
};

} // namespace ligero::vm
