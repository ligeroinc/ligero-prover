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

#include <gmp.h>
#include <gmpxx.h>

namespace ligero::vm::ntt {

template <typename Fp, size_t Beta = 256>
struct ntt_context {
    constexpr static size_t beta = Beta;

    ntt_context() = default;
    // ntt_context(size_t N)
    //     : N_(N), log2N_(std::log2(N)), omegas_(N), omegas_inv_(N) { }

    void init(size_t N, const mpz_class& nth_root);
    void ComputeForward(Fp *out, const Fp *in);
    void ComputeInverse(Fp *out, const Fp *in);

protected:
    size_t N_ = 0, log2N_ = 0;
    std::vector<mpz_class> omegas_, omegas_inv_;
    mpz_class cpu_p_, cpu_2p_, N_inv_;
};

template <size_t Beta>
void mpz_montgomery_mul(mpz_class& out,
                        const mpz_class& x,
                        const mpz_class& y,
                        const mpz_class& p)
{
    mpz_class U = x * y;

    // out = U mod 2^beta (low part)
    mpz_fdiv_r_2exp(out.get_mpz_t(), U.get_mpz_t(), Beta);

    // Q = U.low * J mod 2^beta
    out *= params::bn254_montgomery_factor;
    mpz_fdiv_r_2exp(out.get_mpz_t(), out.get_mpz_t(), Beta);

    // H = Q * p / 2^beta
    out *= p;
    mpz_fdiv_q_2exp(out.get_mpz_t(), out.get_mpz_t(), Beta);

    // out = U.high - H + p, in [0, 2p) range
    mpz_fdiv_q_2exp(U.get_mpz_t(), U.get_mpz_t(), Beta);
    out = U - out + p;
}

uint32_t bit_reverse(uint32_t x, size_t bits) {
    x = ((x >> 1)  & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2)  & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4)  & 0x0f0f0f0fu) | ((x & 0x0f0f0f0fu) << 4);
    x = ((x >> 8)  & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
    x = ((x >> 16) & 0xffffu)     | ((x & 0xffffu)     << 16);
    return x >> (32 - bits);
}

template <typename Fp, size_t Beta>
void ntt_context<Fp, Beta>::init(size_t N, const mpz_class& nth_root) {
    N_     = N;
    log2N_ = std::log2(N);
    
    omegas_.resize(N);
    omegas_inv_.resize(N);
    
    cpu_p_  = Fp::modulus;
    cpu_2p_ = Fp::modulus * 2;

    // Precompute forward omega table
    for (size_t i = 0; i < N_; i++) {        
        mpz_powm_ui(omegas_[i].get_mpz_t(), nth_root.get_mpz_t(), i, cpu_p_.get_mpz_t());
        // w' = w * J mod p
        omegas_[i] <<= beta;
        mpz_mod(omegas_[i].get_mpz_t(), omegas_[i].get_mpz_t(), cpu_p_.get_mpz_t());
    }

    mpz_class inverse_root;
    mpz_invert(inverse_root.get_mpz_t(), nth_root.get_mpz_t(), cpu_p_.get_mpz_t());

    // Precompute inverse omega table
    for (size_t i = 0; i < N_; i++) {
        mpz_powm_ui(omegas_inv_[i].get_mpz_t(),
                    inverse_root.get_mpz_t(), i, cpu_p_.get_mpz_t());

        // w' = w * J mod p
        omegas_inv_[i] <<= beta;
        mpz_mod(omegas_inv_[i].get_mpz_t(), omegas_inv_[i].get_mpz_t(), cpu_p_.get_mpz_t());
    }

    // Precompute N ^ (-1)
    mpz_class degree = N;
    mpz_invert(N_inv_.get_mpz_t(), degree.get_mpz_t(), cpu_p_.get_mpz_t());
    
    N_inv_ = (N_inv_ << beta) % cpu_p_;
}


template <typename Fp, size_t Beta>
void ntt_context<Fp, Beta>::ComputeForward(Fp *out, const Fp *in) {
    
    for (uint32_t i = 0; i < N_; i++) {
        uint32_t reversed_i = bit_reverse(i, log2N_);

        if (i < reversed_i) {
            Fp v = in[i], rv = in[reversed_i];
            out[i] = rv;
            out[reversed_i] = v;
        }
    }

    // ------------------------------------------------------------

    mpz_class x, y, u, v;
    
    for (int iter = log2N_; iter >= 1; --iter) {
        const int M = 1 << iter;
        const int M2 = M >> 1;
        const int omega_stride = N_ >> iter;

        #pragma omp parallel for private(x, y, u, v)
        for (int i = 0; i < N_ / 2; i++) {
            const int group = i / M2;
            const int index = i % M2;
            const int k = group * M + index;

            x = out[k].data();
            y = out[k + M2].data();

            u = x + y;
            v = x - y + cpu_2p_;

            if (u > cpu_2p_) {
                u -= cpu_2p_;
            }
            
            x = omegas_[index * omega_stride];

            mpz_montgomery_mul<Beta>(v, v, x, cpu_p_);

            out[k]      = u;
            out[k + M2] = v;
        }
    }

    for (size_t i = 0; i < N_; i += 2) {
        x = out[i].data();
        y = out[i+1].data();

        u = x + y;
        v = x - y + cpu_2p_;
        
        if (u > cpu_2p_) u -= cpu_2p_;
        if (v > cpu_2p_) v -= cpu_2p_;
        if (u > cpu_p_)  u -= cpu_p_;
        if (v > cpu_p_)  v -= cpu_p_;

        out[i]   = u;
        out[i+1] = v;
    }
}


template <typename Fp, size_t Beta>
void ntt_context<Fp, Beta>::ComputeInverse(Fp *out, const Fp *in) {

    mpz_class x, y, w;
    
    for (size_t i = 0; i < N_; i += 2) {
        x = in[i].data();
        y = in[i+1].data();

        out[i].data()   = x + y;
        out[i+1].data() = x - y + cpu_2p_;
    }

    for (int iter = 2; iter <= log2N_; ++iter) {
        const int M = 1 << iter;
        const int M2 = M >> 1;
        const int omega_stride = N_ >> iter;

        #pragma omp parallel for private(x, y, w)
        for (size_t i = 0; i < N_ / 2; i++) {
            const int group = i / M2;
            const int index = i % M2;
            const int k = group * M + index;

            // Input in range (0, 4p]

            x = out[k].data();
            y = out[k + M2].data();
            w = omegas_inv_[index * omega_stride];

            mpz_montgomery_mul<Beta>(y, y, w, cpu_p_);

            if (x > cpu_2p_) {
                x -= cpu_2p_;
            }

            out[k].data()      = x + y;
            out[k + M2].data() = x - y + cpu_2p_;

            // output in range (0, 4p]
        }
    }

    // ------------------------------------------------------------
    
    for (uint32_t i = 0; i < N_; i++) {       
        uint32_t reversed_i = bit_reverse(i, log2N_);
        
        if (i < reversed_i) {
            std::swap(out[i], out[reversed_i]);
        }
    }

    for (uint32_t i = 0; i < N_; i++) {
        mpz_montgomery_mul<Beta>(out[i].data(), out[i].data(), N_inv_, cpu_p_);

        if (out[i].data() > cpu_p_) {
            out[i].data() -= cpu_p_;
        }
    }
}

}  // namespace ligero::vm::ntt
