/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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

#include <host.hpp>
#include <zkp/finite_ring.hpp>
#include <zkp/gc.hpp>
#include <zkp/hash/rescue_prime_precomputed.hpp>

namespace ligero::vm::zkp {

using namespace expr_literals;

template <typename Context>
struct rescue_prime_module : virtual public host_module {
    using var = typename Context::var_type;
    using ring = typename Context::ring_type;

    static constexpr auto module_name = "hash";
    using hash_params = rescue_prime_params<12, 4, 128, 255086697644033ULL, 96757023244289ULL>;

    rescue_prime_module() = default;
    rescue_prime_module(Context *ctx) : ctx_(ctx){ }

    result_t call_host(std::string func, frame_ptr frame) override {
        auto* fp = static_cast<typename Context::frame_pointer>(frame.get());
        if (func == "rescue256_hash") {
            assert(fp->refs.size() == 3);
            assert(fp->arity == 0);
            rescue_XLIX_hash(static_cast<u32>(fp->refs[0].val()),
                             static_cast<u32>(fp->refs[1].val()),
                             static_cast<u64>(fp->refs[2].val()));
        }
        else {
            undefined();
        }
        
        return {};
    }

    void rescue_XLIX_hash(u32 out_ptr, u32 in_ptr, u64 size) {
        constexpr size_t m = hash_params::state_width;
        
        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& mem_ins = ctx_->store()->memorys[addr];
        u8 *mem = mem_ins.data.data();
        u64 *input_sequence = reinterpret_cast<u64*>(mem + in_ptr);

        u64 num_apply = size / hash_params::rate;
        u64 extra_elements = size % hash_params::rate;

        var zero = ctx_->eval_unsigned(0_expr);
        std::vector<var> state(m, zero);

        for (u64 k = 0; k < num_apply; k++) {
            for (u32 i = 0; i < hash_params::rate; i++) {
                var r = ctx_->make_var(ring(*input_sequence++));
                state[i] = ctx_->eval_unsigned(state[i] + r);
            }
            state = rescue_XLIX_permutation(state);
        }

        if (extra_elements) {
            u64 padding_size = hash_params::rate - extra_elements;
            
            for (u32 i = 0; i < extra_elements; i++) {
                var r = ctx_->make_var(ring(*input_sequence++));
                state[i] = ctx_->eval_unsigned(state[i] + r);
            }

            state[extra_elements] = ctx_->eval_unsigned(state[extra_elements] + 1);
            state = rescue_XLIX_permutation(state);
        }

        // Squeezing only the first 4 element to get a 256bit hash
        u64 *out_sequence = reinterpret_cast<u64*>(mem + out_ptr);
        for (size_t i = 0; i < 4; i++) {
            *out_sequence++ = static_cast<u64>(state[i].val());
        }
    }

    std::vector<var> rescue_XLIX_permutation(std::vector<var> state) {
        constexpr size_t m = hash_params::state_width;
        
        for (size_t round = 0; round < hash_params::num_rounds; round++) {
            // First compute the forward S-box (i.e. ()^alpha)
            for (size_t i = 0; i < m; i++) {
                state[i] = ctx_->eval_unsigned(state[i] * state[i] * state[i]);
            }

            // Then apply the MDS matrix by matrix-vector multiplication (state = MDS * state)
            {
                var zero = ctx_->eval_unsigned(0_expr);
                std::vector<var> tmp(m, zero);
                for (size_t row = 0; row < m; row++) {
                    for (size_t col = 0; col < m; col++) {
                        tmp[row] = ctx_->eval_unsigned(tmp[row] +
                                                      hash_params::MDS[row * m + col] *
                                                      state[col]);
                    }
                }
                state = tmp;
            }

            // Apply the round constants C
            for (size_t i = 0; i < m; i++) {
                state[i] = ctx_->eval_unsigned(state[i] + hash_params::C[round * 2 * m + i]);
            }

            // Inverse S-box
            for (size_t i = 0; i < m; i++) {
                ring si = static_cast<ring>(state[i].val());
                uint64_t si0 = hexl::PowMod(si[0], hash_params::alpha_inv[0], hash_params::p[0]);
                uint64_t si1 = hexl::PowMod(si[1], hash_params::alpha_inv[1], hash_params::p[1]);
                var si_inv = ctx_->make_var(ring{ si0, si1 });
                var si_inv_triple = ctx_->eval_unsigned(si_inv * si_inv * si_inv);
                ctx_->assert_equal(state[i], si_inv_triple);

                state[i] = si_inv;
            }

            // Apply MDS again
            {
                var zero = ctx_->eval_unsigned(0_expr);
                std::vector<var> tmp(m, zero);
                for (size_t row = 0; row < m; row++) {
                    for (size_t col = 0; col < m; col++) {
                        tmp[row] = ctx_->eval_unsigned(tmp[row] +
                                                      hash_params::MDS[row * m + col] *
                                                      state[col]);
                    }
                }
                state = tmp;
            }

            // Apply the round constants C again
            for (size_t i = 0; i < m; i++) {
                state[i] = ctx_->eval_unsigned(state[i] + hash_params::C[round * 2 * m + m + i]);
            }
        }
        
        return state;
    }

private:
    Context *ctx_ = nullptr;
};


}  // namespace ligero::vm::zkp
