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
 * Poseidon-S: Solana `sol_poseidon`-compatible Poseidon-v1 hash over BN254 Fr.
 *
 * The underlying permutation is identical to <ligetron/poseidon.h>:
 * BN254 Fr field, x^5 S-box, R_F=8 full rounds, R_P=57 (t=3) or R_P=60 (t=5)
 * partial rounds, and the iden3/circomlib round constants and MDS matrix.
 * The constants used here are reused verbatim from poseidon_constant.cpp via
 * the parameter structs (poseidon_permx5_254bit_3, poseidon_permx5_254bit_5)
 * defined in <ligetron/poseidon.h> -- they are bit-identical to the
 * constants light-poseidon (which sol_poseidon dispatches to) uses.
 *
 * What differs from poseidon.h is the *sponge wrapper*:
 *
 *   poseidon.h (poseidon_context) -- true sponge:
 *     - Inputs absorbed into state[0..n-1]; capacity at state[n..t-1] = 0.
 *     - More than t inputs trigger additional permutations.
 *     - Output = state[0].
 *
 *   poseidon_s.h (poseidon_s_context) -- fixed-input compression function,
 *   matching light-poseidon's `Poseidon::<Fr>::new_circom(n)`:
 *     - Width t (= Param::t) is fixed; the hash takes exactly t-1 inputs.
 *     - Initial state = [domain_tag, in_0, in_1, ..., in_{t-2}].
 *     - domain_tag defaults to 0 (matching `new_circom`).
 *     - One permutation is run on digest_final().
 *     - Output = state[0].
 *
 * Calling digest_update() more than (Param::t - 1) times is a usage error;
 * setting a non-zero domain_tag will diverge from sol_poseidon.
 */

#ifndef __LIGETRON_POSEIDON_S__
#define __LIGETRON_POSEIDON_S__

#include <ligetron/bn254fr_class.h>
#include <ligetron/vbn254fr_class.h>
#include <ligetron/poseidon.h>

namespace ligetron {

template <typename Param>
struct poseidon_s_context {
    inline static bn254fr_class ARC[(Param::R_F + Param::R_P) * Param::t] = {};
    inline static bn254fr_class MDS[Param::t * Param::t] = {};

    poseidon_s_context() { reset(); };

    static void global_init() {
        for (int i = 0; i < Param::t; i++) {
            for (int j = 0; j < Param::t; j++) {
                MDS[i * Param::t + j] = Param::MDS_literal[i][j];
            }
        }

        for (int i = 0; i < Param::t * (Param::R_F + Param::R_P); i++) {
            ARC[i] = Param::ARC_literal[i];
        }
    }

    void reset() {
        for (int i = 0; i < Param::t; i++) {
            state[i].set_u32(0);
        }
        curr_ = 1;
    }

    void set_domain_tag(const bn254fr_class& tag) {
        state[0] = tag;
    }

    void digest_update(bn254fr_class& data) {
        addmod(state[curr_], state[curr_], data);
        ++curr_;
    }

    void digest_final() {
        permutation();
        curr_ = 1;
    }

protected:
    void perm(size_t &ARC_counter, bool full_round = true) {
        for (int i = 0; i < Param::t; i++) {
            addmod(state[i], state[i], ARC[ARC_counter++]);
        }

        const int num_s_box = full_round ? Param::t : 1;
        for (int i = 0; i < num_s_box; i++) {
            // x^5
            bn254fr_class square;

            mulmod(square, state[i], state[i]);
            mulmod(square, square, square);
            mulmod(state[i], square, state[i]);
        }

        bn254fr_class state_new[Param::t];
        bn254fr_class tmp;
        for (int row = 0; row < Param::t; row++) {
            for (int col = 0; col < Param::t; col++) {
                mulmod_constant(tmp,
                                state[col],
                                MDS[row * Param::t + col]);
                addmod(state_new[row],
                             state_new[row],
                             tmp);
            }
        }

        for (int i = 0; i < Param::t; i++) {
            state[i] = state_new[i];
        }
    }

    void permutation() {
        constexpr size_t R_f = Param::R_F / 2;

        size_t ARC_counter = 0;

        // First half full rounds
        for (int i = 0; i < R_f; i++)
            perm(ARC_counter, true);

        // R_P partial rounds
        for (int i = 0; i < Param::R_P; i++)
            perm(ARC_counter, false);

        // Last half full rounds
        for (int i = 0; i < R_f; i++)
            perm(ARC_counter, true);
    }

    size_t curr_ = 1;

public:
    bn254fr_class state[Param::t];
};


// ------------------------------------------------------------

template <typename Param, bool useMontgomery = false>
struct poseidon_s_vec_context {
    inline static vbn254fr_constant ARC[(Param::R_F + Param::R_P) * Param::t] = {};
    inline static vbn254fr_constant MDS[Param::t * Param::t] = {};

    poseidon_s_vec_context() { reset(); }

    static void global_init() {
        const auto* MDS_str = Param::MDS_literal;
        if constexpr (useMontgomery) {
            MDS_str = Param::MDS_Montgomery_literal;
        }
        for (int i = 0; i < Param::t; i++) {
            for (int j = 0; j < Param::t; j++) {
                vbn254fr_constant_set_str(&MDS[i * Param::t + j], MDS_str[i][j]);
            }
        }

        for (int i = 0; i < Param::t * (Param::R_F + Param::R_P); i++) {
            vbn254fr_constant_set_str(&ARC[i], Param::ARC_literal[i]);
        }
    }

    void reset() {
        for (int i = 0; i < Param::t; i++) {
            state[i].set_ui_scalar(0);
        }
        curr_ = 1;
    }

    void set_domain_tag(const vbn254fr_class& tag) {
        state[0] = tag;
    }

    void digest_update(const vbn254fr_class& data) {
        addmod(state[curr_], state[curr_], data);
        ++curr_;
    }

    void digest_final() {
        permutation();
        curr_ = 1;
    }

    void perm(size_t &ARC_counter, bool full_round = true) {
        for (int i = 0; i < Param::t; i++) {
            addmod_constant(state[i], state[i], ARC[ARC_counter++]);
        }

        int num_s_box = full_round ? Param::t : 1;
        vbn254fr_class square;
        for (int i = 0; i < num_s_box; i++) {
            // x^5
            mulmod(square, state[i], state[i]);
            mulmod(square, square, square);
            mulmod(state[i], square, state[i]);
        }

        vbn254fr_class state_new[Param::t];
        vbn254fr_class tmp;
        for (int row = 0; row < Param::t; row++) {
            for (int col = 0; col < Param::t; col++) {
                if constexpr (useMontgomery) {
                    mont_mul_constant(tmp,
                                      state[col],
                                      MDS[row * Param::t + col]);
                }
                else {
                    mulmod_constant(tmp,
                                    state[col],
                                    MDS[row * Param::t + col]);
                }
                addmod(state_new[row],
                       state_new[row],
                       tmp);
            }
        }

        for (int i = 0; i < Param::t; i++) {
            state[i] = state_new[i];
        }
    }

    void permutation() {
        constexpr size_t R_f = Param::R_F / 2;

        size_t ARC_counter = 0;

        // First half full rounds
        for (int i = 0; i < R_f; i++)
            perm(ARC_counter, true);

        // R_P partial rounds
        for (int i = 0; i < Param::R_P; i++)
            perm(ARC_counter, false);

        // Last half full rounds
        for (int i = 0; i < R_f; i++)
            perm(ARC_counter, true);
    }

    // ------------------------------------------------------------

    size_t curr_ = 1;
    vbn254fr_class state[Param::t];
};

} // namespace ligetron

#endif
