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

#ifndef __LIGETRON_POSEIDON__
#define __LIGETRON_POSEIDON__

#include <ligetron/bn254fr_class.h>
#include <ligetron/vbn254fr_class.h>

namespace ligetron {

struct poseidon_permx5_254bit_5 {
    inline constexpr static size_t N = 1270;
    inline constexpr static size_t t = 5;
    inline constexpr static size_t n = N / t;
    inline constexpr static size_t R_F = 8;
    inline constexpr static size_t R_P = 60;

    static char const *ARC_literal[(R_F + R_P) * t];
    static char const *MDS_literal[t][t];
    static char const *MDS_Montgomery_literal[t][t];
};


struct poseidon_permx5_254bit_3 {
    inline constexpr static size_t N = 762;
    inline constexpr static size_t t = 3;
    inline constexpr static size_t n = N / t;
    inline constexpr static size_t R_F = 8;
    inline constexpr static size_t R_P = 57;

    static char const *ARC_literal[(R_F + R_P) * t];
    static char const *MDS_literal[t][t];
    static char const *MDS_Montgomery_literal[t][t];
};

// ------------------------------------------------------------

template <typename Param>
struct poseidon_context {
    inline static bn254fr_class ARC[(Param::R_F + Param::R_P) * Param::t] = {};
    inline static bn254fr_class MDS[Param::t * Param::t] = {};

    poseidon_context() { reset(); };

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
    }

    void digest_update(bn254fr_class& data) {
        // Absorb to the sponge
        addmod(state[curr_], state[curr_], data);

        ++curr_;

        if (curr_ >= Param::t) {
            internal_round_update();
            curr_ = 0;
        }
    }

    void digest_final() {
        if (curr_ != 0) {
            internal_round_update();
            curr_ = 0;
        }
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
                mulmod(tmp,
                             MDS[row * Param::t + col],
                             state[col]);
                addmod(state_new[row],
                             state_new[row],
                             tmp);
            }
        }

        for (int i = 0; i < Param::t; i++) {
            state[i] = state_new[i];
        }
    }

    void internal_round_update() {
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

    size_t curr_ = 0;

public:
    bn254fr_class state[Param::t];
};


// ------------------------------------------------------------

template <typename Param, bool useMontgomery = false>
struct poseidon_vec_context {
    inline static vbn254fr_constant ARC[(Param::R_F + Param::R_P) * Param::t] = {};
    inline static vbn254fr_constant MDS[Param::t * Param::t] = {};

    poseidon_vec_context() { reset(); }

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
    }

    void digest_update(const vbn254fr_class& data) {
        // Absorb to the sponge
        addmod(state[curr_], state[curr_], data);

        ++curr_;

        if (curr_ >= Param::t) {
            internal_round_update();
            curr_ = 0;
        }
    }

    void digest_final() {
        if (curr_ != 0) {
            internal_round_update();
            curr_ = 0;
        }
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

    void internal_round_update() {
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

    size_t curr_ = 0;
    vbn254fr_class state[Param::t];
};

} // namespace ligetron

#endif
