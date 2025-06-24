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

#include <tuple>
#include <functional>
#include <iostream>
#include <util/recycle_pool.hpp>
#include <util/mpz_vector.hpp>
#include <util/csprng.hpp>
#include <zkp/backend/lazy_witness.hpp>

namespace ligero::vm::zkp {

template <typename Field, typename RandomPolicy>
struct witness_manager {
    using witness_row_type = std::pair<mpz_vector&, mpz_vector&>;

    struct mpz_recycler {
        void operator()(mpz_class& mpz) { mpz = 0u; }
    };

    struct slot_recycler {
        void operator()(quadratic_slot& slot) { slot.reset(); }
    };

    struct witness_recycler {
        void operator()(zkp::lazy_witness& wit) { wit.reset(); }
    };

    using mpz_pool_t     = recycle_pool<mpz_class, mpz_recycler>;
    using slot_pool_t    = recycle_pool<quadratic_slot, slot_recycler>;
    using witness_pool_t = recycle_pool<zkp::lazy_witness, witness_recycler>;

    witness_manager(size_t row_size, size_t padded_row_size)
        : row_size_(row_size),
          padded_row_size_(padded_row_size),
          /** The pool size is just a hint - the recycle pool will grow internally */
          mpz_pool_(padded_row_size * 6),
          witness_pool_(padded_row_size * 3),
          slot_pool_(padded_row_size)
        { }

    mpz_random_engine& encoding_random_engine()  { return encoding_random_engine_;  }
    mpz_random_engine& code_random_engine()      { return code_random_engine_;      }
    mpz_random_engine& linear_random_engine()    { return linear_random_engine_;    }
    mpz_random_engine& quadratic_random_engine() { return quadratic_random_engine_; }

    template <typename Func>
    witness_manager& register_linear_callback(Func&& func) {
        linear_callback_ = std::forward<Func>(func);
        return *this;
    }

    template <typename Func>
    witness_manager& register_quadratic_callback(Func&& func) {
        quadratic_callback_ = std::forward<Func>(func);
        return *this;
    }

    template <typename Func>
    witness_manager& register_mask_callback(Func&& func) {
        mask_callback_ = std::forward<Func>(func);
        return *this;
    }

    mpz_class* acquire_mpz() {
        return mpz_pool_.acquire();
    }

    void recycle_mpz(mpz_class *mpz) {
        mpz_pool_.recycle(mpz);
    }

    lazy_witness* acquire_witness() {
        auto *ins = acquire_instance();
        ins->set_witness_status(true);
        return ins;
    }

    lazy_witness* acquire_instance() {
        lazy_witness *wit = witness_pool_.acquire();
        mpz_class *val = mpz_pool_.acquire();

        wit->value_ptr(val);
        if constexpr (RandomPolicy::enable_linear_check) {
            assert(wit->random_ptr() == nullptr);
            mpz_class *rand = mpz_pool_.acquire();
            wit->random_ptr(rand);
        }

        assert(!wit->is_witness());
        return wit;
    }

    template <typename T>
    lazy_witness* acquire_witness(const T& v) {
        auto *wit = acquire_witness();
        *wit->value_ptr() = v;
        return wit;
    }

    void commit_release_witness(lazy_witness *wit) {
        commit_status status = wit->commit_notify();

        switch (status) {
            case commit_status::quadratic_pending:
                return;
            case commit_status::not_a_witness: {
                assert(wit->slot_ptr() == nullptr);
                if constexpr (RandomPolicy::enable_linear_check) {
                    assert(*wit->random_ptr() == 0);
                    recycle_mpz(wit->random_ptr());
                }
                else {
                    assert(wit->random_ptr() == nullptr);
                }
                mpz_pool_.recycle(wit->value_ptr());
                witness_pool_.recycle(wit);
                return;
            }
            case commit_status::linear_ready: {
                if (is_linear_full()) {
                    process_reset_linear_row();
                }

                linear_val_.push_back_swap(*wit->value_ptr());
                mpz_pool_.recycle(wit->value_ptr());

                if constexpr (RandomPolicy::enable_linear_check) {
                    assert(wit->random_ptr() != nullptr);
                    linear_random_.push_back_swap(*wit->random_ptr());
                    mpz_pool_.recycle(wit->random_ptr());
                }

                witness_pool_.recycle(wit);
                return;
            }
            case commit_status::quadratic_ready: {
                if (is_quadratic_full()) {
                    process_reset_quadratic_rows();
                }

                if (auto *slot = wit->slot_ptr()) {
                    for (int i = 0; i < 3; i++) {
                        auto *ws = slot->get_witnesses(i);
                        auto *v = ws->value_ptr();
                        quadratic_val_[i].push_back_swap(*v);
                        mpz_pool_.recycle(v);

                        /** These are still linear check, even in quadratic rows */
                        if constexpr (RandomPolicy::enable_linear_check) {
                            auto *r = ws->random_ptr();
                            assert(r != nullptr);
                            quadratic_random_[i].push_back_swap(*r);
                            mpz_pool_.recycle(r);
                        }

                        witness_pool_.recycle(ws);
                    }

                    slot_pool_.recycle(slot);
                }
                else {
                    std::cout << "Expect quadratic slot, get nullptr";
                    std::abort();
                }
            }
            default:
                break;
        }
    }

    bool is_linear_full() const {
        return linear_val_.size() >= row_size_;
    }

    bool is_quadratic_full() const {
        assert(quadratic_val_[0].size() == quadratic_val_[1].size());
        assert(quadratic_val_[1].size() == quadratic_val_[2].size());

        const size_t quad_size = quadratic_val_[0].size();
        return quad_size >= row_size_;
    }

    void process_reset_linear_row() {
        if (!linear_val_.empty()) {
            const size_t data_size       = linear_val_.size();
            const size_t pad_zero_size   = row_size_ - data_size;
            const size_t pad_random_size = padded_row_size_ - row_size_;
            linear_counter_ += data_size;

            linear_val_.push_back_zeros(pad_zero_size);
            pad_encoding_random(linear_val_, pad_random_size);
            assert(linear_val_.size() == padded_row_size_);

            if constexpr (RandomPolicy::enable_linear_check) {
                linear_random_.push_back_zeros(pad_zero_size + pad_random_size);
                assert(linear_random_.size() == padded_row_size_);
            }

            // std::cout << "linear row: ";
            // for (size_t i = 0; i < padded_row_size_; i++) {
            //     std::cout << linear_val_[i] << " ";
            // }
            // std::cout << std::endl;

            linear_callback_(witness_row_type{linear_val_, linear_random_});

            linear_val_.clear();
            linear_random_.clear();

            assert(linear_val_.size() == 0);
            assert(linear_random_.size() == 0);
        }
    }

    void process_reset_quadratic_rows() {
        if (!quadratic_val_[0].empty()) {
            const size_t data_size       = quadratic_val_[0].size();
            const size_t pad_zero_size   = row_size_ - data_size;
            const size_t pad_random_size = padded_row_size_ - row_size_;
            quadratic_counter_ += data_size;

            for (size_t k = 0; k < 3; k++) {
                quadratic_val_[k].push_back_zeros(pad_zero_size);

                pad_encoding_random(quadratic_val_[k], pad_random_size);
                assert(quadratic_val_[k].size() == padded_row_size_);

                if constexpr (RandomPolicy::enable_linear_check) {
                    quadratic_random_[k].push_back_zeros(pad_zero_size + pad_random_size);
                    assert(quadratic_random_[k].size() == padded_row_size_);
                }

                // std::cout << "quad row " << k << ": ";
                // for (size_t i = 0; i < padded_row_size_; i++) {
                //     std::cout << quadratic_val_[k][i] << " ";
                // }
                // std::cout << std::endl;
            }

            quadratic_callback_(witness_row_type{quadratic_val_[0], quadratic_random_[0]},
                                witness_row_type{quadratic_val_[1], quadratic_random_[1]},
                                witness_row_type{quadratic_val_[2], quadratic_random_[2]});

            for (int i = 0; i < 3; i++) {
                quadratic_val_[i].clear();
                quadratic_random_[i].clear();

                assert(quadratic_val_[i].size() == 0);
                assert(quadratic_random_[i].size() == 0);
            }
        }
    }

    void process_masks() {
        /// Generate a mask for code test such that [0, l) are all randoms
        /// [l, k) are all 0s
        assert(quadratic_val_[0].empty());
        pad_encoding_random(quadratic_val_[0], row_size_);
        quadratic_val_[0].push_back_zeros(padded_row_size_ - row_size_);

        /// Generate a mask for linear test such that [0, l) add up to 0
        /// and [l, 2k) are randoms
        /// Pad the first 2l position with [0, random, 0, random...] pattern
        /// such that when decode with 2k-point NTT the first l position are 0s
        assert(quadratic_val_[1].empty());

        for (size_t i = 0; i < row_size_ - 1; i++) {
            quadratic_val_[1].push_back_zeros(1);
            pad_encoding_random(quadratic_val_[1], 1);
        }

        mpz_class *sum = acquire_mpz();
        for (size_t i = 0; i < 2 * (row_size_ - 1); i++) {
            /// Add up all odd indexes
            if (i & 1) {
                Field::addmod(*sum, *sum, quadratic_val_[1][i]);
            }
        }
        Field::negate(*sum, *sum);

        quadratic_val_[1].push_back_zeros(1);
        quadratic_val_[1].push_back_swap(*sum);
        recycle_mpz(sum);

        pad_encoding_random(quadratic_val_[1], 2 * (padded_row_size_ - row_size_));

        /// Generate a mask for quadratic test such that [0, l) are 0
        /// and [l, 2k) are randoms
        assert(quadratic_val_[2].empty());

        /// Pad the first 2l position with [0, random, 0, random...]
        /// such that when decode with 2k-point NTT the first l position are 0s
        for (size_t i = 0; i < row_size_; i++) {
            quadratic_val_[2].push_back_zeros(1);
            pad_encoding_random(quadratic_val_[2], 1);
        }
        pad_encoding_random(quadratic_val_[2], 2 * (padded_row_size_ - row_size_));

        mask_callback_(quadratic_val_[0], quadratic_val_[1], quadratic_val_[2]);

        quadratic_val_[0].clear();
        quadratic_val_[1].clear();
        quadratic_val_[2].clear();
    }

    witness_manager& pad_encoding_random(mpz_vector& vec, size_t pad_random_size) {
        if constexpr (RandomPolicy::pad_encoding_random) {
            auto *rand = acquire_mpz();
            for (size_t i = 0; i < pad_random_size; i++) {
                Field::generate_random(*rand, encoding_random_engine_);
                vec.push_back(*rand);
            }
            recycle_mpz(rand);
        }
        else {
            vec.push_back_zeros(pad_random_size);
        }
        return *this;
    }

    void generate_code_random(mpz_class& out) {
        if constexpr (RandomPolicy::enable_code_check) {
            Field::generate_random(out, code_random_engine_);
        }
    }

    void generate_linear_random(mpz_class& out) {
        if constexpr (RandomPolicy::enable_linear_check) {
            Field::generate_random(out, linear_random_engine_);
        }
    }

    void generate_quadratic_random(mpz_class& out) {
        if constexpr (RandomPolicy::enable_quadratic_check) {
            Field::generate_random(out, quadratic_random_engine_);
        }
    }

    witness_manager& witness_add_random(lazy_witness& wit, const mpz_class& random) {
        if constexpr (RandomPolicy::enable_linear_check) {
            assert(wit.random_ptr() != nullptr);
            // std::cout << "random: +" << random << " to: " << *wit.value_ptr() << std::endl;
            Field::addmod(*wit.random_ptr(), *wit.random_ptr(), random);
        }
        return *this;
    }

    witness_manager& witness_sub_random(lazy_witness& wit, const mpz_class& random) {
        if constexpr (RandomPolicy::enable_linear_check) {
            assert(wit.random_ptr() != nullptr);
            // std::cout << "random: -" << random << " to: " << *wit.value_ptr() << std::endl;
            Field::submod(*wit.random_ptr(), *wit.random_ptr(), random);
        }
        return *this;
    }

    witness_manager& constsum_add(const mpz_class& random) {
        if constexpr (RandomPolicy::enable_linear_check) {
            Field::addmod(constant_sum_, constant_sum_, random);
        }
        return *this;
    }

    witness_manager& constsum_sub(const mpz_class& random) {
        if constexpr (RandomPolicy::enable_linear_check) {
            Field::submod(constant_sum_, constant_sum_, random);
        }
        return *this;
    }

    mpz_class constsum() const { return constant_sum_; }

    lazy_witness* clone_witness(lazy_witness& wit) {
        lazy_witness *cloned = acquire_witness(*wit.value_ptr());
        constrain_equal(wit, *cloned);
        return cloned;
    }

    template <typename T>
    witness_manager& constrain_constant(lazy_witness& k, const T& v) {
        mpz_class *rand = acquire_mpz();
        mpz_class *tmp = acquire_mpz();

        generate_linear_random(*rand);
        witness_add_random(k, *rand);

        mpz_assign(*tmp, v);
        assert(*k.value_ptr() == *tmp);

        Field::mulmod(*tmp, *tmp, *rand);
        constsum_sub(*tmp);

        recycle_mpz(tmp);
        recycle_mpz(rand);
        return *this;
    }

    witness_manager& constrain_constant(lazy_witness& k) {
        return constrain_constant(k, *k.value_ptr());
    }

    witness_manager& constrain_equal(lazy_witness& a, lazy_witness& b) {
        assert(*a.value_ptr() == *b.value_ptr());

        mpz_class *rand = acquire_mpz();
        generate_linear_random(*rand);
        witness_add_random(a, *rand);
        witness_sub_random(b, *rand);
        recycle_mpz(rand);
        return *this;
    }

    witness_manager& constrain_bit(lazy_witness *b) {
        assert(*b->value_ptr() == 0 || *b->value_ptr() == 1);

        auto *w1 = clone_witness(*b);
        auto *w2 = clone_witness(*b);

        constrain_quadratic(b, w1, w2);

        commit_release_witness(w1);
        commit_release_witness(w2);
        return *this;
    }

    witness_manager&
    constrain_linear(const mpz_class& rand,
                     lazy_witness& c, lazy_witness& a, lazy_witness& b) {
        witness_add_random(a, rand);
        witness_add_random(b, rand);
        witness_sub_random(c, rand);
        return *this;
    }

    witness_manager&
    constrain_linear(lazy_witness& c, lazy_witness& a, lazy_witness& b) {
        mpz_class *rand = acquire_mpz();
        generate_linear_random(*rand);
        constrain_linear(*rand, c, a, b);
        recycle_mpz(rand);
        return *this;
    }

    template <typename T>
    witness_manager&
    constrain_quadratic_constant(lazy_witness& c, lazy_witness& a, const T& k) {
        mpz_class *rand = acquire_mpz();
        generate_linear_random(*rand);
        witness_add_random(c, *rand);

        mpz_class *tmp = acquire_mpz();
        Field::mulmod(*tmp, *rand, k);
        witness_sub_random(a, *tmp);

        recycle_mpz(tmp);
        recycle_mpz(rand);
        return *this;
    }

    witness_manager&
    constrain_quadratic(lazy_witness *c, lazy_witness *a, lazy_witness *b) {
        auto* slot = slot_pool_.acquire();

        lazy_witness *arr[3] = { a, b, c };

        for (int i = 0; i < 3; i++) {
            if (arr[i]->has_slot()) {
                lazy_witness *tmp = clone_witness(*arr[i]);
                tmp->set_slot(slot, i);
                slot->set_witness(tmp, i);
                commit_release_witness(tmp);
            }
            else {
                arr[i]->set_slot(slot, i);
                slot->set_witness(arr[i], i);
            }
        }
        return *this;
    }

    void finalize() {
        process_reset_linear_row();
        process_reset_quadratic_rows();

        /// Add masks to the witness matrix
        process_masks();

        std::cout << "Num Linear constraints:             "
                  << linear_counter_ << std::endl;
        std::cout << "Num quadratic constraints:          "
                  << quadratic_counter_ << std::endl;

        assert(witness_pool_.in_use_size() == 0);
    }

private:
    size_t row_size_, padded_row_size_;

    mpz_random_engine encoding_random_engine_;
    mpz_random_engine code_random_engine_;
    mpz_random_engine linear_random_engine_;
    mpz_random_engine quadratic_random_engine_;

    mpz_pool_t     mpz_pool_;
    slot_pool_t    slot_pool_;
    witness_pool_t witness_pool_;

    size_t linear_counter_    = 0;
    size_t quadratic_counter_ = 0;

    std::function<void(witness_row_type)> linear_callback_;
    std::function<void(witness_row_type, witness_row_type, witness_row_type)> quadratic_callback_;
    std::function<void(mpz_vector&, mpz_vector&, mpz_vector&)> mask_callback_;

    mpz_class constant_sum_;
    mpz_vector linear_val_, linear_random_;
    mpz_vector quadratic_val_[3];
    mpz_vector quadratic_random_[3];
};


}  // namespace ligero::vm
