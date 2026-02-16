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
#include <gmp.h>
#include <gmpxx.h>

namespace ligero::vm::zkp {

struct quadratic_slot;

enum class commit_status {
    not_a_witness = 0,
    linear_ready,
    quadratic_pending,
    quadratic_ready,
};

struct lazy_witness {
    lazy_witness() : val_(nullptr), rand_(nullptr), slot_(nullptr) { }
    lazy_witness(mpz_class *val, mpz_class *rand) : val_(val), rand_(rand), slot_(nullptr) { }

    lazy_witness(const lazy_witness&) = delete;
    lazy_witness& operator=(const lazy_witness&) = delete;

    [[nodiscard]] commit_status commit_notify();

    mpz_class* value_ptr()  { return val_;  }
    mpz_class* random_ptr() { return rand_; }

    const mpz_class* value_ptr()  const { return val_;  }
    const mpz_class* random_ptr() const { return rand_; }

    void value_ptr(mpz_class *ptr)  { val_ = ptr; }
    void random_ptr(mpz_class *ptr) { rand_ = ptr; }

    bool is_witness() const { return is_witness_; }
    void set_witness_status(bool status)   { is_witness_ = status; }

    bool  has_slot() const { return slot_; }
    quadratic_slot* slot_ptr()   { return slot_; }
    void  set_slot(quadratic_slot *slot, int offset) {
        slot_ = slot;
        slot_offset_ = offset;
    }

    void reset() {
        val_         = nullptr;
        rand_        = nullptr;
        slot_        = nullptr;
        slot_offset_ = -1;
        is_witness_  = false;
    }

protected:
    mpz_class* val_;
    mutable mpz_class* rand_;
    quadratic_slot* slot_ = nullptr;
    int slot_offset_      = -1;
    bool is_witness_      = false;
};

struct quadratic_slot {
    quadratic_slot()
        : witnesses_{ nullptr, nullptr, nullptr},
          ready_{ false, false, false }
        { }

    void reset() {
        for (int i = 0; i < 3; i++) {
            witnesses_[i] = nullptr;
            ready_[i] = false;
        }
    }

    bool is_ready() const {
        return ready_[0] && ready_[1] && ready_[2];
    }

    bool mark_ready(int offset) {
        assert(offset >= 0 && offset < 3);
        ready_[offset] = true;
        return is_ready();
    }

    lazy_witness* get_witnesses(size_t i) { return witnesses_[i]; }
    void set_witness(lazy_witness* wit, int offset) {
        witnesses_[offset] = wit;
    }

    // quadratic_slot* next() { return next_; }
    // const quadratic_slot* next() const { return next_; }

    // void next(quadratic_slot *n) { next_ = n; }

private:
    lazy_witness *witnesses_[3];
    bool ready_[3];
};


[[nodiscard]]
commit_status lazy_witness::commit_notify() {
    if (is_witness_) {
        if (slot_) {
            if (slot_->mark_ready(slot_offset_)) {
                return commit_status::quadratic_ready;
            }
            else {
                return commit_status::quadratic_pending;
            }
        }
        else {
            return commit_status::linear_ready;
        }
    }
    else {
        return commit_status::not_a_witness;
    }
}

}  // namespace ligero::vm::zkp
