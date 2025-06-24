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

#include <cassert>
#include <vector>
#include <gmp.h>
#include <gmpxx.h>

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/split_member.hpp>

namespace ligero::vm {

struct mpz_vector {

    mpz_vector() : storage_(), size_(0) { }
    mpz_vector(size_t n) : storage_(n), size_(n) { }

    template <typename T>
    mpz_vector(size_t n, const T& v) : storage_(n, v), size_(n) { }

    size_t size() const { return size_; }
    size_t capacity() const { return storage_.size(); }
    bool empty() const { return !size_; }

    void reserve(size_t n) { storage_.reserve(n); }

    void resize(size_t n) {
        if (n >= capacity()) {
            storage_.resize(n);
        }
        size_ = n;
    }

    mpz_class& operator[](size_t idx) { return storage_[idx]; }
    const mpz_class& operator[](size_t idx) const { return storage_[idx]; }

    auto begin()       { return storage_.begin(); }
    auto begin() const { return storage_.begin(); }

    auto end()       { return storage_.begin() + size(); }
    auto end() const { return storage_.begin() + size(); }

    void clear() {
        for (size_t i = 0; i < size_; i++) {
            storage_[i] = 0u;
        }
        size_ = 0;
    }

    void push_back(const mpz_class& v) {
        if (size_ < capacity()) {
            storage_[size_++] = v;
        }
        else {
            storage_.push_back(v);
            ++size_;
        }
    }

    void push_back_zeros(size_t n) {
        for (size_t i = 0; i < n; i++) {
            if (size_ < capacity()) {
                ++size_;
            }
            else {
                storage_.emplace_back();
                ++size_;
            }
        }
    }

    void push_back_swap(mpz_class& v) {
        if (size_ < capacity()) {
            storage_[size_++].swap(v);
        }
        else {
            auto& ref = storage_.emplace_back();
            ++size_;
            ref.swap(v);
        }
    }

    /**
     * @brief  Export every mpz_class in `storage_` into `buf`.
     *
     * @param buf         Pointer to a pre-allocated output buffer.
     * @param buf_size    Capacity of the buffer, measured in **limbs**, not bytes.
     *                    Must satisfy:
     *                      self.size() * limb_count <= buf_size
     * @param limb_size   Number of bytes per limb (e.g. 4 or 8).
     * @param limb_count  Number of limbs per integer.  If an integer
     *                    needs fewer limbs, its high limbs remain zero.
     * @return            Total number of limbs actually written across all integers.
     */
    size_t export_limbs(void *buf, size_t buf_size, size_t limb_size, size_t limb_count) {
        assert(size() * limb_count <= buf_size);

        const size_t step_bytes = limb_size * limb_count;
        std::memset(buf, 0, size() * step_bytes);

        size_t exported_words = 0;
        for (size_t i = 0; i < size(); i++) {
            size_t count = 0;
            mpz_export((char*)buf + i * step_bytes,
                       &count,
                       -1,             // Least significant first
                       limb_size,
                       -1,             // Little endian
                       0,              // Skip 0
                       storage_[i].get_mpz_t());
            exported_words += count;
        }
        return exported_words;
    }


    /**
     * @brief  Resize the vector and set mpz_class from `buf`.
     *
     * @param buf         Pointer to an input buffer produced by export_limbs.
     * @param buf_size    Capacity of the buffer, measured in **limbs**, not bytes.
     * @param limb_size   Number of bytes per limb (must match export).
     * @param limb_count  Number of limbs per integer (must match export).
     * @return            Total number of limbs actually read across all integers.
     */
    void import_limbs(const void *buf,
                        size_t buf_size,
                        size_t limb_size,
                        size_t limb_count)
    {
        const size_t num_mpz = buf_size / limb_count;
        const size_t step_bytes = limb_size * limb_count;

        resize(num_mpz);

        for (size_t i = 0; i < num_mpz; ++i) {
            mpz_import(
                storage_[i].get_mpz_t(),  // destination mpz
                limb_count,
                -1,                       // least-significant-word first
                limb_size,                // bytes per limb
                -1,                       // little-endian within limb
                0,                        // no “nails”
                (char*)buf + i * step_bytes // source buffer
            );
        }
    }

private:
    std::vector<mpz_class> storage_;
    size_t size_;
};

}  // namespace ligero::vm
