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
#include <memory>
#include <gmp.h>
#include <gmpxx.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

namespace ligero::vm {

struct mpz_random_engine {
    constexpr static size_t key_size = 32;
    constexpr static size_t block_size = AES_BLOCK_SIZE;

    constexpr static size_t buffer_bytes = 16384;  // 16KB cache
    constexpr static size_t buffer_size = buffer_bytes / sizeof(uint64_t);

    struct deleter {
        void operator()(EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); }
    };

    mpz_random_engine()
        : data_{}, buffer_{}, ctx_(EVP_CIPHER_CTX_new()), offset_(buffer_size), initialized_(false)
    {
        if (!ctx_)
            throw std::runtime_error("Failed to allocate AES context");
    }

    mpz_random_engine(const unsigned char (&key)[key_size],
                      const unsigned char (&iv)[block_size])
        : mpz_random_engine()
    {
        init(key, iv);
    }


    void init(const unsigned char (&key)[key_size], const unsigned char (&iv)[block_size]) {
        if (1 != EVP_EncryptInit_ex(ctx_.get(), EVP_aes_256_ctr(), nullptr, key, iv)) {
            throw std::runtime_error("Cannot initialize AES-CTR context");
        }

        initialized_ = true;
        fill_buf();  // prefill so first operator() call can proceed
    }

    // Refill the entire buffer with fresh keystream
    void fill_buf() {
        if (!initialized_)
            throw std::runtime_error("mpz_random_engine not initialized");

        int out_len = 0;
        if (1 != EVP_EncryptUpdate(ctx_.get(),
                                   reinterpret_cast<unsigned char*>(buffer_),
                                   &out_len,
                                   reinterpret_cast<unsigned char*>(data_),
                                   static_cast<int>(buffer_bytes)))
        {
            throw std::runtime_error("AES-CTR fill_buf failed");
        }

        if (static_cast<size_t>(out_len) != buffer_bytes) {
            throw std::runtime_error("Unexpected keystream length");
        }

        offset_ = 0;
    }

    // Produce a big‐integer from the next num_bytes of keystream
    // — must be nonzero, multiple of 8, and ≤ buffer_bytes
    void operator()(mpz_class& ret, size_t num_bytes) {
        if (num_bytes == 0 || (num_bytes % sizeof(uint64_t) != 0))
            throw std::invalid_argument("num_bytes must be nonzero multiple of 8");

        if (num_bytes > buffer_bytes)
            throw std::out_of_range("Requested bytes exceed buffer capacity");

        const size_t num_u64 = num_bytes / sizeof(uint64_t);
        if (offset_ + num_u64 > buffer_size) {
            fill_buf();
        }

        mpz_import(ret.get_mpz_t(), num_u64, -1, sizeof(uint64_t), 0, 0, buffer_ + offset_);

        offset_ += num_u64;
    }

private:
    alignas(block_size) uint64_t data_[buffer_size];
    alignas(block_size) uint64_t buffer_[buffer_size];
    std::unique_ptr<EVP_CIPHER_CTX, deleter> ctx_;
    size_t offset_ = 0;
    bool initialized_ = false;
};


}  // namespace ligero::vm
