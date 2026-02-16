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

#include <common.hpp>
#include <exception.hpp>
#include <lz4.h>
#include <lz4hc.h>
#include <stdexcept>
#include <string>
#include <memory>
#include <util/log.hpp>
#include <util/timer.hpp>

namespace ligero::aya {

template <typename CompressPolicy, typename BufferPolicy>
struct basic_compressor
    : public CompressPolicy,
      public BufferPolicy
{
    template <typename Str>
    std::string deflate(Str&& str) {
        auto __t = make_timer("Aya", "Net", "Deflate");
        // make sure buffer has same length with 
        if (this->buffer_size() < str.size()) {
            DEBUG << "boom";
        }

        int deflate_size = CompressPolicy::deflate(static_cast<const char*>(str.data()), str.size(), this->buffer(), this->buffer_size());
        return std::string(this->buffer_begin(), this->buffer_begin() + deflate_size);
    }

    template <typename Str>
    std::string inflate(Str&& str) {
        auto __t = make_timer("Aya", "Net", "Inflate");
        int inflate_size = CompressPolicy::inflate(static_cast<const char*>(str.data()), str.size(), this->buffer(), this->buffer_size());
        return std::string(this->buffer_begin(), this->buffer_begin() + inflate_size);
    }

private:
    using CompressPolicy::deflate;
    using CompressPolicy::inflate;
};

template <size_t BufferSize>
struct stack_char_buffer {
    size_t buffer_size() const noexcept { return BufferSize; }
    char* buffer() noexcept { return buffer_; }
    auto buffer_begin() noexcept { return std::begin(buffer_); }
    auto buffer_end()   noexcept { return std::end(buffer_); }
protected:
    char buffer_[BufferSize];
};

template <size_t CompressionLevel = 1>
struct LZ4_HC {
    size_t compression_level() const noexcept { return CompressionLevel; }

    int deflate(const char* src, int size, char* dst, int capacity) const {
        int deflate_size = LZ4_compress_HC(src, dst, size, capacity, CompressionLevel);

        if (deflate_size == 0) {
            LIGERO_THROW( serialize_error()
                          << throw_reason("Cannot compress data (maybe set larger buffer?)")
                          << throw_error_code(error_code::compress_failed) );
        }
        return deflate_size;
    }

    int inflate(const char* src, int size, char* dst, int capacity) const {
        int inflate_size = LZ4_decompress_safe(src, dst, size, capacity);

        if (inflate_size <= 0) {
            DEBUG << "Bad string: " << std::string(src, size);
            LIGERO_THROW( serialize_error()
                          << throw_reason("Cannot decompress data")
                          << throw_error_code(error_code::decompress_failed) );
        }
        return inflate_size;
    }
};

template <size_t BufferSize>
using lz4_compressor = basic_compressor<LZ4_HC<1>, stack_char_buffer<BufferSize>>;

}
