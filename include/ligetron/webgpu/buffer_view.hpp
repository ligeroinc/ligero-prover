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

#include <webgpu/webgpu.h>

namespace ligero {
namespace webgpu {

struct buffer_view {
    using buffer_type  = WGPUBuffer;
    using storage_type = std::shared_ptr<WGPUBuffer>;
    
    buffer_view();
    buffer_view(WGPUBuffer buf);
    buffer_view(WGPUBuffer buf, size_t offset_bytes);
    buffer_view(WGPUBuffer buf, size_t offset_bytes, size_t size_bytes);

    buffer_view(storage_type s);
    buffer_view(storage_type s, size_t offset_bytes);
    buffer_view(storage_type s, size_t offset_bytes, size_t size_bytes);

    buffer_view(const buffer_view&) = default;
    buffer_view& operator=(const buffer_view&) = default;

    bool operator==(buffer_view) const noexcept;

    size_t size()         const noexcept;
    size_t storage_size() const noexcept;
    size_t offset()       const noexcept;

    buffer_type  get()     const noexcept;
    storage_type storage() const noexcept;

    buffer_view slice_bytes(size_t from, size_t n_bytes) const; 
    
    template <typename T = unsigned char>
    buffer_view slice(size_t begin) const;
    
    template <typename T = unsigned char>
    buffer_view slice_n(size_t begin, size_t n) const;

    template <typename T = unsigned char>
    buffer_view slice(size_t begin, size_t end) const;

    // void destroy_source() const;
    
private:
    storage_type storage_;
    size_t offset_bytes_;
    size_t size_bytes_;
};

    
template <typename T>
buffer_view buffer_view::slice_n(size_t begin, size_t n) const {
    return slice_bytes(begin * sizeof(T), n * sizeof(T));
}

template <typename T>
buffer_view buffer_view::slice(size_t begin) const {
    size_t begin_bytes = begin * sizeof(T);
    size_t n_bytes     = size_bytes_ - begin_bytes;
    return slice_bytes(begin_bytes, n_bytes);
}

template <typename T>
buffer_view buffer_view::slice(size_t begin, size_t end) const {
    size_t n = end - begin;
    return slice_n<T>(begin, n);
}

}  // namespace webgpu
}  // namespace ligero
