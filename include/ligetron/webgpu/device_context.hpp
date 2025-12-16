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

#include <cstring>
#include <span>
#include <vector>

#include <webgpu/webgpu.h>
#include <ligetron/webgpu/buffer_view.hpp>

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#endif

namespace ligero {
namespace webgpu {

struct device_context {
    device_context() = default;
    ~device_context();

    void device_init();
    void device_shutdown();
    void device_synchronize();

    WGPUInstance instance() const;
    WGPUAdapter  adapter() const;
    WGPUDevice   device() const;
    WGPUQueue    queue() const;

    void submit(WGPUCommandBuffer command);
    
    buffer_view make_uniform_buffer(size_t num_bytes);
    buffer_view make_device_buffer(size_t num_bytes);
    buffer_view make_map_buffer(size_t num_bytes);

    // Buffer IO
    std::span<const std::byte> map_buffer_raw(buffer_view buf);
    void unmap_buffer(buffer_view buf);
    template <typename T>
    std::vector<T> copy_to_host(buffer_view buf);
    
    void write_buffer_raw(buffer_view buf, const void *data, size_t num_bytes);
    template <typename T>
    void write_buffer(buffer_view buf, const T *data, size_t len);
    template <typename T>
    void write_buffer_clear(buffer_view buf, const T *data, size_t len);

    // Buffer clear
    void clear_buffer(buffer_view buf);

    // Buffer copy
    void copy_buffer_to_buffer(buffer_view from, buffer_view to);
    void copy_buffer_to_buffer(buffer_view from, buffer_view to, size_t bytes);
    void copy_buffer_clear(buffer_view from, buffer_view to);
    
    
protected:
    WGPUInstance instance_   = nullptr;
    WGPUAdapter  adapter_    = nullptr;
    WGPUDevice   device_     = nullptr;
    WGPUQueue    queue_      = nullptr;
    int num_submitted_tasks_ = 0;
};


template <typename T>
std::vector<T> device_context::copy_to_host(buffer_view buf) {
    buffer_view map = make_map_buffer(buf.size());
    copy_buffer_to_buffer(buf, map);
    std::span<const std::byte> s = map_buffer_raw(map);
    std::vector<T> vec(s.size() / sizeof(T));
    std::memcpy(vec.data(), s.data(), s.size());
    unmap_buffer(map);
    return vec;
}

template <typename T>
void device_context::write_buffer(buffer_view buf, const T *data, size_t len) {
    write_buffer_raw(buf, data, len * sizeof(T));
}

template <typename T>
void device_context::write_buffer_clear(buffer_view buf, const T *data, size_t len) {
    write_buffer(buf, data, len);
    clear_buffer(buf.slice(len * sizeof(T)));
}

extern template std::vector<uint32_t>
device_context::copy_to_host(buffer_view buf);

extern template void
device_context::write_buffer(buffer_view buf, const uint32_t *data, size_t len);

extern template void
device_context::write_buffer_clear(buffer_view buf, const uint32_t *data, size_t len); 

}  // namespace webgpu
}  // namespace ligero

