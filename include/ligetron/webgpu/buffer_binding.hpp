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

#include <memory>
#include <vector>
#include <webgpu/webgpu.h>
#include <ligetron/webgpu/buffer_view.hpp>

namespace ligero {
namespace webgpu {

struct eltwise_offset {
    uint32_t x, y, z;
};

struct buffer_binding {
    using bindgroup_type = WGPUBindGroup;
    using buffer_type = buffer_view;
    
    buffer_binding();
    buffer_binding(bindgroup_type bg);
    buffer_binding(bindgroup_type bg,
                   std::vector<buffer_type> bufs);

    bindgroup_type get() const noexcept;

    std::vector<buffer_type>&       buffers() noexcept;
    const std::vector<buffer_type>& buffers() const noexcept;

private:
    std::shared_ptr<bindgroup_type> bind_;
    std::vector<buffer_type> bufs_;
};

}  // namespace webgpu
}  // namespace ligero
