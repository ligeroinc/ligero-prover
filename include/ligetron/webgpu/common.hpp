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
#include <filesystem>
#include <format>
#include <numeric>

#include <webgpu/webgpu.h>

#define WGPU_DESKTOP_MAX_BUFFER_SIZE 2147483648

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#define WGPU_STRING(s) s
#else
#define WGPU_STRING(s) WGPUStringView{ s, std::strlen(s) }
#endif

namespace ligero {
namespace webgpu {

namespace fs = std::filesystem;

constexpr uint32_t max_workgroups        = 256;
constexpr uint32_t workgroup_size        = 256;
constexpr uint32_t ntt_shared_size       = workgroup_size * 2;
constexpr uint32_t ntt_shared_iterations = std::countr_zero(ntt_shared_size);

std::string format_error(WGPUErrorType err, const char *msg);
WGPUShaderModule load_shader(WGPUDevice device, const fs::path& path);

constexpr size_t calc_blocks(size_t N, size_t workgroup_size) {
    return (N + workgroup_size - 1) / workgroup_size;
}

}  // namespace webgpu
}  // namespace ligero
