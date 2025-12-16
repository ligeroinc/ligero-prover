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

#include <gmpxx.h>
#include <webgpu/webgpu.h>

#include <ligetron/webgpu/common.hpp>
#include <ligetron/webgpu/buffer_view.hpp>
#include <ligetron/webgpu/buffer_binding.hpp>
#include <ligetron/webgpu/device_context.hpp>
#include <ligetron/webgpu/device_bignum.hpp>

namespace ligero {
namespace webgpu {

struct powmod_context_base {
    powmod_context_base(const powmod_context_base&) = delete;
    powmod_context_base(powmod_context_base&&)      = delete;

    powmod_context_base& operator=(const powmod_context_base&) = delete;
    powmod_context_base& operator=(powmod_context_base&&)      = delete;
    
    void init_layout();
    void init_pipeline(WGPUShaderModule shader);
    buffer_binding bind_buffer(buffer_view exp,
                               buffer_view coeff,
                               buffer_view out);
    void release();

    void powmod_kernel(buffer_binding bind, size_t threads);
    void powmod_add_kernel(buffer_binding bind, size_t threads);
    
protected:
    explicit powmod_context_base(device_context *device, size_t num_exponent_bits = 32);
    ~powmod_context_base();
    
    size_t num_exponent_bits_;
    
    device_context      *device_                  = nullptr;
    WGPUBindGroupLayout layout_powmod_            = nullptr;
    WGPUBindGroupLayout layout_powmod_precompute_ = nullptr;
    WGPUComputePipeline pipeline_powmod_          = nullptr;
    WGPUComputePipeline pipeline_powmod_add_      = nullptr;

    buffer_view         buf_precompute_;
    buffer_binding      bind_precompute_;    
};


template <typename Bignum>
struct powmod_context : public powmod_context_base {
    explicit powmod_context(device_context *engine, size_t num_exponent_bits = 32);
    virtual ~powmod_context() = default;

    void init_precompute();
    void set_base(const mpz_class& base, const mpz_class& p);
};

extern template struct powmod_context<device_uint256_t>;


}  // namespace webgpu
}  // namespace ligero
