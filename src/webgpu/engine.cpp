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

#include <wgpu.hpp>
#include <stdexcept>

namespace ligero {

using namespace webgpu;

webgpu_context::webgpu_context() { }

webgpu_context::~webgpu_context() {
    device_synchronize();

    if (ntt_shader_) {
        wgpuShaderModuleRelease(ntt_shader_);
        ntt_shader_ = nullptr;
    }
    if (sha_shader_) {
        wgpuShaderModuleRelease(sha_shader_);
        sha_shader_ = nullptr;
    }

    if (ntt_config_layout_) {
        wgpuBindGroupLayoutRelease(ntt_config_layout_);
        ntt_config_layout_ = nullptr;
    }
    if (ntt_layout_) {
        wgpuBindGroupLayoutRelease(ntt_layout_);
        ntt_layout_ = nullptr;
    }
    if (scalar_layout_) {
        wgpuBindGroupLayoutRelease(scalar_layout_);
        scalar_layout_ = nullptr;
    }
    if (eltwise_layout2_) {
        wgpuBindGroupLayoutRelease(eltwise_layout2_);
        eltwise_layout2_ = nullptr;
    }
    if (eltwise_layout3_) {
        wgpuBindGroupLayoutRelease(eltwise_layout3_);
        eltwise_layout3_ = nullptr;
    }
    if (sha256_context_layout_) {
        wgpuBindGroupLayoutRelease(sha256_context_layout_);
        sha256_context_layout_ = nullptr;
    }
    if (sha256_buffer_layout_) {
        wgpuBindGroupLayoutRelease(sha256_buffer_layout_);
        sha256_buffer_layout_ = nullptr;
    }
    if (sampling_layout_) {
        wgpuBindGroupLayoutRelease(sampling_layout_);
        sampling_layout_ = nullptr;
    }

    if (ntt_forward_) {
        wgpuComputePipelineRelease(ntt_forward_);
        ntt_forward_ = nullptr;
    }
    if (ntt_forward_shared_) {
        wgpuComputePipelineRelease(ntt_forward_shared_);
        ntt_forward_shared_ = nullptr;
    }
    if (ntt_inverse_) {
        wgpuComputePipelineRelease(ntt_inverse_);
        ntt_inverse_ = nullptr;
    }
    if (ntt_inverse_shared_) {
        wgpuComputePipelineRelease(ntt_inverse_shared_);
        ntt_inverse_shared_ = nullptr;
    }
    if (ntt_bit_reverse_) {
        wgpuComputePipelineRelease(ntt_bit_reverse_);
        ntt_bit_reverse_ = nullptr;
    }
    if (ntt_adjust_inverse_) {
        wgpuComputePipelineRelease(ntt_adjust_inverse_);
        ntt_adjust_inverse_ = nullptr;
    }
    if (ntt_reduce_) {
        wgpuComputePipelineRelease(ntt_reduce_);
        ntt_reduce_ = nullptr;
    }
    if (ntt_fold_) {
        wgpuComputePipelineRelease(ntt_fold_);
        ntt_fold_ = nullptr;
    }

    if (eltwise_addmod_) {
        wgpuComputePipelineRelease(eltwise_addmod_);
        eltwise_addmod_ = nullptr;
    }
    if (eltwise_submod_) {
        wgpuComputePipelineRelease(eltwise_submod_);
        eltwise_submod_ = nullptr;
    }
    if (eltwise_mulmod_) {
        wgpuComputePipelineRelease(eltwise_mulmod_);
        eltwise_mulmod_ = nullptr;
    }
    if (eltwise_divmod_) {
        wgpuComputePipelineRelease(eltwise_divmod_);
        eltwise_divmod_ = nullptr;
    }
    if (eltwise_addcmod_) {
        wgpuComputePipelineRelease(eltwise_addcmod_);
        eltwise_addcmod_ = nullptr;
    }
    if (eltwise_subcmod_) {
        wgpuComputePipelineRelease(eltwise_subcmod_);
        eltwise_subcmod_ = nullptr;
    }
    if (eltwise_csubmod_) {
        wgpuComputePipelineRelease(eltwise_csubmod_);
        eltwise_csubmod_ = nullptr;
    }
    if (eltwise_mulcmod_) {
        wgpuComputePipelineRelease(eltwise_mulcmod_);
        eltwise_mulcmod_ = nullptr;
    }
    if (eltwise_montmul_) {
        wgpuComputePipelineRelease(eltwise_montmul_);
        eltwise_montmul_ = nullptr;
    }
    if (eltwise_bit_decompose_) {
        wgpuComputePipelineRelease(eltwise_bit_decompose_);
        eltwise_bit_decompose_ = nullptr;
    }
    if (eltwise_fma_) {
        wgpuComputePipelineRelease(eltwise_fma_);
        eltwise_fma_ = nullptr;
    }
    if (eltwise_fmac_) {
        wgpuComputePipelineRelease(eltwise_fmac_);
        eltwise_fmac_ = nullptr;
    }
    if (eltwise_addassignmod_) {
        wgpuComputePipelineRelease(eltwise_addassignmod_);
        eltwise_addassignmod_ = nullptr;
    }

    if (sha256_init_) {
        wgpuComputePipelineRelease(sha256_init_);
        sha256_init_ = nullptr;
    }
    if (sha256_update_) {
        wgpuComputePipelineRelease(sha256_update_);
        sha256_update_ = nullptr;
    }
    if (sha256_final_) {
        wgpuComputePipelineRelease(sha256_final_);
        sha256_final_ = nullptr;
    }

    if (sampling_gather_) {
        wgpuComputePipelineRelease(sampling_gather_);
        sampling_gather_ = nullptr;
    }
}

void webgpu_context::webgpu_init(size_t num_hardware_cores, fs::path shader_root_path) {
    device_init();
    
    num_hardware_cores_ = num_hardware_cores;
    if (num_hardware_cores < workgroup_size) {
        LIGERO_LOG_WARNING
            << std::format("Hardware cores hint {} less than workgroup size {}, round up",
                           num_hardware_cores,
                           workgroup_size);
    }

    if (shader_root_path.empty()) {
        shader_root_path_ = fs::current_path() / "shader";
    }
    else {
        shader_root_path_ = shader_root_path;
    }
}


void webgpu_context::ntt_init(uint32_t origin_size,
                              uint32_t padded_size,
                              uint32_t code_size,
                              const mpz_class& p,
                              const mpz_class& barrett_factor,
                              const mpz_class& root_k,
                              const mpz_class& root_2k,
                              const mpz_class& root_n)
{
    ntt_shader_ = webgpu::load_shader(device_, shader_root_path_ / "bignum.wgsl" );
    ntt_init_constants(origin_size, padded_size, code_size);
    ntt_init_buffer();
    ntt_init_layouts();
    ntt_init_pipelines();
    ntt_init_config(p, barrett_factor, root_k, root_2k, root_n);
}


void webgpu_context::powmod_init(size_t num_exponent_bits) {
    powmod_ctx_ = std::make_unique<webgpu::powmod_context<device_bignum_type>>(this, num_exponent_bits);
    powmod_ctx_->init_layout();
    powmod_ctx_->init_pipeline(ntt_shader_);
    powmod_ctx_->init_precompute();    
}

void webgpu_context::powmod_set_base(const mpz_class& base, const mpz_class& p) {
    get_powmod_context()->set_base(base, p);
}

webgpu::buffer_binding webgpu_context::bind_ntt(buffer_type code) {
    const size_t bind_size = encoding_size() * device_bignum_type::num_bytes;

    if (code.size() != bind_size) {
        LIGERO_LOG_WARNING << std::format("NTT binding has wrong size: {}, expect: {}",
                                          code.size(), bind_size);
    }
    
    WGPUBindGroupEntry entries = {
        .binding = 0,
        .buffer  = code.get(),
        .offset  = code.offset(),
        .size    = bind_size,
    };

    WGPUBindGroupDescriptor desc {
        .layout     = ntt_layout_,
        .entryCount = 1,
        .entries    = &entries,
    };
   
    WGPUBindGroup ntt = wgpuDeviceCreateBindGroup(device_, &desc);

    webgpu::buffer_binding ntt_bind { ntt };
    ntt_bind.buffers() = { buffer_type(code.get(), code.offset(), bind_size) };
    
    return ntt_bind;
}

webgpu::buffer_binding
webgpu_context::bind_powmod(buffer_type exp,
                            buffer_type coeff,
                            buffer_type out)
{
    return get_powmod_context()->bind_buffer(exp, coeff, out);
}

webgpu::buffer_binding webgpu_context::bind_scalar(buffer_type s) {
    WGPUBindGroupEntry scalar_entries {
        .binding = 2,
        .buffer  = s.get(),
        .offset  = s.offset(),
        .size    = s.size()
    };

    WGPUBindGroupDescriptor config_desc {
        .layout = scalar_layout_,
        .entryCount = 1,
        .entries = &scalar_entries,
    };

    auto bg = wgpuDeviceCreateBindGroup(device_, &config_desc);
    webgpu::buffer_binding binding{ bg };
    binding.buffers() = { s };
    return binding;
}

webgpu::buffer_binding webgpu_context::bind_eltwise2(buffer_type x, buffer_type out) {
    if (x.size() != out.size()) {
        LIGERO_LOG_WARNING << std::format("Unaligned eltwise binding size: {}, {}",
                                          x.size(), out.size());
    }

    WGPUBindGroupEntry entries[2] = {
        {
            .binding = 1,
            .buffer  = x.get(),
            .offset  = x.offset(),
            .size    = x.size()
        },
        {
            .binding = 3,
            .buffer  = out.get(),
            .offset  = out.offset(),
            .size    = out.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = eltwise_layout2_,
        .entryCount = 2,
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu::buffer_binding binding{ bindgroup };
    binding.buffers() = { x, out };
    return binding;
}

webgpu::buffer_binding webgpu_context::bind_eltwise3(buffer_type x, buffer_type y, buffer_type out) {
    if (x.size() != y.size() || x.size() != out.size()) {
        LIGERO_LOG_WARNING << std::format("Unaligned eltwise binding size: {}, {}, {}",
                                          x.size(), y.size(), out.size());
    }
    
    WGPUBindGroupEntry entries[3] = {
        {
            .binding = 1,
            .buffer  = x.get(),
            .offset  = x.offset(),
            .size    = x.size()
        },
        {
            .binding = 2,
            .buffer  = y.get(),
            .offset  = y.offset(),
            .size    = y.size()
        },
        {
            .binding = 3,
            .buffer  = out.get(),
            .offset  = out.offset(),
            .size    = out.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = eltwise_layout3_,
        .entryCount = 3,
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu::buffer_binding binding{ bindgroup };
    binding.buffers() = { x, y, out };
    return binding;
}

webgpu::buffer_binding webgpu_context::bind_sha256_context(buffer_type ctx, buffer_type digest) {
    WGPUBindGroupEntry entries[] {
        {
            .binding = 0,
            .buffer  = ctx.get(),
            .offset  = ctx.offset(),
            .size    = ctx.size()
        },
        {
            .binding = 1,
            .buffer  = digest.get(),
            .offset  = digest.offset(),
            .size    = digest.size()
        }
    };

    WGPUBindGroupDescriptor bind_desc {
        .layout = sha256_context_layout_,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &bind_desc);
    webgpu::buffer_binding binding { bindgroup};
    binding.buffers() = { ctx, digest };
    return binding;
}

webgpu::buffer_binding webgpu_context::bind_sha256_buffer(buffer_type input) {
     WGPUBindGroupEntry entries[] {
        {
            .binding = 0,
            .buffer  = input.get(),
            .offset  = input.offset(),
            .size    = input.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = sha256_buffer_layout_,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu::buffer_binding binding{ bindgroup };
    binding.buffers() = { input };
    return binding;
}

webgpu::buffer_binding webgpu_context::bind_sampling(buffer_type from, buffer_type to) {
    WGPUBindGroupEntry entries[2] = {
        {
            .binding = 1,
            .buffer  = from.get(),
            .offset  = from.offset(),
            .size    = from.size(),
        },
        {
            .binding = 3,
            .buffer  = to.get(),
            .offset  = to.offset(),
            .size    = num_samplings_ * device_bignum_type::num_bytes,
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = sampling_layout_,
        .entryCount = 2,
        .entries = entries,
    };
    
    WGPUBindGroup bindGroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu::buffer_binding binding{ bindGroup };
    binding.buffers() = { from, to };
    return binding;
}

void webgpu_context::EltwiseAddMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddMod") };
    
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.y * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_addmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseAddMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddConstMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_addcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseSubMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseSubMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.y * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_submod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseSubConstMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseSubConstMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_subcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseConstSubMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseConstSubMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_csubmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMultMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMultMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.y * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_mulmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMultMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMultConstantMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_mulcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseDivMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {     WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseDivMod") };   
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.y * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_divmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMontMultMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMontMultMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_montmul_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseBitDecompose(webgpu::buffer_binding bind, size_t pos, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, pos, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseBitDecompose") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_bit_decompose_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwisePowMod(webgpu::buffer_binding bind) {
    get_powmod_context()->powmod_kernel(bind, num_default_workgroups_);
}

void webgpu_context::EltwisePowAddMod(webgpu::buffer_binding bind) {
    get_powmod_context()->powmod_add_kernel(bind, num_default_workgroups_);
}

// Z = Z + X * Y
void webgpu_context::EltwiseFMAMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseFMAMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.y * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_fma_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseFMAMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets) {
    write_limbs(scalar_buf_, k, 1);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseFMAConstantMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_fmac_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, scalar_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseAddAssignMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddAssignMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * device_bignum_type::num_bytes,
        element_offsets.z * device_bignum_type::num_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_addassignmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

// NTT
// ------------------------------------------------------------
void webgpu_context::encode_ntt_device(webgpu::buffer_binding msg) {
    assert(msg.buffers()[0].size() == encoding_size() * device_bignum_type::num_bytes);
    
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Encode") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_inverse_kernel(pass, ntt_inverse_bindings_k_, msg, padding_size());
    ntt_forward_kernel(pass, ntt_forward_bindings_n_, msg, encoding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::decode_ntt_device(webgpu::buffer_binding code) {
    assert(code.buffers()[0].size() == encoding_size() * device_bignum_type::num_bytes);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Decode") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);
    
    ntt_inverse_kernel(pass, ntt_inverse_bindings_n_, code, encoding_size());

    /// Copy limbs and fold second half
    wgpuComputePassEncoderSetBindGroup(pass, 0, code.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, ntt_forward_bindings_2k_[0].get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_fold_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    
    ntt_forward_kernel(pass, ntt_forward_bindings_k_, code, padding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}


void webgpu_context::ntt_forward_k(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Forward K") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_forward_kernel(pass, ntt_forward_bindings_k_, bind, padding_size());
    
    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_forward_2k(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Forward 2K") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_forward_kernel(pass, ntt_forward_bindings_2k_, bind, 2 * padding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_forward_n(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Forward N") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_forward_kernel(pass, ntt_forward_bindings_n_, bind, encoding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_forward_kernel(WGPUComputePassEncoder pass,
                                        std::vector<webgpu::buffer_binding>& config,
                                        webgpu::buffer_binding bind,
                                        size_t N)
{
    const uint32_t log2N = static_cast<uint32_t>(std::log2(N));
    assert(log2N >= ntt_shared_iterations);

    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_forward_);
    for (uint32_t iter = log2N; iter > ntt_shared_iterations; iter--) {
        wgpuComputePassEncoderSetBindGroup(pass, 1, config[iter].get(), 0, nullptr);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }

    const uint32_t num_shared_workgroups = N / ntt_shared_size;
    if (num_shared_workgroups <= max_workgroups) {
        wgpuComputePassEncoderSetBindGroup(pass, 1, config[0].get(), 0, nullptr);
        wgpuComputePassEncoderSetPipeline(pass, ntt_forward_shared_);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_shared_workgroups, 1, 1);
    }
    else {
        wgpuComputePassEncoderSetPipeline(pass, ntt_forward_);
        for (uint32_t iter = ntt_shared_iterations; iter >= 1; iter--) {
            wgpuComputePassEncoderSetBindGroup(pass, 1, config[iter].get(), 0, nullptr);
            wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
        }

        wgpuComputePassEncoderSetPipeline(pass, ntt_reduce_);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }

    /// DIF butterfly performs bit reversal at the end
    wgpuComputePassEncoderSetBindGroup(pass, 1, config[0].get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_bit_reverse_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
}

void webgpu_context::ntt_inverse_k(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Inverse K") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_inverse_kernel(pass, ntt_inverse_bindings_k_, bind, padding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_inverse_2k(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Inverse 2K") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_inverse_kernel(pass, ntt_inverse_bindings_2k_, bind, 2 * padding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_inverse_n(webgpu::buffer_binding bind)
{
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Inverse N") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    ntt_inverse_kernel(pass, ntt_inverse_bindings_n_, bind, encoding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::ntt_inverse_kernel(WGPUComputePassEncoder pass,
                                        std::vector<webgpu::buffer_binding>& config,
                                        webgpu::buffer_binding bind,
                                        size_t N)
{
    const uint32_t log2N = static_cast<uint32_t>(std::log2(N));
    assert(log2N >= ntt_shared_iterations);

    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(),      0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, config[0].get(), 0, nullptr);

    /// DIT butterfly performs bit reversal at the beginning
    wgpuComputePassEncoderSetPipeline(pass, ntt_bit_reverse_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    
    const uint32_t num_shared_workgroups = N / ntt_shared_size;
    if (num_shared_workgroups <= max_workgroups) {
        wgpuComputePassEncoderSetPipeline(pass, ntt_inverse_shared_);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_shared_workgroups, 1, 1);
    }
    else {
        wgpuComputePassEncoderSetPipeline(pass, ntt_inverse_);
        for (uint32_t iter = 1; iter <= ntt_shared_iterations; iter++) {
            wgpuComputePassEncoderSetBindGroup(pass, 1, config[iter].get(), 0, nullptr);
            wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
        }
    }

    wgpuComputePassEncoderSetPipeline(pass, ntt_inverse_);
    for (uint32_t iter = ntt_shared_iterations + 1; iter <= log2N; iter++) {
        wgpuComputePassEncoderSetBindGroup(pass, 1, config[iter].get(), 0, nullptr);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }
            
    wgpuComputePassEncoderSetPipeline(pass, ntt_adjust_inverse_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
}


void webgpu_context::ntt_init_layouts() {
    // @group(0) bindings (Storage)
    // --------------------------------------------------
    {
        WGPUBindGroupLayoutEntry ntt_binding {
            .binding = 0,
            .visibility = WGPUShaderStage_Compute,
            .buffer {
                .type = WGPUBufferBindingType_Storage,
            },
        };
        
        WGPUBindGroupLayoutDescriptor ntt_desc {
            .label = WGPU_STRING("Bignum::ntt_buffer"),
            .entryCount = 1,
            .entries = &ntt_binding,
        };

        ntt_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &ntt_desc);
    }
    
    {
        WGPUBindGroupLayoutEntry eltwise_bindings[2] = {
            {
                .binding = 1,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_ReadOnlyStorage,
                    .hasDynamicOffset = true
                },
            },
            {
                .binding = 3,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_Storage,
                    .hasDynamicOffset = true
                },
            },
        };

        WGPUBindGroupLayoutDescriptor eltwise_desc {
            .label = WGPU_STRING("Bignum::eltwise_buffer2"),
            .entryCount = 2,
            .entries = eltwise_bindings,
        };

        eltwise_layout2_ = wgpuDeviceCreateBindGroupLayout(device_, &eltwise_desc);
    }

    {
        WGPUBindGroupLayoutEntry eltwise_bindings[3] = {
            {
                .binding = 1,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_ReadOnlyStorage,
                    .hasDynamicOffset = true
                },
            },
            {
                .binding = 2,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_ReadOnlyStorage,
                    .hasDynamicOffset = true
                },
            },
            {
                .binding = 3,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_Storage,
                    .hasDynamicOffset = true
                },
            },
        };

        WGPUBindGroupLayoutDescriptor eltwise_desc {
            .label = WGPU_STRING("Bignum::eltwise3_buffer3"),
            .entryCount = 3,
            .entries = eltwise_bindings,
        };

        eltwise_layout3_ = wgpuDeviceCreateBindGroupLayout(device_, &eltwise_desc);
    }

    // @group(1) bindings (NTT config)
    // --------------------------------------------------
    {
        WGPUBindGroupLayoutEntry ntt_config_bindings[2] = {
            {
                .binding    = 0,
                .visibility = WGPUShaderStage_Compute,
                .buffer     = { .type = WGPUBufferBindingType_Uniform }
            },
            {
                .binding    = 1,
                .visibility = WGPUShaderStage_Compute,
                .buffer     = { .type = WGPUBufferBindingType_ReadOnlyStorage },
            },
        };

        WGPUBindGroupLayoutDescriptor ntt_config_desc {
            .label = WGPU_STRING("Bignum::ntt_config"),
            .entryCount = 2,
            .entries = ntt_config_bindings,
        };

        ntt_config_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &ntt_config_desc);
    }
    
    {
        WGPUBindGroupLayoutEntry scalar_binding {
            .binding = 2,
            .visibility = WGPUShaderStage_Compute,
            .buffer {
                .type = WGPUBufferBindingType_Uniform,
            }
        };

        WGPUBindGroupLayoutDescriptor desc {
            .label = WGPU_STRING("Bignum::input_scalar"),
            .entryCount = 1,
            .entries = &scalar_binding,
        };

        scalar_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &desc);
    }
}

void webgpu_context::ntt_init_pipelines() {
    WGPUBindGroupLayout ntt_binds[2] = {
        ntt_layout_,
        ntt_config_layout_,
    };

    WGPUBindGroupLayout eltwise2_binds[1] = {
        eltwise_layout2_,
    };

    WGPUBindGroupLayout eltwise3_binds[1] = {
        eltwise_layout3_,
    };

    WGPUBindGroupLayout eltwise2_scalar_binds[2] = {
        eltwise_layout2_,
        scalar_layout_
    };
    
    WGPUPipelineLayoutDescriptor pipelineDesc {
        .bindGroupLayoutCount = 2,
        .bindGroupLayouts = ntt_binds,
    };

    WGPUPipelineLayout ntt_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 1;
    pipelineDesc.bindGroupLayouts     = eltwise2_binds;
    WGPUPipelineLayout eltwise2_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 1;
    pipelineDesc.bindGroupLayouts     = eltwise3_binds;
    WGPUPipelineLayout eltwise3_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 2;
    pipelineDesc.bindGroupLayouts     = eltwise2_scalar_binds;
    WGPUPipelineLayout eltwise2_scalar_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    {
        WGPUComputePipelineDescriptor ntt_desc {
            .layout = ntt_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            },
        };

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_forward_radix2");
        ntt_forward_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_forward_radix2_shared");
        ntt_forward_shared_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_inverse_radix2");
        ntt_inverse_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_inverse_radix2_shared");
        ntt_inverse_shared_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_bit_reverse");
        ntt_bit_reverse_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_reduce4p");
        ntt_reduce_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_adjust_inverse_reduce");
        ntt_adjust_inverse_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_fold");
        ntt_fold_ = wgpuDeviceCreateComputePipeline(device_, &ntt_desc);
    }

    {
        WGPUComputePipelineDescriptor eltwise_desc {
            .layout = eltwise3_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            }
        };

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddMod");
        eltwise_addmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseSubMod");
        eltwise_submod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMultMod");
        eltwise_mulmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseDivMod");
        eltwise_divmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseFMAMod");
        eltwise_fma_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

    }

    {
        WGPUComputePipelineDescriptor eltwise_desc {
            .layout = eltwise2_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            }
        };

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddAssignMod");
        eltwise_addassignmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);
    }

    {
        WGPUComputePipelineDescriptor eltwise_desc {
            .layout = eltwise2_scalar_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            }
        };

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseBitDecompose");
        eltwise_bit_decompose_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddConstantMod");
        eltwise_addcmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseSubConstantMod");
        eltwise_subcmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseConstantSubMod");
        eltwise_csubmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMultConstantMod");
        eltwise_mulcmod_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMontMultConstantMod");
        eltwise_montmul_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseFMAConstantMod");
        eltwise_fmac_ = wgpuDeviceCreateComputePipeline(device_, &eltwise_desc);
    }

    wgpuPipelineLayoutRelease(ntt_pipeline_layout);
    wgpuPipelineLayoutRelease(eltwise2_pipeline_layout);
    wgpuPipelineLayoutRelease(eltwise2_scalar_pipeline_layout);
    wgpuPipelineLayoutRelease(eltwise3_pipeline_layout);
}

void webgpu_context::ntt_init_constants(uint32_t origin_size,
                                        uint32_t padded_size,
                                        uint32_t code_size)
{    
    size_l_ = origin_size;
    size_k_ = padded_size;
    size_n_ = code_size;
    
    ntt_iterations_k_  = static_cast<uint32_t>(std::log2(size_k_));
    ntt_iterations_2k_ = ntt_iterations_k_ + 1;
    ntt_iterations_n_  = static_cast<uint32_t>(std::log2(size_n_));

    num_default_workgroups_  = calc_blocks(num_hardware_cores_, workgroup_size);
}

void webgpu_context::ntt_init_buffer() {
    // Allocate uniform buffers
    // --------------------------------------------------
    scalar_buf_ = make_uniform_buffer(sizeof(device_bignum_type));
    
    size_t config_size = sizeof(ntt_config_t);
    
    // Make sure uniform is 256 byte aligned
    assert(config_size % 256 == 0);

    // Create log2(N) copys of configurations in order to dynamically select at runtimge
    // Plus one to leave space for unused [0]
    ntt_config_k_  = make_uniform_buffer(config_size * (ntt_iterations_k_  + 1));
    ntt_config_2k_ = make_uniform_buffer(config_size * (ntt_iterations_2k_ + 1));
    ntt_config_n_  = make_uniform_buffer(config_size * (ntt_iterations_n_  + 1));

    // Allocate storage buffers
    // --------------------------------------------------
    ntt_omegas_k_.resize(ntt_iterations_k_ + 1);
    ntt_omegasinv_k_.resize(ntt_iterations_k_ + 1);

    ntt_omegas_2k_.resize(ntt_iterations_2k_ + 1);
    ntt_omegasinv_2k_.resize(ntt_iterations_2k_ + 1);

    ntt_omegas_n_.resize(ntt_iterations_n_ + 1);
    ntt_omegasinv_n_.resize(ntt_iterations_n_ + 1);

    for (size_t i = 1; i <= ntt_iterations_k_; i++) {
        // Size N FFT only needs N/2 omegas
        const size_t omega_bytes = ((1ull << i) / 2) * device_bignum_type::num_bytes;
        ntt_omegas_k_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_k_[i] = make_device_buffer(omega_bytes);
    }

    for (size_t i = 1; i <= ntt_iterations_2k_; i++) {
        // Size N FFT only needs N/2 omegas
        const size_t omega_bytes = ((1ull << i) / 2) * device_bignum_type::num_bytes;
        ntt_omegas_2k_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_2k_[i] = make_device_buffer(omega_bytes);
    }

    for (size_t i = 1; i <= ntt_iterations_n_; i++) {
        // Size N FFT only needs N/2 omegas
        const size_t omega_bytes = ((1ull << i) / 2) * device_bignum_type::num_bytes;
        ntt_omegas_n_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_n_[i] = make_device_buffer(omega_bytes);
    }

    // NB: Since position 0 is never used, we fill shared omegas for all iterations in it
    const size_t shared_omegas_bytes = device_bignum_type::num_bytes *
        ((1ull << ntt_shared_iterations) - 1);

    ntt_omegas_k_[0]     = make_device_buffer(shared_omegas_bytes);
    ntt_omegasinv_k_[0]  = make_device_buffer(shared_omegas_bytes);
    ntt_omegas_2k_[0]    = make_device_buffer(shared_omegas_bytes);
    ntt_omegasinv_2k_[0] = make_device_buffer(shared_omegas_bytes);
    ntt_omegas_n_[0]     = make_device_buffer(shared_omegas_bytes);
    ntt_omegasinv_n_[0]  = make_device_buffer(shared_omegas_bytes);
}

void webgpu_context::ntt_init_config(const mpz_class& p,
                                     const mpz_class& barrett_factor,
                                     const mpz_class& root_k,
                                     const mpz_class& root_2k,
                                     const mpz_class& root_n)
{
    ntt_precompute_omegas(p, root_k, size_k_,
                          ntt_omegas_k_, ntt_omegasinv_k_, ntt_config_k_);
    ntt_precompute_omegas(p, root_2k, 2 * size_k_,
                          ntt_omegas_2k_, ntt_omegasinv_2k_, ntt_config_2k_);
    ntt_precompute_omegas(p, root_n, size_n_,
                          ntt_omegas_n_, ntt_omegasinv_n_, ntt_config_n_);

    // ------------------------------------------------------------

    scalar_binding_ = bind_scalar(scalar_buf_);

    ntt_forward_bindings_k_.resize(ntt_iterations_k_ + 1, nullptr);
    ntt_inverse_bindings_k_.resize(ntt_iterations_k_ + 1, nullptr);
    for (size_t i = 0; i <= ntt_iterations_k_; i++) {
        WGPUBindGroupEntry config_entries[] = {
            {
                .binding = 0,
                .buffer  = ntt_config_k_.get(),
                .offset  = i * sizeof(ntt_config_t),
                .size    = sizeof(ntt_config_t)
            },
            {
                .binding = 1,
                .buffer  = ntt_omegas_k_[i].get(),
                .offset  = ntt_omegas_k_[i].offset(),
                .size    = ntt_omegas_k_[i].size(),
            },
        };

        WGPUBindGroupDescriptor config_desc {
            .layout     = ntt_config_layout_,
            .entryCount = sizeof(config_entries) / sizeof(WGPUBindGroupEntry),
            .entries    = config_entries,
        };

        ntt_forward_bindings_k_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);

        config_entries[1].binding = 1;
        config_entries[1].buffer  = ntt_omegasinv_k_[i].get();
        config_entries[1].offset  = ntt_omegasinv_k_[i].offset();
        config_entries[1].size    = ntt_omegasinv_k_[i].size();

        ntt_inverse_bindings_k_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);
    }

    ntt_forward_bindings_2k_.resize(ntt_iterations_2k_ + 1, nullptr);
    ntt_inverse_bindings_2k_.resize(ntt_iterations_2k_ + 1, nullptr);
    for (size_t i = 0; i <= ntt_iterations_2k_; i++) {
        WGPUBindGroupEntry config_entries[] = {
            {
                .binding = 0,
                .buffer  = ntt_config_2k_.get(),
                .offset  = i * sizeof(ntt_config_t),
                .size    = sizeof(ntt_config_t)
            },
            {
                .binding = 1,
                .buffer  = ntt_omegas_2k_[i].get(),
                .offset  = ntt_omegas_2k_[i].offset(),
                .size    = ntt_omegas_2k_[i].size(),
            },
        };

        WGPUBindGroupDescriptor config_desc {
            .layout     = ntt_config_layout_,
            .entryCount = sizeof(config_entries) / sizeof(WGPUBindGroupEntry),
            .entries    = config_entries,
        };

        ntt_forward_bindings_2k_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);

        config_entries[1].binding = 1;
        config_entries[1].buffer  = ntt_omegasinv_2k_[i].get();
        config_entries[1].offset  = ntt_omegasinv_2k_[i].offset();
        config_entries[1].size    = ntt_omegasinv_2k_[i].size();

        ntt_inverse_bindings_2k_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);
    }

    ntt_forward_bindings_n_.resize(ntt_iterations_n_ + 1, nullptr);
    ntt_inverse_bindings_n_.resize(ntt_iterations_n_ + 1, nullptr);
    for (size_t i = 0; i <= ntt_iterations_n_; i++) {
        WGPUBindGroupEntry config_entries[] = {
            {
                .binding = 0,
                .buffer  = ntt_config_n_.get(),
                .offset  = i * sizeof(ntt_config_t),
                .size    = sizeof(ntt_config_t)
            },
            {
                .binding = 1,
                .buffer  = ntt_omegas_n_[i].get(),
                .offset  = ntt_omegas_n_[i].offset(),
                .size    = ntt_omegas_n_[i].size()
            },
        };

        WGPUBindGroupDescriptor config_desc {
            .layout = ntt_config_layout_,
            .entryCount = sizeof(config_entries) / sizeof(WGPUBindGroupEntry),
            .entries = config_entries,
        };

        ntt_forward_bindings_n_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);

        config_entries[1].binding = 1;
        config_entries[1].buffer  = ntt_omegasinv_n_[i].get();
        config_entries[1].offset  = ntt_omegasinv_n_[i].offset();
        config_entries[1].size    = ntt_omegasinv_n_[i].size();
        
        ntt_inverse_bindings_n_[i] = wgpuDeviceCreateBindGroup(device_, &config_desc);
    }
}

void webgpu_context::ntt_precompute_omegas(const mpz_class& p,
                                           const mpz_class& nth_root,
                                           uint32_t N,
                                           std::vector<buffer_type>& omegas_buf,
                                           std::vector<buffer_type>& omegas_inv_buf,
                                           buffer_type config_buf)
{
    const size_t log2N = static_cast<size_t>(std::log2(N));
    
    {
        std::vector<device_bignum_type> omegas(N/2);
        for (size_t i = 0; i < N/2; i++) {
            mpz_class omega;
            mpz_powm_ui(omega.get_mpz_t(), nth_root.get_mpz_t(), i, p.get_mpz_t());

            // w' = w * beta mod p
            omega <<= device_bignum_type::num_bits;
            mpz_mod(omega.get_mpz_t(), omega.get_mpz_t(), p.get_mpz_t());

            omegas[i] = omega;
        }

        for (size_t i = 1; i <= log2N; i++) {
            const size_t M = 1ull << i;
            const size_t num_omegas = M / 2;
            const size_t stride = N / M ;
            std::vector<device_bignum_type> curr_omegas(num_omegas);

            for (size_t j = 0; j < num_omegas; j++) {
                curr_omegas[j] = omegas[j * stride];
            }

            write_buffer(omegas_buf[i], curr_omegas.data(), curr_omegas.size());
        }

        // Set shared omegas at position 0
        std::vector<device_bignum_type> shared_omegas((1ull << ntt_shared_iterations) - 1);
        for (size_t i = 1, base = 0; i <= ntt_shared_iterations; i++) {
            const size_t M = 1ull << i;
            const size_t num_omegas = M / 2;
            const size_t stride = N / M ;

            for (size_t j = 0; j < num_omegas; j++) {
                shared_omegas[base + j] = omegas[j * stride];
            }
            base += num_omegas;
        }
        write_buffer(omegas_buf[0], shared_omegas.data(), shared_omegas.size());
    }

    {
        std::vector<device_bignum_type> omegas_inv(N/2);
        mpz_class inverse_root;
        mpz_invert(inverse_root.get_mpz_t(), nth_root.get_mpz_t(), p.get_mpz_t());

        // Precompute inverse omega table
        for (size_t i = 0; i < N/2; i++) {
            mpz_class omega_inv;
            mpz_powm_ui(omega_inv.get_mpz_t(),
                        inverse_root.get_mpz_t(), i, p.get_mpz_t());

            // w' = w * J mod p
            omega_inv <<= device_bignum_type::num_bits;
            mpz_mod(omega_inv.get_mpz_t(), omega_inv.get_mpz_t(), p.get_mpz_t());

            omegas_inv[i] = omega_inv;
        }

        for (size_t i = 1; i <= log2N; i++) {
            const size_t M = 1ull << i;
            const size_t num_omegas = M / 2;
            const size_t stride = N / M ;
            std::vector<device_bignum_type> curr_omegas(num_omegas);

            for (size_t j = 0; j < num_omegas; j++) {
                curr_omegas[j] = omegas_inv[j * stride];
            }
            
            write_buffer(omegas_inv_buf[i], curr_omegas.data(), curr_omegas.size());
        }

        // Set shared omegas at position 0
        std::vector<device_bignum_type> shared_omegas((1ull << ntt_shared_iterations) - 1);
        for (size_t i = 1, base = 0; i <= ntt_shared_iterations; i++) {
            const size_t M = 1ull << i;
            const size_t num_omegas = M / 2;
            const size_t stride = N / M ;

            for (size_t j = 0; j < num_omegas; j++) {
                shared_omegas[base + j] = omegas_inv[j * stride];
            }
            base += num_omegas;
        }
        write_buffer(omegas_inv_buf[0], shared_omegas.data(), shared_omegas.size());
    }

    mpz_class N_inv;

    // Precompute N ^ (-1)
    mpz_class degree = N;
    mpz_invert(N_inv.get_mpz_t(), degree.get_mpz_t(), p.get_mpz_t());
    
    N_inv = (N_inv << device_bignum_type::num_bits) % p;

    ntt_config_t config {
        .N_inv    = device_bignum_type(N_inv),
        .N        = N,
        .log2N    = static_cast<uint32_t>(std::log2(N)),
        .M        = 1,
    };

    // We actually need iterations [1, log2(N)], add 0 to save index calculation
    std::vector<ntt_config_t> configs;
    for (size_t i = 0; i <= log2N; i++) {
        config.M    = 1u << i;
        config.iter = i;
        configs.push_back(config);
    }

    // Write to device buffer
    write_buffer(config_buf, configs.data(), configs.size());
}

webgpu::powmod_context<webgpu_context::device_bignum_type>*
webgpu_context::get_powmod_context() {
    if (!powmod_ctx_) {
        throw std::logic_error("Uninitialized powmod context");
    }

    return powmod_ctx_.get(); 
}

void webgpu_context::sha256_init(size_t sha_instances) {
    fs::path path = shader_root_path_ / "sha256.wgsl";
    std::string placeholder = "#INSTANCES";
        
    std::ifstream ifs(path);
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string source = ss.str();

    // Dynamically replace num instances
    source.replace(source.find(placeholder),
                   placeholder.size(),
                   std::to_string(sha_instances));

    WGPUShaderModuleWGSLDescriptor wgslDesc {
        .chain = WGPUChainedStruct {
            .next = nullptr,
#if defined(__EMSCRIPTEN__)
            .sType = WGPUSType_ShaderModuleWGSLDescriptor,
#else
            .sType = WGPUSType_ShaderSourceWGSL,
#endif
        },
        .code = WGPU_STRING(source.c_str())
    };

    WGPUShaderModuleDescriptor desc {
        .nextInChain = (WGPUChainedStruct*)&wgslDesc,
        .label = WGPU_STRING("sha256.wgsl")
    };

    sha_instances_ = sha_instances;
    sha_shader_    = wgpuDeviceCreateShaderModule(device_, &desc);

    WGPUBindGroupLayoutEntry sha256_ctx_bindings[] {
        {
            .binding = 0,
            .visibility = WGPUShaderStage_Compute,
            .buffer { .type = WGPUBufferBindingType_Storage },
        },
        {
            .binding = 1,
            .visibility = WGPUShaderStage_Compute,
            .buffer { .type = WGPUBufferBindingType_Storage },
        }
    };

    WGPUBindGroupLayoutDescriptor ctx_layout_desc {
        .label = WGPU_STRING("SHA256::context"),
        .entryCount = 2,
        .entries = sha256_ctx_bindings,
    };

    sha256_context_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &ctx_layout_desc);

    WGPUBindGroupLayoutEntry sha256_buffer_bindings[] = {
        {
            .binding = 0,
            .visibility = WGPUShaderStage_Compute,
            .buffer { .type = WGPUBufferBindingType_ReadOnlyStorage },
        },
    };

    WGPUBindGroupLayoutDescriptor layoutDesc {
        .label = WGPU_STRING("SHA256::buffer"),
        .entryCount = 1,
        .entries = sha256_buffer_bindings,
    };
        
    sha256_buffer_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &layoutDesc);

    // ------------------------------------------------------------

    WGPUBindGroupLayout init_layouts[1] {
        sha256_context_layout_
    };

    WGPUBindGroupLayout update_layouts[2] {
        sha256_context_layout_,
        sha256_buffer_layout_,
    };
    
    WGPUPipelineLayoutDescriptor pipelineDesc {
        .bindGroupLayoutCount = 1,
        .bindGroupLayouts = init_layouts,
    };
    
    WGPUPipelineLayout init_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 2;
    pipelineDesc.bindGroupLayouts     = update_layouts;
    WGPUPipelineLayout update_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    WGPUComputePipelineDescriptor compute_desc {
        .layout = init_pipeline_layout,
        .compute { .module = sha_shader_ },
    };

    compute_desc.label = WGPU_STRING("sha256 init");
    compute_desc.compute.entryPoint = WGPU_STRING("sha256_init");
    sha256_init_ = wgpuDeviceCreateComputePipeline(device_, &compute_desc);

    compute_desc.label = WGPU_STRING("sha256 final");
    compute_desc.compute.entryPoint = WGPU_STRING("sha256_final");
    sha256_final_ = wgpuDeviceCreateComputePipeline(device_, &compute_desc);

    compute_desc.layout = update_pipeline_layout;

    compute_desc.label = WGPU_STRING("sha256 update");
    compute_desc.compute.entryPoint = WGPU_STRING("sha256_update");
    sha256_update_ = wgpuDeviceCreateComputePipeline(device_, &compute_desc);

    wgpuPipelineLayoutRelease(init_pipeline_layout);
    wgpuPipelineLayoutRelease(update_pipeline_layout);
}


void webgpu_context::sha256_digest_init(webgpu::buffer_binding ctx) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("sh256_digest_init") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    // Clear context buffer
    auto& sha256_ctx = ctx.buffers()[0];
    wgpuCommandEncoderClearBuffer(encoder,
                                  sha256_ctx.get(),
                                  sha256_ctx.offset(),
                                  sha256_ctx.size());
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, sha256_init_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, ctx.get(), 0, nullptr);

    wgpuComputePassEncoderDispatchWorkgroups(
        pass, calc_blocks(sha_instances_, workgroup_size), 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}


void webgpu_context::sha256_digest_update(webgpu::buffer_binding ctx, webgpu::buffer_binding buf) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("sha256_digest_update") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, sha256_update_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, ctx.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, buf.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(
        pass, calc_blocks(sha_instances_, workgroup_size), 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}


void webgpu_context::sha256_digest_final(webgpu::buffer_binding ctx) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("sha256_digest_final") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, sha256_final_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, ctx.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(
        pass, calc_blocks(sha_instances_, workgroup_size), 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

// template <typename LimbType, size_t NumLimbs>
void webgpu_context::sampling_init(const std::vector<size_t>& index) {    
    WGPUBindGroupLayoutEntry index_binding[] = {
        {
            .binding = 3,
            .visibility = WGPUShaderStage_Compute,
            .buffer { .type = WGPUBufferBindingType_Uniform }
        },
    };

    WGPUBindGroupLayoutDescriptor index_desc {
        .label = WGPU_STRING("Sampling::index"),
        .entryCount = sizeof(index_binding) / sizeof(WGPUBindGroupLayoutEntry),
        .entries = index_binding,
    };

    auto index_layout = wgpuDeviceCreateBindGroupLayout(device_, &index_desc);

    {
        WGPUBindGroupLayoutEntry bindings[2] = {
            {
                .binding    = 1,
                .visibility = WGPUShaderStage_Compute,
                .buffer     = { .type = WGPUBufferBindingType_ReadOnlyStorage }
            },
            {
                .binding    = 3,
                .visibility = WGPUShaderStage_Compute,
                .buffer     = {
                    .type = WGPUBufferBindingType_Storage,
                    .hasDynamicOffset = true,
                }
            },
        };

        WGPUBindGroupLayoutDescriptor desc {
            .label = WGPU_STRING("Sampling::buffer"),
            .entryCount = 2,
            .entries = bindings,
        };

        sampling_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &desc);
    }

    // --------------------------------------------------
    {
        WGPUBindGroupLayout layouts[] {            
            sampling_layout_,
            index_layout,
        };
        
        WGPUPipelineLayoutDescriptor pipelineDesc {
            .bindGroupLayoutCount = 2,
            .bindGroupLayouts = layouts,
        };

        WGPUPipelineLayout layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

        WGPUComputePipelineDescriptor desc {
            .layout = layout,
            .compute { .module = ntt_shader_ },
        };

        desc.compute.entryPoint = WGPU_STRING("sample_gather");
        sampling_gather_ = wgpuDeviceCreateComputePipeline(device_, &desc);

        wgpuPipelineLayoutRelease(layout);
    }

    // --------------------------------------------------
    num_samplings_           = index.size();
    num_sampling_workgroups_ = calc_blocks(index.size(), workgroup_size);

    // Pad the index to satisfy uniform 16 byte alignment requirement
    std::vector<webgpu::device_uint128_t> padded_index(index.size());
    for (size_t i = 0; i < index.size(); i++) {
        padded_index[i] = index[i];
    }
    
    sampling_index_buf_ = make_uniform_buffer(padded_index.size() * sizeof(webgpu::device_uint128_t));
    write_buffer(sampling_index_buf_, padded_index.data(), padded_index.size());

    // --------------------------------------------------

    WGPUBindGroupEntry entries[] = {
        {
            .binding = 3,
            .buffer  = sampling_index_buf_.get(),
            .offset  = sampling_index_buf_.offset(),
            .size    = sampling_index_buf_.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = index_layout,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    sampling_index_binding_ = wgpuDeviceCreateBindGroup(device_, &desc);
    sampling_index_binding_.buffers() = { sampling_index_buf_ };
}


void webgpu_context::sample_gather(webgpu::buffer_binding bind, size_t sampling_offset) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("sample_gather") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes = sampling_offset * num_samplings_ * device_bignum_type::num_bytes;
    wgpuComputePassEncoderSetPipeline(pass, sampling_gather_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 1, &offset_bytes);
    wgpuComputePassEncoderSetBindGroup(pass, 1, sampling_index_binding_.get(), 0, nullptr);

    wgpuComputePassEncoderDispatchWorkgroups(pass, num_sampling_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}


}  // namespace ligero
