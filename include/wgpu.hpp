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
#include <cmath>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <numeric>
#include <sstream>
#include <thread>
#include <vector>

#include <params.hpp>
#include <util/log.hpp>
#include <ligetron/webgpu/common.hpp>
#include <ligetron/webgpu/buffer_binding.hpp>
#include <ligetron/webgpu/buffer_view.hpp>
#include <ligetron/webgpu/device_bignum.hpp>
#include <ligetron/webgpu/device_context.hpp>
#include <ligetron/webgpu/powmod_context.hpp>

#include <gmp.h>
#include <gmpxx.h>

#include <webgpu/webgpu.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#endif

using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace ligero {

struct webgpu_context : public webgpu::device_context {    
    using buffer_type        = webgpu::buffer_view;
    using device_bignum_type = webgpu::device_uint256_t;

    struct ntt_config_t {
        device_bignum_type N_inv;
        uint32_t N;
        uint32_t log2N;
        uint32_t M;
        uint32_t iter;
        uint32_t _padding[64 - 4 - device_bignum_type::num_limbs];
    };
    
    struct sha256_context {
        uint32_t data[64];
        uint32_t datalen;
        uint32_t bitlen[2];
        uint32_t state[8];
    };

    webgpu_context();
    ~webgpu_context();

    void webgpu_init(size_t num_hardware_cores, fs::path shader_root_path = "");
    
    void ntt_init(uint32_t origin_size,
                  uint32_t padded_size,
                  uint32_t code_size,
                  const mpz_class& p,
                  const mpz_class& barrett_factor,
                  const mpz_class& root_k,
                  const mpz_class& root_2k,
                  const mpz_class& root_n);

    void powmod_init(size_t num_exponent_bits);
    void powmod_set_base(const mpz_class& base, const mpz_class& p);

    webgpu::buffer_binding bind_scalar(buffer_type s);
    webgpu::buffer_binding bind_eltwise2(buffer_type x, buffer_type out);
    webgpu::buffer_binding bind_eltwise3(buffer_type x, buffer_type y, buffer_type out);
    webgpu::buffer_binding bind_sha256_context(buffer_type context, buffer_type digest);
    webgpu::buffer_binding bind_sha256_buffer(buffer_type input);
    webgpu::buffer_binding bind_sampling(buffer_type from, buffer_type to);
    webgpu::buffer_binding bind_ntt(buffer_type buf);
    webgpu::buffer_binding bind_powmod(buffer_type exp,
                                       buffer_type coeff,
                                       buffer_type out);

    void EltwiseAddMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});
    void EltwiseSubMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});
    void EltwiseMultMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});
    void EltwiseDivMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});
    void EltwiseFMAMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});
    void EltwiseBitDecompose(webgpu::buffer_binding bind, size_t i, webgpu::eltwise_offset element_offsets = {});
    // Compute element-wise out = coeff * base ^ exp mod p
    void EltwisePowMod(webgpu::buffer_binding bind);
    // Compute element-wise out = out + coeff * base ^ exp mod p
    void EltwisePowAddMod(webgpu::buffer_binding bind);

    void EltwiseAddMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseSubConstMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseConstSubMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseMultMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseMontMultMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseFMAMod(webgpu::buffer_binding bind, const mpz_class& k, webgpu::eltwise_offset element_offsets = {});
    void EltwiseAddAssignMod(webgpu::buffer_binding bind, webgpu::eltwise_offset element_offsets = {});

    // NTT
    // --------------------------------------------------
    void ntt_forward_kernel(WGPUComputePassEncoder pass,
                            std::vector<webgpu::buffer_binding>& config,
                            webgpu::buffer_binding bind,
                            size_t N);
    void ntt_inverse_kernel(WGPUComputePassEncoder pass,
                            std::vector<webgpu::buffer_binding>& config,
                            webgpu::buffer_binding bind,
                            size_t N);
    
    void ntt_forward_k(webgpu::buffer_binding bind);
    void ntt_forward_2k(webgpu::buffer_binding bind);
    void ntt_forward_n(webgpu::buffer_binding bind);

    void ntt_inverse_k(webgpu::buffer_binding bind);
    void ntt_inverse_2k(webgpu::buffer_binding bind);
    void ntt_inverse_n(webgpu::buffer_binding bind);

    void encode_ntt_device(webgpu::buffer_binding msg);
    void decode_ntt_device(webgpu::buffer_binding code);

    // SHA256
    // --------------------------------------------------
    void sha256_init(size_t num_instances);
    void sha256_digest_init(webgpu::buffer_binding ctx);
    void sha256_digest_update(webgpu::buffer_binding ctx, webgpu::buffer_binding buf);
    void sha256_digest_final(webgpu::buffer_binding ctx);

    // Sampling
    // --------------------------------------------------
    void sampling_init(const std::vector<size_t>&);
    void sample_gather(webgpu::buffer_binding bind, size_t sampling_offset);

    // --------------------------------------------------

    uint32_t message_size() const { return size_l_; }
    uint32_t padding_size() const { return size_k_; }
    uint32_t encoding_size() const { return size_n_; }

    // --------------------------------------------------

    buffer_type make_message_buffer() {
        return make_device_buffer(message_size() * device_bignum_type::num_bytes);
    }

    buffer_type make_codeword_buffer() {
        return make_device_buffer(encoding_size() * device_bignum_type::num_bytes);
    }

    buffer_type make_sample_buffer() {
        return make_device_buffer(vm::params::sample_size * device_bignum_type::num_bytes);
    }

    void write_limbs(buffer_type buf, const mpz_class& val, size_t size) {
        device_bignum_type tmp(val);
        std::vector<device_bignum_type> host_buf(size, tmp);
        write_buffer(buf, host_buf.data(), host_buf.size());
    }

    void write_limbs(buffer_type buf, const std::vector<mpz_class>& vals) {
        std::vector<device_bignum_type> host_buf(vals.size());
        for (size_t i = 0; i < vals.size(); i++) {
            host_buf[i] = vals[i];
        }
        write_buffer(buf, host_buf.data(), host_buf.size());
    }

private:
    void ntt_init_layouts();
    void ntt_init_pipelines();
    void ntt_init_constants(uint32_t origin_size,
                            uint32_t padded_size,
                            uint32_t code_size);
    void ntt_init_buffer();
    void ntt_init_config(const mpz_class& p,
                         const mpz_class& barrett_factor,
                         const mpz_class& root_k,
                         const mpz_class& root_2k,
                         const mpz_class& root_n);
    void ntt_precompute_omegas(const mpz_class& p,
                               const mpz_class& nth_root,
                               uint32_t N,
                               std::vector<buffer_type>& omegas_buf,
                               std::vector<buffer_type>& omegas_inv_buf,
                               buffer_type config_buf);

    webgpu::powmod_context<device_bignum_type>* get_powmod_context();

    
    fs::path shader_root_path_;

    int      num_submitted_tasks_;
    uint32_t num_hardware_cores_;

    uint32_t num_default_workgroups_;
    uint32_t num_ntt_shared_msg_workgroups_;
    uint32_t num_ntt_shared_code_workgroups_;
    uint32_t num_sampling_workgroups_;
    
    uint32_t size_l_, size_k_, size_n_;
    uint32_t ntt_iterations_k_, ntt_iterations_2k_, ntt_iterations_n_;
    uint32_t sha_instances_;

    std::unique_ptr<webgpu::powmod_context<device_bignum_type>> powmod_ctx_;
    
    // Shader Modules
    WGPUShaderModule ntt_shader_ = nullptr;
    WGPUShaderModule sha_shader_ = nullptr;

    // Bindgroup Layouts
    WGPUBindGroupLayout ntt_config_layout_     = nullptr;
    WGPUBindGroupLayout ntt_layout_            = nullptr;
    WGPUBindGroupLayout scalar_layout_         = nullptr;
    WGPUBindGroupLayout eltwise_layout2_       = nullptr;
    WGPUBindGroupLayout eltwise_layout3_       = nullptr;
    WGPUBindGroupLayout sha256_context_layout_ = nullptr;
    WGPUBindGroupLayout sha256_buffer_layout_  = nullptr;
    WGPUBindGroupLayout sampling_layout_       = nullptr;

    // Bindings
    std::vector<webgpu::buffer_binding> ntt_forward_bindings_k_;
    std::vector<webgpu::buffer_binding> ntt_inverse_bindings_k_;
    std::vector<webgpu::buffer_binding> ntt_forward_bindings_2k_;
    std::vector<webgpu::buffer_binding> ntt_inverse_bindings_2k_;
    std::vector<webgpu::buffer_binding> ntt_forward_bindings_n_;
    std::vector<webgpu::buffer_binding> ntt_inverse_bindings_n_;
    webgpu::buffer_binding scalar_binding_; 
    webgpu::buffer_binding sampling_index_binding_;

    // Compute Pipelines
    // --------------------------------------------------
    // NTT
    WGPUComputePipeline ntt_forward_        = nullptr;
    WGPUComputePipeline ntt_inverse_        = nullptr;
    WGPUComputePipeline ntt_forward_shared_ = nullptr;
    WGPUComputePipeline ntt_inverse_shared_ = nullptr;
    WGPUComputePipeline ntt_bit_reverse_    = nullptr;
    WGPUComputePipeline ntt_adjust_inverse_ = nullptr;
    WGPUComputePipeline ntt_reduce_         = nullptr;
    WGPUComputePipeline ntt_fold_           = nullptr;

    // Eltwise operations
    WGPUComputePipeline eltwise_addmod_  = nullptr;
    WGPUComputePipeline eltwise_submod_  = nullptr;
    WGPUComputePipeline eltwise_mulmod_  = nullptr;
    WGPUComputePipeline eltwise_divmod_  = nullptr;
    WGPUComputePipeline eltwise_addcmod_ = nullptr;
    WGPUComputePipeline eltwise_subcmod_ = nullptr;
    WGPUComputePipeline eltwise_csubmod_ = nullptr;
    WGPUComputePipeline eltwise_mulcmod_ = nullptr;
    WGPUComputePipeline eltwise_montmul_ = nullptr;
    WGPUComputePipeline eltwise_bit_decompose_ = nullptr;
    WGPUComputePipeline eltwise_fma_     = nullptr;
    WGPUComputePipeline eltwise_fmac_    = nullptr;
    WGPUComputePipeline eltwise_addassignmod_  = nullptr;

    // SHA256
    WGPUComputePipeline sha256_init_   = nullptr;
    WGPUComputePipeline sha256_update_ = nullptr;
    WGPUComputePipeline sha256_final_  = nullptr;

    // GPU Sampling
    WGPUComputePipeline sampling_gather_ = nullptr;

    // Internal States
    // --------------------------------------------------
    // NTT contexts
    buffer_type ntt_config_k_, ntt_config_2k_, ntt_config_n_;
    
    std::vector<buffer_type> ntt_omegas_k_,  ntt_omegas_2k_, ntt_omegas_n_;
    std::vector<buffer_type> ntt_omegasinv_k_, ntt_omegasinv_2k_, ntt_omegasinv_n_;

    buffer_type scalar_buf_;

    // Sampling Indexes
    size_t num_samplings_;
    buffer_type sampling_index_buf_;
};


}  // namespace ligero
