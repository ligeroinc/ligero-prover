#include <ligetron/webgpu/powmod_context.hpp>
#include <util/log.hpp>

namespace ligero {
namespace webgpu {

powmod_context_base::powmod_context_base(device_context *device,
                                         size_t num_exponent_bits)
    : device_(device), num_exponent_bits_(num_exponent_bits)
{
    
}

powmod_context_base::~powmod_context_base() {
    release();
}

buffer_binding
powmod_context_base::bind_buffer(buffer_view exp,
                                 buffer_view coeff,
                                 buffer_view out)
{
    if (coeff.size() != out.size()) {
        LIGERO_LOG_WARNING << std::format("Unaligned powmod binding size: {}, {}",
                                          coeff.size(), out.size());
    }

    WGPUBindGroupEntry entries[] = {
        {
            .binding = 4,
            .buffer  = exp.get(),
            .offset  = exp.offset(),
            .size    = exp.size()
        },
        {
            .binding = 5,
            .buffer  = coeff.get(),
            .offset  = coeff.offset(),
            .size    = coeff.size()
        },
        {
            .binding = 6,
            .buffer  = out.get(),
            .offset  = out.offset(),
            .size    = out.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = layout_powmod_,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    buffer_binding binding = wgpuDeviceCreateBindGroup(device_->device(), &desc);
    binding.buffers() = { exp, coeff, out };
    return binding;
}

void powmod_context_base::init_layout() {
    // Initialize layout
    // --------------------------------------------------
    {
        WGPUBindGroupLayoutEntry powmod_bindings[3] = {
            {
                .binding = 4,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_ReadOnlyStorage,
                    .hasDynamicOffset = false
                },
            },
            {
                .binding = 5,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_ReadOnlyStorage,
                    .hasDynamicOffset = false
                },
            },
            {
                .binding = 6,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_Storage,
                    .hasDynamicOffset = false
                },
            }
        };

        WGPUBindGroupLayoutDescriptor powmod_desc {
            .label = "Bignum::powmod_buffer",
            .entryCount = 3,
            .entries = powmod_bindings,
        };

        layout_powmod_ = wgpuDeviceCreateBindGroupLayout(device_->device(), &powmod_desc);
    }
    
    {
        WGPUBindGroupLayoutEntry powmod_precomp_bindings[1] = {
            {
                .binding = 4,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_Uniform,
                },
            },
        };

        WGPUBindGroupLayoutDescriptor powmod_precomp_desc {
            .label = WGPU_STRING("Bignum::powmod_precompute_layout"),
            .entryCount = 1,
            .entries = powmod_precomp_bindings,
        };

        layout_powmod_precompute_ = wgpuDeviceCreateBindGroupLayout(device_->device(), &powmod_precomp_desc);
    }
}

void powmod_context_base::init_pipeline(WGPUShaderModule shader) {
    // Initialize pipeline
    // --------------------------------------------------
    WGPUBindGroupLayout powmod_binds[2] = {
        layout_powmod_,
        layout_powmod_precompute_,
    };
    
    WGPUPipelineLayoutDescriptor pipelineDesc {
        .bindGroupLayoutCount = 2,
        .bindGroupLayouts = powmod_binds,
    };

    WGPUPipelineLayout powmod_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_->device(), &pipelineDesc);

    {
        WGPUComputePipelineDescriptor powmod_desc {
            .layout = powmod_pipeline_layout,
            .compute {
                .module = shader,
            }
        };

        powmod_desc.compute.entryPoint = WGPU_STRING("EltwisePowMod");
        pipeline_powmod_ = wgpuDeviceCreateComputePipeline(device_->device(), &powmod_desc);

        powmod_desc.compute.entryPoint = WGPU_STRING("EltwisePowAddMod");
        pipeline_powmod_add_ = wgpuDeviceCreateComputePipeline(device_->device(), &powmod_desc);
    }

    wgpuPipelineLayoutRelease(powmod_pipeline_layout);
}

void powmod_context_base::release() {
    if (layout_powmod_) {
        wgpuBindGroupLayoutRelease(layout_powmod_);
        layout_powmod_ = nullptr;
    }
    if (layout_powmod_precompute_) {
        wgpuBindGroupLayoutRelease(layout_powmod_precompute_);
        layout_powmod_precompute_ = nullptr;
    }
    if (pipeline_powmod_) {
        wgpuComputePipelineRelease(pipeline_powmod_);
        pipeline_powmod_ = nullptr;
    }
    if (pipeline_powmod_add_) {
        wgpuComputePipelineRelease(pipeline_powmod_add_);
        pipeline_powmod_add_ = nullptr;
    }
}

void powmod_context_base::powmod_kernel(buffer_binding bind, size_t threads) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwisePowMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_->device(), &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, pipeline_powmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind_precompute_.get(), 0, nullptr);
    
    wgpuComputePassEncoderDispatchWorkgroups(pass, threads, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    device_->submit(command);
}

void powmod_context_base::powmod_add_kernel(buffer_binding bind, size_t threads) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwisePowAddMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_->device(), &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, pipeline_powmod_add_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, bind.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind_precompute_.get(), 0, nullptr);
    wgpuComputePassEncoderDispatchWorkgroups(pass, threads, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    device_->submit(command);    
}

template <typename Bignum>
powmod_context<Bignum>::powmod_context(device_context *engine, size_t num_exponent_bits)
    : powmod_context_base(engine, num_exponent_bits) { }

template <typename Bignum>
void powmod_context<Bignum>::init_precompute() {
    const size_t buffer_size = num_exponent_bits_ * Bignum::num_bytes;
    buf_precompute_ = device_->make_uniform_buffer(buffer_size);

    // Create bindgroup for precompute table
    WGPUBindGroupEntry entries[] = {
        {
            .binding = 4,
            .buffer  = buf_precompute_.get(),
            .offset  = buf_precompute_.offset(),
            .size    = buf_precompute_.size()
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = layout_powmod_precompute_,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    bind_precompute_ = wgpuDeviceCreateBindGroup(device_->device(), &desc);
    bind_precompute_.buffers() = { buf_precompute_ };
}



template <typename Bignum>
void powmod_context<Bignum>::set_base(const mpz_class& base, const mpz_class& p) {
    std::vector<Bignum> precomp(num_exponent_bits_);

    // Set precomp[i] = r^(2^i)R mod p (Montgomery form)
    // The shader code will start with 1 (**NOT** in Montgomery form)
    // such that after Montgomery reduction we don't need convert the result back
    assert(base < p);
    mpz_class rpow = base;    
    for (int i = 0; i < precomp.size(); i++) {
        // r' = r * beta mod p
        precomp[i] = (rpow << Bignum::num_bits) % p;
        rpow = (rpow * rpow) % p;
    }

    device_->write_buffer(buf_precompute_,
                          precomp.data(),
                          precomp.size());
}

template struct powmod_context<device_uint256_t>;

}  // namespace webgpu
}  // namespace ligero

