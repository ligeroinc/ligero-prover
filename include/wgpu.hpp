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

#include <gmp.h>
#include <gmpxx.h>

#include <webgpu/webgpu.h>

#if defined(__EMSCRIPTEN__)
#include <emscripten.h>
#endif

#define WGPU_DEFAULT_WORKGROUP_SIZE  256
#define WGPU_DESKTOP_MAX_BUFFER_SIZE 2147483648

#if defined(__EMSCRIPTEN__)
#define WGPU_STRING(s) s
#else
#define WGPU_STRING(s) WGPUStringView{ s, strlen(s) }
#endif

using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace ligero {

template <typename T>
struct async_waiter {
    T data;
    bool done = false;
};

std::string format_error(WGPUErrorType err, const char *msg) {
    switch (err) {
    case WGPUErrorType_NoError:
        return std::format("No Error: {}", msg);
    case WGPUErrorType_Validation:
        return std::format("Validation Error: {}", msg);
    case WGPUErrorType_OutOfMemory:
        return std::format("Out of Memory: {}", msg);
    case WGPUErrorType_Internal:
        return std::format("Internal Error: {}", msg);
    case WGPUErrorType_Unknown:
        return std::format("Unknown Error: {}", msg);
    default:
        return std::format("<Uncaptured Type>: {}", msg);
    }
}

template <size_t Limbs>
struct webgpu_bignum {
    static constexpr size_t limb_size = sizeof(uint32_t);
    static constexpr size_t num_limbs = Limbs;
    
    webgpu_bignum() : limbs() { }
    webgpu_bignum(int i) : limbs() { limbs[0] = static_cast<uint32_t>(i); }
    webgpu_bignum(uint32_t i) : limbs{i} { }
    webgpu_bignum(uint64_t i) : limbs() {
        limbs[0] = i & 0xFFFFFFFFu;
        limbs[1] = i >> 32 & 0xFFFFFFFFu;
    }
    webgpu_bignum(const mpz_class& val) : limbs() { set_mpz(val); }

    webgpu_bignum& operator=(int i) {
        limbs[0] = static_cast<uint32_t>(i);
        return *this;
    }

    webgpu_bignum& operator=(uint32_t i) {
        limbs[0] = i;
        return *this;
    }

    webgpu_bignum& operator=(uint64_t i) {
        limbs[0] = i & 0xFFFFFFFFu;
        limbs[1] = i >> 32 & 0xFFFFFFFFu;
        return *this;
    }
        
    webgpu_bignum& operator=(const mpz_class& val) {
        set_mpz(val);
        return *this;
    }

    void set_mpz(const mpz_class& val) {
        size_t words;
        mpz_export(limbs, &words, -1, sizeof(uint32_t), -1, 0, val.get_mpz_t());
        for (size_t i = words; i < num_limbs; i++) {
            limbs[i] = 0u;
        }
    }

    mpz_class to_mpz() const {
        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), num_limbs, -1, sizeof(uint32_t), -1, 0, limbs);
        return tmp;
    }
    
    uint32_t limbs[num_limbs];
};

using webgpu_vec4u_t = webgpu_bignum<4>;

template <size_t NumLimbs>
struct global_config_t {
    webgpu_bignum<NumLimbs> p;
    webgpu_bignum<NumLimbs> double_p;
    webgpu_bignum<NumLimbs> J;
    webgpu_bignum<NumLimbs> barrett_factor;
    webgpu_bignum<NumLimbs> constant;
};

template <size_t NumLimbs>
struct ntt_config_t {
    webgpu_bignum<NumLimbs> N_inv;
    uint32_t N;
    uint32_t log2N;
    uint32_t M;
    uint32_t iter;
    uint32_t _padding[64 - 4 - NumLimbs];
};


WGPUShaderModule load_shader(const fs::path& path, WGPUDevice device) {
    if (!fs::exists(path)) {
        LIGERO_LOG_FATAL <<
            std::format("Shader file {} does not exists!", path.c_str());
        exit(EXIT_FAILURE);
    }
    
    std::ifstream ifs(path);
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string source = ss.str();

    WGPUShaderModuleWGSLDescriptor wgslDesc {
        .chain = WGPUChainedStruct {
            .next = nullptr,
#if defined(__EMSCRIPTEN__)
            .sType = WGPUSType_ShaderModuleWGSLDescriptor,
#else
            // use Dawn's type
            .sType = WGPUSType_ShaderSourceWGSL,
#endif

        },
        .code = WGPU_STRING(source.c_str())
    };

    WGPUShaderModuleDescriptor desc {
        .nextInChain = (WGPUChainedStruct*)&wgslDesc,
        .label = WGPU_STRING(path.c_str()),
    };

    return wgpuDeviceCreateShaderModule(device, &desc);
}

WGPUComputePipeline prepare_pipeline(WGPUDevice device, WGPUComputePipelineDescriptor desc) {
    return wgpuDeviceCreateComputePipeline(device, &desc);
}

#if defined(__EMSCRIPTEN__)
extern "C" {
EMSCRIPTEN_KEEPALIVE
WGPUAdapter wgpuRequestAdapterSync(WGPUInstance instance) {
    async_waiter<WGPUAdapter> waiter;
    WGPURequestAdapterOptions options {
        // Always request the most powerful GPU
        .powerPreference = WGPUPowerPreference_HighPerformance
    };

    wgpuInstanceRequestAdapter(
        instance,
        &options,
        [](WGPURequestAdapterStatus s, WGPUAdapter a, const char *msg, void *waiter) {
            auto *w = reinterpret_cast<async_waiter<WGPUAdapter>*>(waiter);
            if (s == WGPURequestAdapterStatus_Success) {
                w->data = a;
            }
            else {
                std::cout << "ERROR: Failed to request adapter: " << msg << std::endl;
            }
        
            w->done = true;
        }, (void*)&waiter);

    while (!waiter.done) { emscripten_sleep(1); }

    if (waiter.data == nullptr) {
        exit(EXIT_FAILURE);
    }

    return waiter.data;
}
}
#else
WGPUAdapter wgpuRequestAdapterSync(WGPUInstance instance) {
    WGPUAdapter adapter;
    
    WGPURequestAdapterOptions options {
        // Always request the most powerful GPU
        .powerPreference = WGPUPowerPreference_HighPerformance
    };

    WGPURequestAdapterCallbackInfo info {
        .nextInChain = nullptr,
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPURequestAdapterStatus s,
                       WGPUAdapter a,
                       WGPUStringView msg,
                       void *ud1, void *ud2)
            {
                if (s != WGPURequestAdapterStatus_Success) {
                    LIGERO_LOG_ERROR
                        << "Failed to request adapter: "
                        << std::string_view(msg.data, msg.length);
                }
                *reinterpret_cast<WGPUAdapter*>(ud1) = a;
            },
        .userdata1 = &adapter,
    };

    auto f = wgpuInstanceRequestAdapter(instance, &options, info);

    WGPUFutureWaitInfo wait { .future = f };
    WGPUWaitStatus status = wgpuInstanceWaitAny(instance, 1, &wait, UINT64_MAX);
    if (status != WGPUWaitStatus_Success) {
        std::cerr << "Error: " << "failed to request webgpu adapter: ";
        switch (status) {
            case WGPUWaitStatus_TimedOut:
                std::cerr << "timeout" << std::endl;
                break;
            case WGPUWaitStatus_Error:
                std::cerr << "unknown error" << std::endl;
                break;
            default: break;
        }
    }
    return adapter;
}
#endif

#if defined(__EMSCRIPTEN__)
extern "C" {
EMSCRIPTEN_KEEPALIVE
WGPUDevice wgpuRequestDeviceSync(WGPUInstance instance, WGPUAdapter adapter) {
    async_waiter<WGPUDevice> waiter;

    WGPUDeviceDescriptor desc {
        .label = WGPU_STRING("LigetronWebGPU"),
        .requiredFeatureCount = 0,
        .requiredLimits = nullptr, // use default limits
        .deviceLostCallback = [](WGPUDeviceLostReason reason, const char* msg, void*) {
            std::string reason_str;
            switch (reason) {
            case WGPUDeviceLostReason_Unknown:
                reason_str = "DeviceLostReason::Unknown"; break;
            case WGPUDeviceLostReason_Destroyed:
                reason_str = "DeviceLostReason::Destroyed"; break;
            default:
                reason_str = "DeviceLostReason::<Uncaptured>";
            }
            std::cout << std::format("Device Disconnected due to {}, {}",
                                     reason_str,
                                     msg);
        },
    };

    wgpuAdapterRequestDevice(
        adapter,
        &desc,
        [](WGPURequestDeviceStatus s, WGPUDevice d, const char *msg, void *data) {
            auto *w = reinterpret_cast<async_waiter<WGPUDevice>*>(data);
            if (s == WGPURequestDeviceStatus_Success) {
                w->data = d;
            }
            else {
                std::cout << "ERROR: Failed to request device: " << msg << std::endl;
            }

            w->done = true;
        }, (void*)&waiter);

    while (!waiter.done) { emscripten_sleep(1); }

    if (waiter.data == nullptr) {
        exit(EXIT_FAILURE);
    }
    
    wgpuDeviceSetUncapturedErrorCallback(
        waiter.data,
        [](WGPUErrorType err, const char *msg, void *) {
            std::cout << format_error(err, msg) << std::endl;
        }, nullptr);

    return waiter.data;
}
}
#else
WGPUDevice wgpuRequestDeviceSync(WGPUInstance instance, WGPUAdapter adapter) {
    WGPUDeviceLostCallbackInfo lost {
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPUDevice const * device, WGPUDeviceLostReason reason, WGPUStringView msg, void*, void*) {
            std::string reason_str;
            switch (reason) {
            case WGPUDeviceLostReason_Unknown:
                reason_str = "DeviceLostReason::Unknown"; break;
            case WGPUDeviceLostReason_Destroyed:
                reason_str = "DeviceLostReason::Destroyed"; break;
            case WGPUDeviceLostReason_CallbackCancelled:
                reason_str = "DeviceLostReason::CallbackCancelled"; break;
            case WGPUDeviceLostReason_FailedCreation:
                reason_str = "DeviceLostReason::FailedCreation"; break;
            default:
                reason_str = "DeviceLostReason::<Uncaptured>";
            }
            LIGERO_LOG_INFO
                << std::format("Device Disconnected due to {}, {}",
                               reason_str,
                               std::string_view(msg.data, msg.length));
        },
        .userdata1 = nullptr,
        .userdata2 = nullptr
    };

    WGPUUncapturedErrorCallbackInfo err {
        .callback = [](WGPUDevice const *, WGPUErrorType type, WGPUStringView msg, void* , void*) {
            LIGERO_LOG_ERROR << format_error(type, msg.data);
            std::abort();
        }
    };

    WGPULimits limits = WGPU_LIMITS_INIT;

    bool success = wgpuAdapterGetLimits(adapter, &limits);
    if (!success) {
        LIGERO_LOG_WARNING << "Cannot get device limits, use default limits" << std::endl;
    }
    else {
        if (limits.maxStorageBufferBindingSize >= WGPU_DESKTOP_MAX_BUFFER_SIZE) {
            limits.maxStorageBufferBindingSize = WGPU_DESKTOP_MAX_BUFFER_SIZE;
        }
        else {
            LIGERO_LOG_WARNING
                << std::format("Required maxStorageBufferBindingSize={}, max supported {}",
                               limits.maxStorageBufferBindingSize,
                               WGPU_DESKTOP_MAX_BUFFER_SIZE);
        }

        if (limits.maxBufferSize >= WGPU_DESKTOP_MAX_BUFFER_SIZE) {
            limits.maxBufferSize = WGPU_DESKTOP_MAX_BUFFER_SIZE;
        }
        else {
            LIGERO_LOG_WARNING
                << std::format("Required maxBufferSize={}, max supported {}",
                               limits.maxBufferSize,
                               WGPU_DESKTOP_MAX_BUFFER_SIZE);
        }
    }

    const char *disabled_toggle_names[] = {
        "enable_integer_range_analysis_in_robustness"
    };

    WGPUDawnTogglesDescriptor toggles {
        .chain = {
            .next = nullptr,
            .sType = WGPUSType_DawnTogglesDescriptor
        },
        .enabledToggleCount  = 0,
        .enabledToggles      = nullptr,
        .disabledToggleCount = 1,
        .disabledToggles     = disabled_toggle_names
    };
      
    WGPUDeviceDescriptor desc {
        .nextInChain                  = &toggles.chain,
        .label                        = WGPU_STRING("LigetronWebGPU"),
        .requiredFeatureCount         = 0,
        .requiredFeatures             = nullptr,
        .requiredLimits               = &limits,
        .deviceLostCallbackInfo       = lost,
        .uncapturedErrorCallbackInfo  = err
    };

    WGPUDevice device;
    WGPURequestDeviceCallbackInfo info {
        .nextInChain = nullptr,
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPURequestDeviceStatus s,
                       WGPUDevice d,
                       WGPUStringView msg,
                       void *ud1, void *ud2)
            {
                if (s != WGPURequestDeviceStatus_Success) {
                    LIGERO_LOG_ERROR << "Failed to request device: "
                                     << std::string_view(msg.data, msg.length);
                }
                *reinterpret_cast<WGPUDevice*>(ud1) = d;
            },
        .userdata1 = &device,
    };

    auto f = wgpuAdapterRequestDevice(adapter, &desc, info);
    WGPUFutureWaitInfo wait { .future = f };
    WGPUWaitStatus status = wgpuInstanceWaitAny(instance, 1, &wait, UINT64_MAX);
    if (status != WGPUWaitStatus_Success) {
        std::cerr << "Error: " << "failed to request webgpu device: ";
        switch (status) {
            case WGPUWaitStatus_TimedOut:
                std::cerr << "timeout" << std::endl;
                break;
            case WGPUWaitStatus_Error:
                std::cerr << "unknown error" << std::endl;
                break;
            default: break;
        }
    }
    return device;
}
#endif

#if defined(__EMSCRIPTEN__)
extern "C" {
EMSCRIPTEN_KEEPALIVE
void wgpuBufferMapSync(WGPUInstance instance, WGPUBuffer map_buf, size_t offset, size_t size) {
    async_waiter<void*> waiter;

    wgpuBufferMapAsync(
        map_buf,
        WGPUMapMode_Read,
        offset,
        size,
        [](WGPUBufferMapAsyncStatus status, void *data) {
            auto *w = reinterpret_cast<async_waiter<void*>*>(data);
            if (status != WGPUBufferMapAsyncStatus_Success) {
                std::cout << "Map Async failed with status: " << status << std::endl;
            }
            w->done = true;
        }, (void*)&waiter);

    while (!waiter.done) { emscripten_sleep(1); }
}
}
#else
void wgpuBufferMapSync(WGPUInstance instance, WGPUBuffer map_buf, size_t offset, size_t size) {
    WGPUBufferMapCallbackInfo info {
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPUMapAsyncStatus status, WGPUStringView msg, void *ud1, void *ud2) {
            if (status != WGPUMapAsyncStatus_Success) {
                std::string status_str;
                switch(status) {
                case WGPUMapAsyncStatus_Success:
                    status_str = "[MapAsync::Success]: "; break;
                case WGPUMapAsyncStatus_CallbackCancelled:
                    status_str = "[MapAsync::CallbackCancelled]: "; break;
                case WGPUMapAsyncStatus_Error:
                    status_str = "[MapAsync::Error]: "; break;
                case WGPUMapAsyncStatus_Aborted:
                    status_str = "[MapAsync::Aborted]: "; break;
                default:
                    status_str = "[MapAsync::UncapturedError]: ";
                }
                LIGERO_LOG_ERROR << status_str << std::string_view(msg.data, msg.length);
            }
        }
    };
    
    auto f = wgpuBufferMapAsync(map_buf, WGPUMapMode_Read, offset, size, info);
    WGPUFutureWaitInfo wait { .future = f };
    WGPUWaitStatus status = wgpuInstanceWaitAny(instance, 1, &wait, UINT64_MAX);
    if (status != WGPUWaitStatus_Success) {
        std::cerr << "Error: " << "failed to map buffer: ";
        switch (status) {
            case WGPUWaitStatus_TimedOut:
                std::cerr << "timeout" << std::endl;
                break;
            case WGPUWaitStatus_Error:
                std::cerr << "unknown error" << std::endl;
                break;
            default: break;
        }
    }
}
#endif

#if defined(__EMSCRIPTEN__)
extern "C" {
EMSCRIPTEN_KEEPALIVE
void wgpuDeviceSynchronize(WGPUInstance instance, WGPUQueue queue) {
    bool ready = false;
    
    wgpuQueueOnSubmittedWorkDone(queue,
        [](WGPUQueueWorkDoneStatus status, void *ud1) {
            if (status != WGPUQueueWorkDoneStatus_Success) {
                std::string status_str;
                switch(status) {
                case WGPUQueueWorkDoneStatus_Success:
                    status_str = "Completed"; break;
                case WGPUQueueWorkDoneStatus_Error:
                    status_str = "Error"; break;
                case WGPUQueueWorkDoneStatus_Unknown:
                    status_str = "Unknown Error"; break;
                case WGPUQueueWorkDoneStatus_DeviceLost:
                    status_str = "Device Lost"; break;
                default:
                    status_str = "<Uncaptured>";
                }
                LIGERO_LOG_ERROR << std::format("Work failed with status: {}", status_str);
            }
            *reinterpret_cast<bool*>(ud1) = true;
        }, &ready);

    while (!ready) { emscripten_sleep(1); }
}
}
#else
void wgpuDeviceSynchronize(WGPUInstance instance, WGPUQueue queue) {
    WGPUQueueWorkDoneCallbackInfo info {
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPUQueueWorkDoneStatus status, WGPUStringView message, void *ud1, void *ud2) {
            if (status != WGPUQueueWorkDoneStatus_Success) {
                std::string status_str;
                switch(status) {
                case WGPUQueueWorkDoneStatus_Success:
                    status_str = "Completed"; break;
                case WGPUQueueWorkDoneStatus_CallbackCancelled:
                    status_str = "Callback cancelled"; break;
                case WGPUQueueWorkDoneStatus_Error:
                    status_str = "Error"; break;
                default:
                    status_str = "<Uncaptured>";
                }
                LIGERO_LOG_ERROR << std::format("WebGPU Work failed: {}, reason: {}", status_str, message.data);
            }
        }
    };
    
    auto f = wgpuQueueOnSubmittedWorkDone(queue, info);
    WGPUFutureWaitInfo wait { .future = f };
    WGPUWaitStatus status = wgpuInstanceWaitAny(instance, 1, &wait, UINT64_MAX);
    if (status != WGPUWaitStatus_Success) {
        std::cerr << "Error: " << "failed to synchronize device: ";
        switch (status) {
            case WGPUWaitStatus_TimedOut:
                std::cerr << "timeout" << std::endl;
                break;
            case WGPUWaitStatus_Error:
                std::cerr << "unknown error" << std::endl;
                break;
            default: break;
        }
    }
}
#endif

struct webgpu_buffer_view {
    webgpu_buffer_view() : source_(nullptr), offset_bytes_(0), size_bytes_(0) { }
    webgpu_buffer_view(WGPUBuffer buf)
        : source_(buf), offset_bytes_(0), size_bytes_(wgpuBufferGetSize(buf)) { }
    webgpu_buffer_view(WGPUBuffer buf, size_t offset)
        : source_(buf),
          offset_bytes_(offset),
          size_bytes_(wgpuBufferGetSize(buf) - offset)
        { assert(offset <= wgpuBufferGetSize(buf)); }
    webgpu_buffer_view(WGPUBuffer buf, size_t offset, size_t size)
        : source_(buf), offset_bytes_(offset), size_bytes_(size)
        { assert(offset + size <= wgpuBufferGetSize(buf)); }

    bool operator==(webgpu_buffer_view other) const noexcept {
        return (source_ == other.source_) &&
            (offset_bytes_ == other.offset_bytes_) &&
            (size_bytes_ == other.size_bytes_);
    }

    void destroy_source() {
        if (source_)
            wgpuBufferDestroy(source_);
    }

    size_t offset()      const { return offset_bytes_; }
    size_t size()        const { return size_bytes_; }
    size_t source_size() const { return wgpuBufferGetSize(source_); }
    
    WGPUBuffer get() { return source_; }

    template <typename T = unsigned char>
    webgpu_buffer_view slice_n(size_t begin, size_t n) const {
        size_t begin_bytes = begin * sizeof(T);
        size_t n_bytes     = n     * sizeof(T);
        assert(offset_bytes_ + n_bytes <= source_size());
        return webgpu_buffer_view(source_, offset_bytes_ + begin_bytes, n_bytes);
    }

    template <typename T = unsigned char>
    webgpu_buffer_view slice(size_t begin) const {
        size_t begin_bytes = begin * sizeof(T);
        size_t n_bytes     = size_bytes_ - begin_bytes;
        return slice_n(begin_bytes, n_bytes);
    }

    template <typename T = unsigned char>
    webgpu_buffer_view slice(size_t begin, size_t end) const {
        size_t n = end - begin;
        return slice_n<T>(begin, n);
    }
    
protected:
    WGPUBuffer source_;
    size_t offset_bytes_;
    size_t size_bytes_;
};


struct webgpu_binding {
    webgpu_binding() : bind_(nullptr) { }
    webgpu_binding(WGPUBindGroup bind) : bind_(bind) { }

    WGPUBindGroup get() { return bind_; }

    std::vector<webgpu_buffer_view>& buffers() { return bufs_; }
    const std::vector<webgpu_buffer_view>& buffers() const { return bufs_; }
    
    void destroy() {
        if (bind_) {
            wgpuBindGroupRelease(bind_);
        }
    }
    
protected:
    WGPUBindGroup bind_;
    std::vector<webgpu_buffer_view> bufs_;
};

struct eltwise_offset { uint32_t x, y, z; };

struct webgpu_context {
    using limb_type = uint32_t;
    static constexpr uint32_t num_limbs = 8;
    static constexpr uint32_t limb_bits = std::numeric_limits<limb_type>::digits;
    static constexpr uint32_t limb_size = sizeof(limb_type);
    static constexpr uint32_t num_element_bytes = num_limbs * limb_size;
    static constexpr uint32_t num_element_bits = num_limbs * limb_bits;

    static constexpr uint32_t max_workgroups        = 256;
    static constexpr uint32_t workgroup_size        = WGPU_DEFAULT_WORKGROUP_SIZE;
    static constexpr uint32_t ntt_shared_size       = workgroup_size * 2;
    static constexpr uint32_t ntt_shared_iterations = std::countr_zero(ntt_shared_size);
    
    using buffer_type        = webgpu_buffer_view;
    using device_bignum_type = webgpu_bignum<num_limbs>;

    struct sha256_context {
        uint32_t data[64];
        uint32_t datalen;
        uint32_t bitlen[2];
        uint32_t state[8];
    };

    webgpu_context() = default;
    ~webgpu_context();

    void webgpu_init(size_t num_hardware_cores, fs::path shader_root_path = "");
    void webgpu_free();
    
    void ntt_init(uint32_t origin_size,
                  uint32_t padded_size,
                  uint32_t code_size,
                  const mpz_class& p,
                  const mpz_class& barrett_factor,
                  const mpz_class& root_k,
                  const mpz_class& root_2k,
                  const mpz_class& root_n);

    void device_synchronize();
    void submit(WGPUCommandBuffer command);

    webgpu_binding bind_eltwise2(buffer_type x, buffer_type out);
    webgpu_binding bind_eltwise3(buffer_type x, buffer_type y, buffer_type out);
    webgpu_binding bind_sha256_context(buffer_type context, buffer_type digest);
    webgpu_binding bind_sha256_buffer(buffer_type input);
    webgpu_binding bind_sampling(buffer_type from, buffer_type to);
    webgpu_binding bind_ntt(buffer_type buf);

    void set_global_constant(const mpz_class& k);
    void EltwiseAddMod(webgpu_binding bind, eltwise_offset element_offsets = {});
    void EltwiseSubMod(webgpu_binding bind, eltwise_offset element_offsets = {});
    void EltwiseMultMod(webgpu_binding bind, eltwise_offset element_offsets = {});
    void EltwiseDivMod(webgpu_binding bind, eltwise_offset element_offsets = {});
    void EltwiseFMAMod(webgpu_binding bind, eltwise_offset element_offsets = {});
    void EltwiseBitDecompose(webgpu_binding bind, size_t i, eltwise_offset element_offsets = {});

    void EltwiseAddMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseSubConstMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseConstSubMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseMultMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseMontMultMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseFMAMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets = {});
    void EltwiseAddAssignMod(webgpu_binding bind, eltwise_offset element_offsets = {});

    // NTT
    // ------------------------------------------------------------
    void ntt_forward_kernel(WGPUComputePassEncoder pass,
                            std::vector<webgpu_binding>& config,
                            webgpu_binding bind,
                            size_t N);
    void ntt_inverse_kernel(WGPUComputePassEncoder pass,
                            std::vector<webgpu_binding>& config,
                            webgpu_binding bind,
                            size_t N);
    
    void ntt_forward_k(webgpu_binding bind);
    void ntt_forward_2k(webgpu_binding bind);
    void ntt_forward_n(webgpu_binding bind);

    void ntt_inverse_k(webgpu_binding bind);
    void ntt_inverse_2k(webgpu_binding bind);
    void ntt_inverse_n(webgpu_binding bind);

    void encode_ntt_device(webgpu_binding msg);
    void decode_ntt_device(webgpu_binding code);

    // SHA256
    // ------------------------------------------------------------
    void sha256_init(size_t num_instances);
    void sha256_digest_init(webgpu_binding ctx);
    void sha256_digest_update(webgpu_binding ctx, webgpu_binding buf);
    void sha256_digest_final(webgpu_binding ctx);

    // Sampling
    // ------------------------------------------------------------
    void sampling_init(const std::vector<size_t>&);
    void sample_gather(webgpu_binding bind, size_t sampling_offset);

    // ------------------------------------------------------------

    auto& device() { return device_; }

    uint32_t message_size() const { return size_l_; }
    uint32_t padding_size() const { return size_k_; }
    uint32_t encoding_size() const { return size_n_; }

    // ------------------------------------------------------------

    buffer_type make_uniform_buffer(size_t num_bytes) {
        WGPUBufferDescriptor uniform_desc {
            .usage = WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst,
            .size  = num_bytes,
        };
        return buffer_type(wgpuDeviceCreateBuffer(device_, &uniform_desc), 0, num_bytes);
    }
    
    buffer_type make_device_buffer(size_t num_bytes) {
        WGPUBufferDescriptor desc {
            .usage = WGPUBufferUsage_Storage
                   | WGPUBufferUsage_CopyDst | WGPUBufferUsage_CopySrc,
            .size = num_bytes,
        };
        return buffer_type(wgpuDeviceCreateBuffer(device_, &desc), 0, num_bytes);
    }

    buffer_type make_message_buffer() {
        return make_device_buffer(message_size() * num_element_bytes);
    }

    buffer_type make_codeword_buffer() {
        return make_device_buffer(encoding_size() * num_element_bytes);
    }

    buffer_type make_sample_buffer() {
        return make_device_buffer(vm::params::sample_size * num_element_bytes);
    }

    buffer_type make_map_buffer(size_t size_in_byte) {
        WGPUBufferDescriptor desc {
            .usage = WGPUBufferUsage_CopyDst | WGPUBufferUsage_MapRead,
            .size = size_in_byte,
        };

        return buffer_type{ wgpuDeviceCreateBuffer(device_, &desc) };
    }

    template <typename T>
    void write_buffer(buffer_type buf, const T *data, size_t len) {
        const size_t bytes = len * sizeof(T);
        assert(buf.size() >= bytes);
        wgpuQueueWriteBuffer(queue_, buf.get(), buf.offset(), data, bytes);
    }

    template <typename T>
    void write_buffer_clear(buffer_type buf, const T *data, size_t len) {
        write_buffer(buf, data, len);
        clear_buffer(buf.slice(len * sizeof(T)));
    }

    void write_limbs(buffer_type buf, const mpz_class& val, size_t size) {
        device_bignum_type tmp = val;
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

    void clear_buffer(buffer_type buf) {
        WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, nullptr);
        wgpuCommandEncoderClearBuffer(encoder, buf.get(), buf.offset(), buf.size());
        WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
        wgpuCommandEncoderRelease(encoder);
        submit(command);
    }
    
    void copy_buffer_to_buffer(buffer_type from, buffer_type to) {
        assert(from.size() <= to.size());
        copy_buffer_to_buffer(from, to, from.size());
    }

    void copy_buffer_to_buffer(buffer_type from, buffer_type to, size_t bytes) {
        WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, nullptr);
        wgpuCommandEncoderCopyBufferToBuffer(encoder,
                                             from.get(), from.offset(),
                                             to.get(), to.offset(),
                                             bytes);
        WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
        wgpuCommandEncoderRelease(encoder);
        submit(command);
    }

    void copy_buffer_clear(buffer_type from, buffer_type to) {
        WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, nullptr);
        wgpuCommandEncoderClearBuffer(encoder, to.get(), to.offset(), to.size());
        wgpuCommandEncoderCopyBufferToBuffer(encoder,
                                             from.get(), from.offset(),
                                             to.get(), to.offset(),
                                             from.size());
        WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
        wgpuCommandEncoderRelease(encoder);
        submit(command);
    }

    template <typename T>
    const T* map_read(buffer_type map_buf) {
        wgpuBufferMapSync(instance_, map_buf.get(), map_buf.offset(), map_buf.size());
        const T* ptr = (const T*)wgpuBufferGetConstMappedRange(map_buf.get(),
                                                               map_buf.offset(),
                                                               map_buf.size());
        return ptr;
    }

    template <typename T>
    std::vector<T> copy_to_host(buffer_type buf) {
        buffer_type map = make_map_buffer(buf.size());
        copy_buffer_to_buffer(buf, map);
        const T* ptr = map_read<T>(map);
        std::vector<T> tmp(ptr, ptr + buf.size() / sizeof(T));
        wgpuBufferUnmap(map.get());
        map.destroy_source();
        return tmp;
    }

private:
    size_t calc_blocks(size_t N, size_t workgroup_size) {
        return (N + workgroup_size - 1) / workgroup_size;
    }
    
    void init_instance() {
#if defined(__EMSCRIPTEN__)
        instance_ = wgpuCreateInstance(nullptr);
#else
        WGPUInstanceFeatureName features[] = {
            WGPUInstanceFeatureName_TimedWaitAny
        };

        WGPUInstanceLimits limits {
            .nextInChain          = nullptr,
            .timedWaitAnyMaxCount = 1
        };

        WGPUInstanceDescriptor desc {
            .nextInChain          = nullptr,
            .requiredFeatureCount = 1,
            .requiredFeatures     = features,
            .requiredLimits       = &limits,
        };

        instance_ = wgpuCreateInstance(&desc);
#endif

        if (!instance_) {
            throw std::runtime_error("Could not initialize WebGPU!");
        }
    }
    
    void init_adapter() {
        adapter_ = wgpuRequestAdapterSync(instance_);
    }

    void init_device() {
        device_ = wgpuRequestDeviceSync(instance_, adapter_);
    }

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
    
public:
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

    WGPUInstance instance_ = nullptr;
    WGPUAdapter  adapter_  = nullptr;
    WGPUDevice   device_   = nullptr;
    WGPUQueue    queue_    = nullptr;

    // Shader Modules
    WGPUShaderModule ntt_shader_ = nullptr;
    WGPUShaderModule sha_shader_ = nullptr;

    // Bindgroup Layouts
    WGPUBindGroupLayout global_config_layout_  = nullptr;
    WGPUBindGroupLayout ntt_config_layout_     = nullptr;
    WGPUBindGroupLayout ntt_layout_            = nullptr;
    WGPUBindGroupLayout eltwise_layout2_       = nullptr;
    WGPUBindGroupLayout eltwise_layout3_       = nullptr;
    WGPUBindGroupLayout sha256_context_layout_ = nullptr;
    WGPUBindGroupLayout sha256_buffer_layout_  = nullptr;
    WGPUBindGroupLayout sampling_layout_       = nullptr;

    // Bindings
    webgpu_binding global_config_binding_;
    std::vector<webgpu_binding> ntt_forward_bindings_k_;
    std::vector<webgpu_binding> ntt_inverse_bindings_k_;
    std::vector<webgpu_binding> ntt_forward_bindings_2k_;
    std::vector<webgpu_binding> ntt_inverse_bindings_2k_;
    std::vector<webgpu_binding> ntt_forward_bindings_n_;
    std::vector<webgpu_binding> ntt_inverse_bindings_n_;
    webgpu_binding sampling_index_binding_;

    // Compute Pipelines
    // ------------------------------------------------------------
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
    // ------------------------------------------------------------
    // NTT contexts
    webgpu_buffer_view global_config_;
    webgpu_buffer_view ntt_config_k_, ntt_config_2k_, ntt_config_n_;
    
    std::vector<webgpu_buffer_view> ntt_omegas_k_,  ntt_omegas_2k_, ntt_omegas_n_;
    std::vector<webgpu_buffer_view> ntt_omegasinv_k_, ntt_omegasinv_2k_, ntt_omegasinv_n_;

    // Sampling Indexes
    size_t num_samplings_;
    webgpu_buffer_view sampling_index_buf_;
};

// ----------------------------------------------------------------------------- //

webgpu_context::~webgpu_context() {
    device_synchronize();

    if (queue_)      wgpuQueueRelease(queue_);
    if (device_)     wgpuDeviceRelease(device_);
    if (adapter_)    wgpuAdapterRelease(adapter_);
    if (instance_)   wgpuInstanceRelease(instance_);

    if (ntt_shader_) wgpuShaderModuleRelease(ntt_shader_);
    if (sha_shader_) wgpuShaderModuleRelease(sha_shader_);

    if (global_config_layout_) wgpuBindGroupLayoutRelease(global_config_layout_);
    if (ntt_config_layout_) wgpuBindGroupLayoutRelease(ntt_config_layout_);
    if (ntt_layout_) wgpuBindGroupLayoutRelease(ntt_layout_);
    if (eltwise_layout2_) wgpuBindGroupLayoutRelease(eltwise_layout2_);
    if (eltwise_layout3_) wgpuBindGroupLayoutRelease(eltwise_layout3_);
    if (sha256_context_layout_) wgpuBindGroupLayoutRelease(sha256_context_layout_);
    if (sha256_buffer_layout_) wgpuBindGroupLayoutRelease(sha256_buffer_layout_);
    if (sampling_layout_) wgpuBindGroupLayoutRelease(sampling_layout_);

    if (ntt_forward_) wgpuComputePipelineRelease(ntt_forward_);
    if (ntt_forward_shared_) wgpuComputePipelineRelease(ntt_forward_shared_);
    if (ntt_inverse_) wgpuComputePipelineRelease(ntt_inverse_);
    if (ntt_inverse_shared_) wgpuComputePipelineRelease(ntt_inverse_shared_);
    if (ntt_bit_reverse_) wgpuComputePipelineRelease(ntt_bit_reverse_);
    if (ntt_adjust_inverse_) wgpuComputePipelineRelease(ntt_adjust_inverse_);
    if (ntt_reduce_) wgpuComputePipelineRelease(ntt_reduce_);
    if (ntt_fold_) wgpuComputePipelineRelease(ntt_fold_);

    if (eltwise_addmod_) wgpuComputePipelineRelease(eltwise_addmod_);
    if (eltwise_submod_) wgpuComputePipelineRelease(eltwise_submod_);
    if (eltwise_mulmod_) wgpuComputePipelineRelease(eltwise_mulmod_);
    if (eltwise_divmod_) wgpuComputePipelineRelease(eltwise_divmod_);
    if (eltwise_addcmod_) wgpuComputePipelineRelease(eltwise_addcmod_);
    if (eltwise_subcmod_) wgpuComputePipelineRelease(eltwise_subcmod_);
    if (eltwise_csubmod_) wgpuComputePipelineRelease(eltwise_csubmod_);
    if (eltwise_mulcmod_) wgpuComputePipelineRelease(eltwise_mulcmod_);
    if (eltwise_montmul_) wgpuComputePipelineRelease(eltwise_montmul_);
    if (eltwise_bit_decompose_) wgpuComputePipelineRelease(eltwise_bit_decompose_);
    if (eltwise_fma_) wgpuComputePipelineRelease(eltwise_fma_);
    if (eltwise_fmac_) wgpuComputePipelineRelease(eltwise_fmac_);
    if (eltwise_addassignmod_) wgpuComputePipelineRelease(eltwise_addassignmod_);

    if (sha256_init_) wgpuComputePipelineRelease(sha256_init_);
    if (sha256_update_) wgpuComputePipelineRelease(sha256_update_);
    if (sha256_final_) wgpuComputePipelineRelease(sha256_final_);

    if (sampling_gather_) wgpuComputePipelineRelease(sampling_gather_);

    global_config_.destroy_source();
    ntt_config_k_.destroy_source();
    ntt_config_2k_.destroy_source();
    ntt_config_n_.destroy_source();

    for (auto& buf : ntt_omegas_k_) { buf.destroy_source(); }
    for (auto& buf : ntt_omegasinv_k_) { buf.destroy_source(); }
    for (auto& buf : ntt_omegas_2k_) { buf.destroy_source(); }
    for (auto& buf : ntt_omegasinv_2k_) { buf.destroy_source(); }
    for (auto& buf : ntt_omegas_n_) { buf.destroy_source(); }
    for (auto& buf : ntt_omegasinv_n_) { buf.destroy_source(); }

    sampling_index_buf_.destroy_source();
}

void webgpu_context::submit(WGPUCommandBuffer command) {
#if !defined(__EMSCRIPTEN__)
    constexpr int throttle = 127;
    if ((++num_submitted_tasks_ & throttle) == 0) {
        device_synchronize();
        num_submitted_tasks_ = 0;
    }
#endif
    wgpuQueueSubmit(queue_, 1, &command);
    wgpuCommandBufferRelease(command);
}

void webgpu_context::device_synchronize() {
    if (instance_ && queue_)
        wgpuDeviceSynchronize(instance_, queue_);
}

void webgpu_context::webgpu_init(size_t num_hardware_cores, fs::path shader_root_path) {    
    init_instance();
    init_adapter();
    init_device();

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

    queue_ = wgpuDeviceGetQueue(device_);
}

void webgpu_context::webgpu_free() {
    // Wait all task finish before dropping the context
    device_synchronize();
    
    wgpuDeviceRelease(device_);
    wgpuAdapterRelease(adapter_);
    wgpuInstanceRelease(instance_);
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
    ntt_shader_ = load_shader(shader_root_path_ / "bignum.wgsl", device_);
    ntt_init_constants(origin_size, padded_size, code_size);
    ntt_init_buffer();
    ntt_init_layouts();
    ntt_init_pipelines();
    ntt_init_config(p, barrett_factor, root_k, root_2k, root_n);
}

webgpu_binding webgpu_context::bind_ntt(buffer_type code) {
    const size_t bind_size = encoding_size() * num_element_bytes;

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

    webgpu_binding ntt_bind { ntt };
    ntt_bind.buffers() = { buffer_type(code.get(), code.offset(), bind_size) };
    
    return ntt_bind;
}

webgpu_binding webgpu_context::bind_eltwise2(buffer_type x, buffer_type out) {
    if (x.size() != out.size()) {
        LIGERO_LOG_WARNING << std::format("Unaligned eltwise binding size: {}, {}",
                                          x.size(), out.size());
    }

    WGPUBindGroupEntry entries[] = {
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
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu_binding binding{ bindgroup };
    binding.buffers() = { x, out };
    return binding;
}

webgpu_binding webgpu_context::bind_eltwise3(buffer_type x, buffer_type y, buffer_type out) {
    if (x.size() != y.size() || x.size() != out.size()) {
        LIGERO_LOG_WARNING << std::format("Unaligned eltwise binding size: {}, {}, {}",
                                          x.size(), y.size(), out.size());
    }
    
    WGPUBindGroupEntry entries[] = {
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
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };

    WGPUBindGroup bindgroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu_binding binding{ bindgroup };
    binding.buffers() = { x, y, out };
    return binding;
}

webgpu_binding webgpu_context::bind_sha256_context(buffer_type ctx, buffer_type digest) {
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
    webgpu_binding binding { bindgroup};
    binding.buffers() = { ctx, digest };
    return binding;
}

webgpu_binding webgpu_context::bind_sha256_buffer(buffer_type input) {
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
    webgpu_binding binding{ bindgroup };
    binding.buffers() = { input };
    return binding;
}

webgpu_binding webgpu_context::bind_sampling(buffer_type from, buffer_type to) {
    WGPUBindGroupEntry entries[] = {
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
            .size    = num_samplings_ * num_element_bytes,
        },
    };

    WGPUBindGroupDescriptor desc {
        .layout = sampling_layout_,
        .entryCount = sizeof(entries) / sizeof(WGPUBindGroupEntry),
        .entries = entries,
    };
    
    WGPUBindGroup bindGroup = wgpuDeviceCreateBindGroup(device_, &desc);
    webgpu_binding binding{ bindGroup };
    binding.buffers() = { from, to };
    return binding;
}


void webgpu_context::set_global_constant(const mpz_class& k) {
    device_bignum_type k_buf = k;
    write_buffer(global_config_.slice(offsetof(global_config_t<num_limbs>, constant)),
                 &k_buf,
                 1);
}

void webgpu_context::EltwiseAddMod(webgpu_binding bind, eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddMod") };
    
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * num_element_bytes,
        element_offsets.y * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_addmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseAddMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddConstMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_addcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseSubMod(webgpu_binding bind, eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseSubMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * num_element_bytes,
        element_offsets.y * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_submod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseSubConstMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseSubConstMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_subcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseConstSubMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseConstSubMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_csubmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMultMod(webgpu_binding bind, eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMultMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * num_element_bytes,
        element_offsets.y * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };
    
    wgpuComputePassEncoderSetPipeline(pass, eltwise_mulmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMultMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMultConstantMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_mulcmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseDivMod(webgpu_binding bind, eltwise_offset element_offsets) {     WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseDivMod") };   
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * num_element_bytes,
        element_offsets.y * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_divmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseMontMultMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseMontMultMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_montmul_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseBitDecompose(webgpu_binding bind, size_t pos, eltwise_offset element_offsets) {
    set_global_constant(pos);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseBitDecompose") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_bit_decompose_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

// Z = Z + X * Y
void webgpu_context::EltwiseFMAMod(webgpu_binding bind, eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseFMAMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[3] {
        element_offsets.x * num_element_bytes,
        element_offsets.y * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_fma_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 3, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseFMAMod(webgpu_binding bind, const mpz_class& k, eltwise_offset element_offsets) {
    set_global_constant(k);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseFMAConstantMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_fmac_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
        
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void webgpu_context::EltwiseAddAssignMod(webgpu_binding bind, eltwise_offset element_offsets) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("EltwiseAddAssignMod") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes[2] {
        element_offsets.x * num_element_bytes,
        element_offsets.z * num_element_bytes,
    };

    wgpuComputePassEncoderSetPipeline(pass, eltwise_addassignmod_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 2, offset_bytes);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

// NTT
// ------------------------------------------------------------
void webgpu_context::encode_ntt_device(webgpu_binding msg) {
    assert(msg.buffers()[0].size() == encoding_size() * num_element_bytes);
    
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

void webgpu_context::decode_ntt_device(webgpu_binding code) {
    assert(code.buffers()[0].size() == encoding_size() * num_element_bytes);

    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("NTT Decode") };
    WGPUCommandEncoder encoder  = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);
    
    ntt_inverse_kernel(pass, ntt_inverse_bindings_n_, code, encoding_size());

    /// Copy limbs and fold second half
    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, code.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 2, ntt_forward_bindings_2k_[0].get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_fold_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    
    ntt_forward_kernel(pass, ntt_forward_bindings_k_, code, padding_size());

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);

    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}


void webgpu_context::ntt_forward_k(webgpu_binding bind)
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

void webgpu_context::ntt_forward_2k(webgpu_binding bind)
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

void webgpu_context::ntt_forward_n(webgpu_binding bind)
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
                                        std::vector<webgpu_binding>& config,
                                        webgpu_binding bind,
                                        size_t N)
{
    const uint32_t log2N = static_cast<uint32_t>(std::log2(N));
    assert(log2N >= ntt_shared_iterations);

    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_forward_);
    for (uint32_t iter = log2N; iter > ntt_shared_iterations; iter--) {
        wgpuComputePassEncoderSetBindGroup(pass, 2, config[iter].get(), 0, nullptr);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }

    const uint32_t num_shared_workgroups = N / ntt_shared_size;
    if (num_shared_workgroups <= max_workgroups) {
        wgpuComputePassEncoderSetBindGroup(pass, 2, config[0].get(), 0, nullptr);
        wgpuComputePassEncoderSetPipeline(pass, ntt_forward_shared_);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_shared_workgroups, 1, 1);
    }
    else {
        wgpuComputePassEncoderSetPipeline(pass, ntt_forward_);
        for (uint32_t iter = ntt_shared_iterations; iter >= 1; iter--) {
            wgpuComputePassEncoderSetBindGroup(pass, 2, config[iter].get(), 0, nullptr);
            wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
        }

        wgpuComputePassEncoderSetPipeline(pass, ntt_reduce_);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }

    /// DIF butterfly performs bit reversal at the end
    wgpuComputePassEncoderSetBindGroup(pass, 2, config[0].get(), 0, nullptr);

    wgpuComputePassEncoderSetPipeline(pass, ntt_bit_reverse_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
}

void webgpu_context::ntt_inverse_k(webgpu_binding bind)
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

void webgpu_context::ntt_inverse_2k(webgpu_binding bind)
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

void webgpu_context::ntt_inverse_n(webgpu_binding bind)
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
                                        std::vector<webgpu_binding>& config,
                                        webgpu_binding bind,
                                        size_t N)
{
    const uint32_t log2N = static_cast<uint32_t>(std::log2(N));
    assert(log2N >= ntt_shared_iterations);

    wgpuComputePassEncoderSetBindGroup(pass, 0, global_config_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(),      0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 2, config[0].get(), 0, nullptr);

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
            wgpuComputePassEncoderSetBindGroup(pass, 2, config[iter].get(), 0, nullptr);
            wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
        }
    }

    wgpuComputePassEncoderSetPipeline(pass, ntt_inverse_);
    for (uint32_t iter = ntt_shared_iterations + 1; iter <= log2N; iter++) {
        wgpuComputePassEncoderSetBindGroup(pass, 2, config[iter].get(), 0, nullptr);
        wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
    }
            
    wgpuComputePassEncoderSetPipeline(pass, ntt_adjust_inverse_);
    wgpuComputePassEncoderDispatchWorkgroups(pass, num_default_workgroups_, 1, 1);
}


void webgpu_context::ntt_init_layouts() {
    // @group(0) bindings (Global config)
    // ------------------------------------------------------------
    {
        WGPUBindGroupLayoutEntry global_config_bindings[1] = {
            {
                .binding = 0,
                .visibility = WGPUShaderStage_Compute,
                .buffer {
                    .type = WGPUBufferBindingType_Uniform,
                },
            },
        };

        WGPUBindGroupLayoutDescriptor global_config_desc {
            .label = WGPU_STRING("Bignum::global_config_layout"),
            .entryCount = 1,
            .entries = global_config_bindings,
        };

        global_config_layout_ = wgpuDeviceCreateBindGroupLayout(device_, &global_config_desc);
    }

    // @group(1) bindings (Storage)
    // ------------------------------------------------------------
    {
        WGPUBindGroupLayoutEntry ntt_bindings = {
            .binding = 0,
            .visibility = WGPUShaderStage_Compute,
            .buffer {
                .type = WGPUBufferBindingType_Storage,
            },
        };
        
        WGPUBindGroupLayoutDescriptor ntt_desc {
            .label = WGPU_STRING("Bignum::ntt_buffer"),
            .entryCount = 1,
            .entries = &ntt_bindings,
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

    // @group(2) bindings (NTT config)
    // ------------------------------------------------------------
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
}

void webgpu_context::ntt_init_pipelines() {
    WGPUBindGroupLayout ntt_binds[3] = {
        global_config_layout_,
        ntt_layout_,
        ntt_config_layout_,
    };

    WGPUBindGroupLayout eltwise2_binds[2] = {
        global_config_layout_,
        eltwise_layout2_,
    };

    WGPUBindGroupLayout eltwise3_binds[2] = {
        global_config_layout_,
        eltwise_layout3_,
    };
    
    WGPUPipelineLayoutDescriptor pipelineDesc {
        .bindGroupLayoutCount = 3,
        .bindGroupLayouts = ntt_binds,
    };

    WGPUPipelineLayout ntt_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 2;
    pipelineDesc.bindGroupLayouts     = eltwise2_binds;
    WGPUPipelineLayout eltwise2_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    pipelineDesc.bindGroupLayoutCount = 2;
    pipelineDesc.bindGroupLayouts     = eltwise3_binds;
    WGPUPipelineLayout eltwise3_pipeline_layout = wgpuDeviceCreatePipelineLayout(device_, &pipelineDesc);

    {
        WGPUComputePipelineDescriptor ntt_desc {
            .layout = ntt_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            },
        };

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_forward_radix2");
        ntt_forward_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_forward_radix2_shared");
        ntt_forward_shared_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_inverse_radix2");
        ntt_inverse_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_inverse_radix2_shared");
        ntt_inverse_shared_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_bit_reverse");
        ntt_bit_reverse_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_reduce4p");
        ntt_reduce_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_adjust_inverse_reduce");
        ntt_adjust_inverse_ = prepare_pipeline(device_, ntt_desc);

        ntt_desc.compute.entryPoint = WGPU_STRING("ntt_fold");
        ntt_fold_ = prepare_pipeline(device_, ntt_desc);
    }

    {
        WGPUComputePipelineDescriptor eltwise_desc {
            .layout = eltwise3_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            }
        };

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddMod");
        eltwise_addmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseSubMod");
        eltwise_submod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMultMod");
        eltwise_mulmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseDivMod");
        eltwise_divmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseFMAMod");
        eltwise_fma_ = prepare_pipeline(device_, eltwise_desc);

    }

    {
        WGPUComputePipelineDescriptor eltwise_desc {
            .layout = eltwise2_pipeline_layout,
            .compute {
                .module = ntt_shader_,
            }
        };

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseBitDecompose");
        eltwise_bit_decompose_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddAssignMod");
        eltwise_addassignmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseAddConstantMod");
        eltwise_addcmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseSubConstantMod");
        eltwise_subcmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseConstantSubMod");
        eltwise_csubmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMultConstantMod");
        eltwise_mulcmod_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseMontMultConstantMod");
        eltwise_montmul_ = prepare_pipeline(device_, eltwise_desc);

        eltwise_desc.compute.entryPoint = WGPU_STRING("EltwiseFMAConstantMod");
        eltwise_fmac_ = prepare_pipeline(device_, eltwise_desc);
    }

    wgpuPipelineLayoutRelease(ntt_pipeline_layout);
    wgpuPipelineLayoutRelease(eltwise2_pipeline_layout);
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
    global_config_     = make_uniform_buffer(sizeof(global_config_t<num_limbs>));
    size_t config_size = sizeof(ntt_config_t<num_limbs>);
    
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
        const size_t omega_bytes = ((1ull << i) / 2) * num_element_bytes;
        ntt_omegas_k_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_k_[i] = make_device_buffer(omega_bytes);
    }

    for (size_t i = 1; i <= ntt_iterations_2k_; i++) {
        // Size N FFT only needs N/2 omegas
        const size_t omega_bytes = ((1ull << i) / 2) * num_element_bytes;
        ntt_omegas_2k_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_2k_[i] = make_device_buffer(omega_bytes);
    }

    for (size_t i = 1; i <= ntt_iterations_n_; i++) {
        // Size N FFT only needs N/2 omegas
        const size_t omega_bytes = ((1ull << i) / 2) * num_element_bytes;
        ntt_omegas_n_[i]    = make_device_buffer(omega_bytes);
        ntt_omegasinv_n_[i] = make_device_buffer(omega_bytes);
    }

    // NB: Since position 0 is never used, we fill shared omegas for all iterations in it
    const size_t shared_omegas_bytes = num_element_bytes *
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

    mpz_class double_p = p * 2;
    mpz_class mpz_J;
    mpz_class beta = mpz_class(1) << num_element_bits;
    mpz_invert(mpz_J.get_mpz_t(), p.get_mpz_t(), beta.get_mpz_t());

    global_config_t<num_limbs> config{
        .p              = p,
        .double_p       = double_p,
        .J              = mpz_J,
        .barrett_factor = barrett_factor,
    };

    write_buffer(global_config_, &config, 1);

    // ------------------------------------------------------------
    {
        WGPUBindGroupEntry global_config_entries = {
            .binding = 0,
            .buffer  = global_config_.get(),
            .offset  = global_config_.offset(),
            .size    = sizeof(global_config_t<num_limbs>)
        };

        WGPUBindGroupDescriptor config_desc {
            .layout = global_config_layout_,
            .entryCount = 1,
            .entries = &global_config_entries,
        };

        global_config_binding_  = wgpuDeviceCreateBindGroup(device_, &config_desc);
    }


    ntt_forward_bindings_k_.resize(ntt_iterations_k_ + 1, nullptr);
    ntt_inverse_bindings_k_.resize(ntt_iterations_k_ + 1, nullptr);
    for (size_t i = 0; i <= ntt_iterations_k_; i++) {
        WGPUBindGroupEntry config_entries[] = {
            {
                .binding = 0,
                .buffer  = ntt_config_k_.get(),
                .offset  = i * sizeof(ntt_config_t<num_limbs>),
                .size    = sizeof(ntt_config_t<num_limbs>)
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
                .offset  = i * sizeof(ntt_config_t<num_limbs>),
                .size    = sizeof(ntt_config_t<num_limbs>)
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
                .offset  = i * sizeof(ntt_config_t<num_limbs>),
                .size    = sizeof(ntt_config_t<num_limbs>)
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
            omega <<= num_element_bits;
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
            omega_inv <<= num_element_bits;
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
    
    N_inv = (N_inv << num_element_bits) % p;

    ntt_config_t<num_limbs> config {
        .N_inv    = N_inv,
        .N        = N,
        .log2N    = static_cast<uint32_t>(std::log2(N)),
        .M        = 1,
    };

    // We actually need iterations [1, log2(N)], add 0 to save index calculation
    std::vector<ntt_config_t<num_limbs>> configs;
    for (size_t i = 0; i <= log2N; i++) {
        config.M    = 1u << i;
        config.iter = i;
        configs.push_back(config);
    }

    // Write to device buffer
    write_buffer(config_buf, configs.data(), configs.size());
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


void webgpu_context::sha256_digest_init(webgpu_binding ctx) {
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


void webgpu_context::sha256_digest_update(webgpu_binding ctx, webgpu_binding buf) {
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


void webgpu_context::sha256_digest_final(webgpu_binding ctx) {
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
            .binding = 1,
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
            index_layout,
            sampling_layout_,
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
        sampling_gather_ = prepare_pipeline(device_, desc);

        wgpuPipelineLayoutRelease(layout);
    }

    // --------------------------------------------------
    num_samplings_           = index.size();
    num_sampling_workgroups_ = calc_blocks(index.size(), workgroup_size);

    // Pad the index to satisfy uniform 16 byte alignment requirement
    std::vector<webgpu_vec4u_t> padded_index(index.size());
    for (size_t i = 0; i < index.size(); i++) {
        padded_index[i].limbs[0] = index[i];
    }
    
    sampling_index_buf_ = make_uniform_buffer(padded_index.size() * sizeof(webgpu_vec4u_t));
    write_buffer(sampling_index_buf_, padded_index.data(), padded_index.size());

    // --------------------------------------------------

    WGPUBindGroupEntry entries[] = {
        {
            .binding = 1,
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


void webgpu_context::sample_gather(webgpu_binding bind, size_t sampling_offset) {
    WGPUCommandEncoderDescriptor cmd { .label = WGPU_STRING("sample_gather") };
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, &cmd);
    WGPUComputePassEncoder pass = wgpuCommandEncoderBeginComputePass(encoder, nullptr);

    uint32_t offset_bytes = sampling_offset * num_samplings_ * num_element_bytes;
    wgpuComputePassEncoderSetPipeline(pass, sampling_gather_);
    wgpuComputePassEncoderSetBindGroup(pass, 0, sampling_index_binding_.get(), 0, nullptr);
    wgpuComputePassEncoderSetBindGroup(pass, 1, bind.get(), 1, &offset_bytes);

    wgpuComputePassEncoderDispatchWorkgroups(pass, num_sampling_workgroups_, 1, 1);

    wgpuComputePassEncoderEnd(pass);
    wgpuComputePassEncoderRelease(pass);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

}  // ligero
