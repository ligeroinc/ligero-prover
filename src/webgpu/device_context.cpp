#include <iostream>

#include <util/log.hpp>
#include <ligetron/webgpu/common.hpp>
#include <ligetron/webgpu/device_context.hpp>

namespace ligero {
namespace webgpu {

// Internal linkage helpers
namespace {

#if defined(__EMSCRIPTEN__)
template <typename T>
struct async_waiter {
    T data;
    bool done = false;
};
#endif

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
                reason_str = "DeviceLostReason::Unknown";
                break;
            case WGPUDeviceLostReason_Destroyed:
                // Normally exit, don't print error
                return;
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
                reason_str = "DeviceLostReason::Unknown";
                break;
            case WGPUDeviceLostReason_Destroyed:
                // Normally exit, don't print error
                return;
            case WGPUDeviceLostReason_CallbackCancelled:
                reason_str = "DeviceLostReason::CallbackCancelled";
                break;
            case WGPUDeviceLostReason_FailedCreation:
                reason_str = "DeviceLostReason::FailedCreation"; break;
            default:
                reason_str = "DeviceLostReason::<Uncaptured>";
            }
            LIGERO_LOG_ERROR
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

}  // namespace

// --------------------------------------------------

device_context::~device_context() {
    device_shutdown();
}

void device_context::device_init() {
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

    adapter_ = wgpuRequestAdapterSync(instance_);
    device_  = wgpuRequestDeviceSync(instance_, adapter_);
    queue_   = wgpuDeviceGetQueue(device_);
}

void device_context::device_shutdown() {
    device_synchronize();

    if (queue_) {
        wgpuQueueRelease(queue_);
        queue_ = nullptr;
    }
    
    if (device_) {
        wgpuDeviceRelease(device_);
        device_ = nullptr;
    }
    
    if (adapter_) {
        wgpuAdapterRelease(adapter_);
        adapter_ = nullptr;
    }
    
    if (instance_) {
        // Make sure the instance is aware of the release
        wgpuInstanceProcessEvents(instance_);
        wgpuInstanceRelease(instance_);
        instance_ = nullptr;
    }
}

void device_context::device_synchronize() {
    if (instance_ && queue_)
        wgpuDeviceSynchronize(instance_, queue_);
}

WGPUInstance device_context::instance() const { return instance_; }
WGPUAdapter  device_context::adapter()  const { return adapter_;  }
WGPUDevice   device_context::device()   const { return device_;   }
WGPUQueue    device_context::queue()    const { return queue_;    }

void device_context::submit(WGPUCommandBuffer command) {
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

buffer_view device_context::make_uniform_buffer(size_t num_bytes) {
    WGPUBufferDescriptor uniform_desc {
        .usage = WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst,
        .size  = num_bytes,
    };
    return buffer_view(wgpuDeviceCreateBuffer(device_, &uniform_desc), 0, num_bytes);
}

buffer_view device_context::make_device_buffer(size_t num_bytes) {
    WGPUBufferDescriptor desc {
        .usage = WGPUBufferUsage_Storage
                 | WGPUBufferUsage_CopyDst | WGPUBufferUsage_CopySrc,
        .size = num_bytes,
    };
    return buffer_view(wgpuDeviceCreateBuffer(device_, &desc), 0, num_bytes);
}

buffer_view device_context::make_map_buffer(size_t num_bytes) {
    WGPUBufferDescriptor desc {
        .usage = WGPUBufferUsage_CopyDst | WGPUBufferUsage_MapRead,
        .size = num_bytes,
    };

    return buffer_view{ wgpuDeviceCreateBuffer(device_, &desc) };
}

void device_context::write_buffer_raw(buffer_view buf, const void *data, size_t num_bytes) {
    assert(buf.size() >= num_bytes);
    wgpuQueueWriteBuffer(queue_, buf.get(), buf.offset(), data, num_bytes);
}

void device_context::clear_buffer(buffer_view buf) {
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, nullptr);
    wgpuCommandEncoderClearBuffer(encoder, buf.get(), buf.offset(), buf.size());
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void device_context::copy_buffer_to_buffer(buffer_view from, buffer_view to) {
    assert(from.size() <= to.size());
    copy_buffer_to_buffer(from, to, from.size());
}

void device_context::copy_buffer_to_buffer(buffer_view from, buffer_view to, size_t bytes) {
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(device_, nullptr);
    wgpuCommandEncoderCopyBufferToBuffer(encoder,
                                         from.get(), from.offset(),
                                         to.get(), to.offset(),
                                         bytes);
    WGPUCommandBuffer command = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuCommandEncoderRelease(encoder);
    submit(command);
}

void device_context::copy_buffer_clear(buffer_view from, buffer_view to) {
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

std::span<const std::byte>
device_context::map_buffer_raw(buffer_view map_buf) {
    wgpuBufferMapSync(instance_, map_buf.get(), map_buf.offset(), map_buf.size());
    const void* ptr = wgpuBufferGetConstMappedRange(map_buf.get(),
                                                    map_buf.offset(),
                                                    map_buf.size());
    return std::span<const std::byte>{
        static_cast<const std::byte*>(ptr), map_buf.size() };
}

void device_context::unmap_buffer(buffer_view buf) {
    wgpuBufferUnmap(buf.get());
}

// Explicit template instantiations
// --------------------------------------------------
template std::vector<uint32_t>
device_context::copy_to_host(buffer_view buf);

template void
device_context::write_buffer(buffer_view buf, const uint32_t *data, size_t len);

template void
device_context::write_buffer_clear(buffer_view buf, const uint32_t *data, size_t len);

}  // namespace webgpu
}  // namespace ligero




