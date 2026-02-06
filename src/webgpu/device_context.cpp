#include <iostream>

#include <util/log.hpp>
#include <ligetron/webgpu/common.hpp>
#include <ligetron/webgpu/device_context.hpp>

namespace ligero {
namespace webgpu {

// Internal linkage helpers
namespace {

// Helper to wait for a WebGPU future to complete
// Uses blocking wait - emdawnwebgpu handles asyncify internally for web builds
void waitForFuture(WGPUInstance instance, WGPUFuture future) {
    WGPUFutureWaitInfo wait { .future = future };
    WGPUWaitStatus status = wgpuInstanceWaitAny(instance, 1, &wait, UINT64_MAX);
    if (status != WGPUWaitStatus_Success) {
        LIGERO_LOG_ERROR << "wgpuInstanceWaitAny failed with status: " << static_cast<int>(status);
    }
}

WGPUAdapter wgpuRequestAdapterSync(WGPUInstance instance) {
    WGPUAdapter adapter = nullptr;

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
    waitForFuture(instance, f);
    return adapter;
}

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
#if !defined(__EMSCRIPTEN__)
            case WGPUDeviceLostReason_CallbackCancelled:
                reason_str = "DeviceLostReason::CallbackCancelled";
                break;
            case WGPUDeviceLostReason_FailedCreation:
                reason_str = "DeviceLostReason::FailedCreation"; break;
#endif
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
#if !defined(__EMSCRIPTEN__)
            std::abort();
#endif
        }
    };

#if !defined(__EMSCRIPTEN__)
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
        .label                        = {"LigetronWebGPU", WGPU_STRLEN},
        .requiredFeatureCount         = 0,
        .requiredFeatures             = nullptr,
        .requiredLimits               = &limits,
        .deviceLostCallbackInfo       = lost,
        .uncapturedErrorCallbackInfo  = err
    };
#else
    WGPUDeviceDescriptor desc {
        .label                        = {"LigetronWebGPU", WGPU_STRLEN},
        .requiredFeatureCount         = 0,
        .requiredLimits               = nullptr,
        .deviceLostCallbackInfo       = lost,
        .uncapturedErrorCallbackInfo  = err
    };
#endif

    WGPUDevice device = nullptr;
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
    waitForFuture(instance, f);
    return device;
}

void wgpuBufferMapSync(WGPUInstance instance, WGPUBuffer map_buf, size_t offset, size_t size) {
    WGPUBufferMapCallbackInfo info {
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPUMapAsyncStatus status, WGPUStringView msg, void *ud1, void *ud2) {
            if (status != WGPUMapAsyncStatus_Success) {
                std::string status_str;
                switch(status) {
                case WGPUMapAsyncStatus_Success:
                    status_str = "[MapAsync::Success]: "; break;
#if !defined(__EMSCRIPTEN__)
                case WGPUMapAsyncStatus_CallbackCancelled:
                    status_str = "[MapAsync::CallbackCancelled]: "; break;
                case WGPUMapAsyncStatus_Aborted:
                    status_str = "[MapAsync::Aborted]: "; break;
#endif
                case WGPUMapAsyncStatus_Error:
                    status_str = "[MapAsync::Error]: "; break;
                default:
                    status_str = "[MapAsync::UncapturedError]: ";
                }
                LIGERO_LOG_ERROR << status_str << std::string_view(msg.data, msg.length);
            }
        }
    };

    auto f = wgpuBufferMapAsync(map_buf, WGPUMapMode_Read, offset, size, info);
    waitForFuture(instance, f);
}

void wgpuDeviceSynchronize(WGPUInstance instance, WGPUQueue queue) {
    WGPUQueueWorkDoneCallbackInfo info {
        .mode = WGPUCallbackMode_AllowProcessEvents,
        .callback = [](WGPUQueueWorkDoneStatus status, WGPUStringView message, void *ud1, void *ud2) {
            if (status != WGPUQueueWorkDoneStatus_Success) {
                std::string status_str;
                switch(status) {
                case WGPUQueueWorkDoneStatus_Success:
                    status_str = "Completed"; break;
#if !defined(__EMSCRIPTEN__)
                case WGPUQueueWorkDoneStatus_CallbackCancelled:
                    status_str = "Callback cancelled"; break;
#endif
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
    waitForFuture(instance, f);
}

}  // namespace

// --------------------------------------------------

device_context::~device_context() {
    device_shutdown();
}

void device_context::device_init() {
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
