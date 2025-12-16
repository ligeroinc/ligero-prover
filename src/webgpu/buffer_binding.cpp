#include <ligetron/webgpu/buffer_binding.hpp>

// Use unnamed namespace for internal linkage
namespace {
std::shared_ptr<WGPUBindGroup> make_binding(WGPUBindGroup bg) {
    return std::shared_ptr<WGPUBindGroup>(new WGPUBindGroup(bg), [](WGPUBindGroup *bg) {
        if (bg) {
            if (*bg)
                wgpuBindGroupRelease(*bg);
            delete bg;            
        }
    });
}
}

namespace ligero::webgpu {

buffer_binding::buffer_binding() { }

buffer_binding::buffer_binding(buffer_binding::bindgroup_type bg)
    : buffer_binding(bg, {}) { }

buffer_binding::buffer_binding(buffer_binding::bindgroup_type bg,
                               std::vector<buffer_binding::buffer_type> bufs)
    : bind_(make_binding(bg)), bufs_(std::move(bufs)) { }

buffer_binding::bindgroup_type
buffer_binding::get() const noexcept {
    return *bind_;
}

std::vector<buffer_binding::buffer_type>&
buffer_binding::buffers() noexcept {
    return bufs_;
}

const std::vector<buffer_binding::buffer_type>&
buffer_binding::buffers() const noexcept {
    return bufs_;
}

}  // namespace ligero::webgpu

