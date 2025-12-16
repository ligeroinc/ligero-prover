#include <fstream>
#include <sstream>

#include <util/log.hpp>
#include <ligetron/webgpu/common.hpp>

namespace ligero {
namespace webgpu {

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

WGPUShaderModule load_shader(WGPUDevice device, const fs::path& path) {
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


}  // namespace webgpu
}  // namespace ligero


