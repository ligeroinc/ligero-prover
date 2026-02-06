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

    WGPUShaderSourceWGSL wgslDesc {
        .chain = WGPUChainedStruct {
            .next = nullptr,
            .sType = WGPUSType_ShaderSourceWGSL,
        },
        .code = {source.c_str(), source.length()}
    };

    WGPUShaderModuleDescriptor desc {
        .nextInChain = (WGPUChainedStruct*)&wgslDesc,
        .label = {path.c_str(), strlen(path.c_str())},
    };

    return wgpuDeviceCreateShaderModule(device, &desc);
}


}  // namespace webgpu
}  // namespace ligero


