cmake_minimum_required(VERSION 3.24)

project(LigeroVM C CXX)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)

FetchContent_MakeAvailable(json)

# Use the NEW behavior for CMP0167 (CMake ≥3.29):
# ensures that try_compile() respects COMPILE_OPTIONS and LINK_OPTIONS.
# Guarded with if(POLICY) for compatibility with older CMake versions.
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

# Use NEW behavior for CMP0144 (CMake ≥3.27):
# allows find_package() to honor upper-case <PKG>_ROOT environment variables
# (e.g. BOOST_ROOT) in addition to the lowercase CMake variables.
# Guarded with if(POLICY) for compatibility with older CMake versions.
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()


if(EMSCRIPTEN)
  # Emscripten restricts find_package to the sysroot, so neither CONFIG
  # nor MODULE mode can locate protobuf in wasm-libs.  Create the targets
  # and variables that protobuf_generate() and linking need manually.
  include(FindProtobuf)          # load protobuf_generate() function only
  set(Protobuf_FOUND TRUE)
  set(Protobuf_INCLUDE_DIRS "${CMAKE_PREFIX_PATH}/include")
  if(NOT TARGET protobuf::libprotobuf)
    add_library(protobuf::libprotobuf STATIC IMPORTED)
  endif()
  set_target_properties(protobuf::libprotobuf PROPERTIES
    IMPORTED_LOCATION "${CMAKE_PREFIX_PATH}/lib/libprotobuf.a"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_PREFIX_PATH}/include")
else()
  # Native: try CONFIG first (developer-built protobuf), fall back to
  # CMake's FindProtobuf module (apt libprotobuf-dev).
  find_package(Protobuf CONFIG QUIET)
  if(NOT Protobuf_FOUND)
    find_package(Protobuf REQUIRED)
  endif()
endif()

# Cross-compiled protobuf (wasm-libs) omits protoc; create the imported
# target from the host executable so protobuf_generate() works.
if(NOT TARGET protobuf::protoc AND Protobuf_PROTOC_EXECUTABLE)
  add_executable(protobuf::protoc IMPORTED)
  set_target_properties(protobuf::protoc PROPERTIES
    IMPORTED_LOCATION "${Protobuf_PROTOC_EXECUTABLE}")
endif()

if (NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  find_package(ZLIB    REQUIRED)
  find_package(GMP     REQUIRED)
  find_package(OpenSSL REQUIRED)
  find_package(Boost
    COMPONENTS random log exception program_options iostreams
    REQUIRED)
  find_package(Dawn REQUIRED)
  find_package(wabt REQUIRED)

  # Note: Dawn_INCLUDE_DIRS is not set by modern Dawn CMake config
  # Include directories are automatically provided via the dawn::webgpu_dawn imported target
  include_directories(${Boost_INCLUDE_DIRS})
endif()

# ==============================================================================
# Configure WGSL Shaders
# ==============================================================================
set(LIGETRON_WGSL_BIGINT_HEADER     "${CMAKE_SOURCE_DIR}/shader/bigint.wgsl.in")
set(LIGETRON_WGSL_BN254FR_HEADER    "${CMAKE_SOURCE_DIR}/shader/bn254fr.wgsl.in")
set(LIGETRON_WGSL_KERNELS_TEMPLATE  "${CMAKE_SOURCE_DIR}/shader/kernels.wgsl.in")
set(LIGETRON_WGSL_SHA256_KERNEL     "${CMAKE_SOURCE_DIR}/shader/sha256.wgsl")

# Tell CMake to monitor shader changes at build-time
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS 
  "${LIGETRON_WGSL_BIGINT_HEADER}" 
  "${LIGETRON_WGSL_BN254FR_HEADER}"
  "${LIGETRON_WGSL_KERNELS_TEMPLATE}"
  "${LIGETRON_WGSL_SHA256_KERNEL}"
)

file(READ "${LIGETRON_WGSL_BIGINT_HEADER}"  LIGETRON_WGSL_BIGINT_CONTENT)
file(READ "${LIGETRON_WGSL_BN254FR_HEADER}" LIGETRON_WGSL_BN254FR_CONTENT)

configure_file(
  "${LIGETRON_WGSL_KERNELS_TEMPLATE}"
  "${CMAKE_CURRENT_BINARY_DIR}/shader/bignum.wgsl"
  @ONLY
)

configure_file(
  "${LIGETRON_WGSL_SHA256_KERNEL}"
  "${CMAKE_CURRENT_BINARY_DIR}/shader/sha256.wgsl"
  COPYONLY
)

# ==============================================================================
# Generate Version Tags
# ==============================================================================
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process(
  COMMAND git rev-parse HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE)

file(READ "${CMAKE_SOURCE_DIR}/VERSION" LIGETRON_VERSION)
string(STRIP "${LIGETRON_VERSION}" LIGETRON_VERSION)
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${LIGETRON_VERSION})
set(LIGETRON_VERSION_MAJOR ${CMAKE_MATCH_1})
set(LIGETRON_VERSION_MINOR ${CMAKE_MATCH_2})
set(LIGETRON_VERSION_PATCH ${CMAKE_MATCH_3})

add_compile_definitions(
  LIGETRON_VERSION_MAJOR=${LIGETRON_VERSION_MAJOR}
  LIGETRON_VERSION_MINOR=${LIGETRON_VERSION_MINOR}
  LIGETRON_VERSION_PATCH=${LIGETRON_VERSION_PATCH}
  LIGETRON_GIT_BRANCH="${GIT_BRANCH}"
  LIGETRON_GIT_COMMIT_HASH="${GIT_COMMIT_HASH}")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

  file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/pack")
  file(COPY "${CMAKE_BINARY_DIR}/shader" DESTINATION "${CMAKE_BINARY_DIR}/pack")

  add_compile_definitions(NDEBUG)
  add_compile_options(-O3 -mbulk-memory -sUSE_ZLIB=1 --use-port=emdawnwebgpu)
  add_link_options(
    --use-port=emdawnwebgpu
    -sUSE_ZLIB=1
    -sERROR_ON_UNDEFINED_SYMBOLS=0
    -sTOTAL_STACK=2MB
    -sINITIAL_MEMORY=256MB
    -sALLOW_MEMORY_GROWTH)
  add_link_options(-sINVOKE_RUN=0 -sEXPORTED_RUNTIME_METHODS=['FS','callMain'])
  add_link_options(--preload-file "${CMAKE_BINARY_DIR}/pack@/")

  if (ZKPLATFORM)
    add_link_options(-sENVIRONMENT=worker,node)
  else()
    set(CMAKE_EXECUTABLE_SUFFIX ".html")
    add_link_options(--emrun)
    # Per-target shell files are set below on webgpu_prover / webgpu_verifier
  endif()

  add_link_options(
    -sASYNCIFY=1
    -sASYNCIFY_STACK_SIZE=4194304
  )

  # Create validated imported targets for wasm-libs dependencies.
  # To add a new wasm dependency: add the .a to wasm-libs, add its name here.
  foreach(_lib gmp gmpxx ssl crypto wabt
               boost_iostreams boost_unit_test_framework)
    set(_lib_path "${CMAKE_PREFIX_PATH}/lib/lib${_lib}.a")
    if(NOT EXISTS "${_lib_path}")
      message(FATAL_ERROR "wasm-libs missing: lib${_lib}.a in ${CMAKE_PREFIX_PATH}/lib/")
    endif()
    add_library(wasm::${_lib} STATIC IMPORTED)
    set_target_properties(wasm::${_lib} PROPERTIES
      IMPORTED_LOCATION "${_lib_path}")
  endforeach()

else()
  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    add_compile_options(-O0 -g)
  else()
    add_compile_definitions(NDEBUG)
    add_compile_options(-O3)
    # add_compile_options(-fopenmp)
    # add_link_options(-fopenmp)
  endif()
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)
# External library headers as SYSTEM to suppress warnings from them
include_directories(SYSTEM ${CMAKE_PREFIX_PATH}/include)

add_library(logging      include/util/log.cpp)
add_library(bn254        src/bn254.cpp)
add_library(proof_proto OBJECT)
target_link_libraries(proof_proto PUBLIC protobuf::libprotobuf)
target_include_directories(proof_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate(
  APPEND_PATH
  TARGET proof_proto
  PROTOS
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/common.proto
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/ligero_proof.proto
  IMPORT_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/proto
    ${Protobuf_INCLUDE_DIRS}
  PROTOC_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB_RECURSE WEBGPU_SOURCES CONFIGURE_DEPENDS
    src/webgpu/*.cpp
)
add_library(webgpu_engine STATIC ${WEBGPU_SOURCES})
target_include_directories(webgpu_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/)

# Link to Dawn for native builds (provides include directories automatically via imported target)
# For web builds, link only Boost libraries
if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  target_link_libraries(webgpu_engine dawn::webgpu_dawn ${Boost_LIBRARIES})
else()
  target_link_libraries(webgpu_engine ${Boost_LIBRARIES})
endif()

macro (link_binaries)
  foreach(BINARY IN ITEMS ${ARGN})
    target_include_directories(${BINARY} PRIVATE ${json_SOURCE_DIR}/include)
    target_link_libraries(${BINARY}
      webgpu_engine logging bn254 proof_proto)

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
      target_link_libraries(${BINARY}
        wasm::gmp wasm::gmpxx wasm::ssl wasm::crypto
        wasm::wabt wasm::boost_iostreams)
    else()
      target_link_libraries(${BINARY}
        ${Boost_LIBRARIES}
        ZLIB::ZLIB
        GMP::gmp GMP::gmpxx
        OpenSSL::SSL OpenSSL::Crypto
        wabt::wabt
        dawn::webgpu_dawn)
    endif()
  endforeach()
endmacro()

add_executable(webgpu_prover src/webgpu_prover.cpp)
add_executable(webgpu_verifier src/webgpu_verifier.cpp)
link_binaries(webgpu_prover webgpu_verifier)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Web" AND NOT ZKPLATFORM)
  set(PROVER_SHELL_FILE "${PROJECT_SOURCE_DIR}/emscripten_templates/prover.html"
      CACHE FILEPATH "Emscripten HTML shell for webgpu_prover")
  set(VERIFIER_SHELL_FILE "${PROJECT_SOURCE_DIR}/emscripten_templates/verifier.html"
      CACHE FILEPATH "Emscripten HTML shell for webgpu_verifier")
  target_link_options(webgpu_prover PRIVATE
    --shell-file ${PROVER_SHELL_FILE})
  target_link_options(webgpu_verifier PRIVATE
    --shell-file ${VERIFIER_SHELL_FILE})
endif()

enable_testing()
add_subdirectory(tests)
