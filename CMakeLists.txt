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


if (NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  find_package(ZLIB    REQUIRED)
  find_package(GMP     REQUIRED)
  find_package(OpenSSL REQUIRED)
  find_package(Boost
    COMPONENTS random log exception serialization program_options iostreams
    REQUIRED)
  find_package(Dawn REQUIRED)
  find_package(wabt REQUIRED)

  # Note: Dawn_INCLUDE_DIRS is not set by modern Dawn CMake config
  # Include directories are automatically provided via the dawn::webgpu_dawn imported target
  include_directories(${Boost_INCLUDE_DIRS})
endif()

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
  file(COPY "${CMAKE_SOURCE_DIR}/shader" DESTINATION "${CMAKE_BINARY_DIR}/pack")

  add_compile_definitions(NDEBUG)
  add_compile_options(-O3 -Wno-narrowing -mbulk-memory -sUSE_ZLIB=1)
  add_link_options(
    -sUSE_WEBGPU=1
    -sUSE_ZLIB=1
    -sERROR_ON_UNDEFINED_SYMBOLS=0
    -sTOTAL_STACK=2MB
    -sINITIAL_MEMORY=256MB)
  add_link_options(-sINVOKE_RUN=0 -sEXPORTED_RUNTIME_METHODS=['FS','callMain'])
  add_link_options(--preload-file "${CMAKE_BINARY_DIR}/pack@/")

  if (ZKPLATFORM)
    add_link_options(-sENVIRONMENT=worker -sALLOW_MEMORY_GROWTH)
  else()
    set(CMAKE_EXECUTABLE_SUFFIX ".html")
    add_link_options(--emrun)
    add_link_options(--shell-file ${PROJECT_SOURCE_DIR}/emscripten_templates/edit_distance.html)
  endif()

  add_link_options(
    -sASYNCIFY=1
    -sASYNCIFY_IMPORTS=emscripten_sleep
    -sASYNCIFY_ONLY=[]
    -sASYNCIFY_STACK_SIZE=4194304
    -sASYNCIFY_ADD=['wgpuRequestAdapterSync','wgpuRequestDeviceSync','wgpuBufferMapSync','wgpuDeviceSynchronize']
  )

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
include_directories(${CMAKE_PREFIX_PATH}/include)
link_directories(${CMAKE_PREFIX_PATH}/lib)

add_library(logging      include/util/log.cpp)
add_library(bn254        src/bn254.cpp)
add_library(portable_archive
  include/util/boost/portable_binary_iarchive.cpp
  include/util/boost/portable_binary_oarchive.cpp)


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
      webgpu_engine logging bn254 portable_archive)

    if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
      target_link_libraries(${BINARY}
        gmp gmpxx ssl crypto wabt boost_serialization boost_iostreams)
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

enable_testing()
add_subdirectory(tests)
