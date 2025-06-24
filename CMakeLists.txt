cmake_minimum_required(VERSION 3.24)

project(LigeroVM C CXX)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)

FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)

FetchContent_MakeAvailable(json)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()


if (NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  find_package(GMP     REQUIRED)
  find_package(OpenSSL REQUIRED)
  find_package(Boost
    COMPONENTS random log exception serialization program_options
    REQUIRED)
  find_package(Dawn REQUIRED)
  find_package(wabt REQUIRED)

  include_directories(${Dawn_INCLUDE_DIRS})
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

add_compile_definitions(
  LIGETRON_VERSION_MAJOR=0
  LIGETRON_VERSION_MINOR=9
  LIGETRON_VERSION_PATCH=9
  LIGETRON_GIT_BRANCH="${GIT_BRANCH}"
  LIGETRON_GIT_COMMIT_HASH="${GIT_COMMIT_HASH}")

if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(Boost_LIBRARIES boost_serialization)

  add_compile_definitions(NDEBUG)
  add_compile_options(-O3 -Wno-narrowing -mbulk-memory)
  add_link_options(-sUSE_WEBGPU=1 -sERROR_ON_UNDEFINED_SYMBOLS=0 -sTOTAL_STACK=2MB -sINITIAL_MEMORY=256MB)
  add_link_options(-sINVOKE_RUN=0 -sEXPORTED_RUNTIME_METHODS=['FS','callMain'])

  if (ZKPLATFORM)
    add_link_options(--preload-file "../shader@shader" -sALLOW_MEMORY_GROWTH)
    add_link_options(-sENVIRONMENT=worker)
  else()
    set(CMAKE_EXECUTABLE_SUFFIX ".html")

    add_link_options(--preload-file "pack@/" --emrun)
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

add_library(log          include/util/log.cpp)
add_library(bn254        src/bn254.cpp)

macro (link_binaries)
  foreach(BINARY IN ITEMS ${ARGN})
	target_include_directories(${BINARY} PRIVATE ${json_SOURCE_DIR}/include)
	target_link_libraries(${BINARY} log bn254)
	
	if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
      target_link_libraries(${BINARY} ${Boost_LIBRARIES} gmp gmpxx ssl crypto wabt)
	else()
	  if (ENABLE_CUDA)
		target_link_libraries(${BINARY} cuNTT cudart)
	  endif()

	  target_link_libraries(${BINARY} ${Boost_LIBRARIES} GMP::gmp GMP::gmpxx OpenSSL::SSL OpenSSL::Crypto wabt::wabt)
	  target_link_libraries(${BINARY} dawn::webgpu_dawn)
	endif()
  endforeach()
endmacro()

add_executable(webgpu_prover src/webgpu_prover.cpp)
add_executable(webgpu_verifier src/webgpu_verifier.cpp)
link_binaries(webgpu_prover webgpu_verifier)

enable_testing()
add_subdirectory(tests)

