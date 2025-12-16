# unit tests should only run in native mode (not Web builds)
if("${CMAKE_BUILD_TYPE}" STREQUAL "Web")
    message(STATUS "Skipping webgpu tests for Web build")
    return()
endif()

# Use NEW behavior for CMP0144 (CMake ≥3.27):
# allows find_package() to honor upper-case <PKG>_ROOT environment variables
# (e.g. BOOST_ROOT) in addition to the lowercase CMake variables.
# Guarded with if(POLICY) for compatibility with older CMake versions.
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

find_package(Boost REQUIRED COMPONENTS unit_test_framework)

# Pick your standard; adjust as needed.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Collect test sources (one executable per file is nice for -R filtering)
file(GLOB WEBGPU_TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

if (WEBGPU_TEST_SOURCES STREQUAL "")
    message(STATUS "No webgpu tests found in ${CMAKE_CURRENT_SOURCE_DIR}")
endif()

foreach(TEST_SRC ${WEBGPU_TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SRC} NAME_WE)

    add_executable(webgpu_${TEST_NAME} ${TEST_SRC})
    target_link_libraries(webgpu_${TEST_NAME} Boost::unit_test_framework)
    target_compile_features(webgpu_${TEST_NAME} PRIVATE cxx_std_20)

    target_include_directories(webgpu_${TEST_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)

    target_compile_definitions(webgpu_${TEST_NAME}
      PRIVATE PROJECT_ROOT_DIR="${PROJECT_SOURCE_DIR}/")

    link_binaries(webgpu_${TEST_NAME})

    add_test(NAME webgpu.${TEST_NAME} COMMAND webgpu_${TEST_NAME})
endforeach()
