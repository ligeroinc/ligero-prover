# Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
cmake_minimum_required(VERSION 3.20)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(ecdsa_r1cs LANGUAGES CXX)
  set(ECDSA_R1CS_STANDALONE TRUE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GMPXX REQUIRED IMPORTED_TARGET gmpxx)
  find_package(OpenSSL REQUIRED)
  add_library(ecdsa_r1cs_dependencies INTERFACE)
  target_link_libraries(ecdsa_r1cs_dependencies INTERFACE PkgConfig::GMPXX OpenSSL::Crypto)
else()
  set(ECDSA_R1CS_STANDALONE FALSE)
  if(NOT TARGET ecdsa_r1cs_dependencies)
    message(FATAL_ERROR "Define ecdsa_r1cs_dependencies with GMPXX/GMP/Crypto before adding this directory")
  endif()
endif()

add_library(ecdsa_r1cs_core STATIC r1cs.cpp native.cpp circuit.cpp)
target_compile_features(ecdsa_r1cs_core PUBLIC cxx_std_20)
target_link_libraries(ecdsa_r1cs_core PUBLIC ecdsa_r1cs_dependencies)
target_include_directories(ecdsa_r1cs_core PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
  target_compile_options(ecdsa_r1cs_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

# The integrated prover owns its executable and test graph. Native standalone
# builds need neither the GPU backend nor a sibling checkout to check this core.
if(NOT ECDSA_R1CS_STANDALONE)
  return()
endif()

add_executable(ecdsa_r1cs main.cpp)
target_link_libraries(ecdsa_r1cs PRIVATE ecdsa_r1cs_core)
add_executable(ecdsa_r1cs_template generate_template.cpp)
target_link_libraries(ecdsa_r1cs_template PRIVATE ecdsa_r1cs_core)

include(CTest)
if(BUILD_TESTING)
  find_package(Threads REQUIRED)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_executable(ecdsa_r1cs_arithmetic_test arithmetic_test.cpp)
  target_link_libraries(ecdsa_r1cs_arithmetic_test PRIVATE ecdsa_r1cs_core)
  add_executable(ecdsa_r1cs_lc_test lc_test.cpp)
  target_link_libraries(ecdsa_r1cs_lc_test PRIVATE ecdsa_r1cs_core)
  add_executable(ecdsa_r1cs_test test.cpp)
  target_link_libraries(ecdsa_r1cs_test PRIVATE ecdsa_r1cs_core)
  add_executable(ecdsa_r1cs_witness_only_test witness_only_test.cpp)
  target_link_libraries(ecdsa_r1cs_witness_only_test PRIVATE ecdsa_r1cs_core)
  add_executable(ecdsa_r1cs_witness_parts_test test_witness_parts.cpp)
  target_link_libraries(ecdsa_r1cs_witness_parts_test PRIVATE ecdsa_r1cs_core Threads::Threads)
  add_executable(ecdsa_r1cs_template_layout_test template_layout_test.cpp)
  target_link_libraries(ecdsa_r1cs_template_layout_test PRIVATE ecdsa_r1cs_core)

  add_test(NAME native_ec COMMAND ecdsa_r1cs_test --native-only)
  add_test(NAME foreign_arithmetic COMMAND ecdsa_r1cs_arithmetic_test)
  add_test(NAME linear_combinations COMMAND ecdsa_r1cs_lc_test)
  add_test(NAME secp256k1_r1cs COMMAND ecdsa_r1cs_test --curve secp256k1 --extended)
  add_test(NAME p256_r1cs COMMAND ecdsa_r1cs_test --curve p256 --extended)
  add_test(NAME witness_only_equivalence COMMAND ecdsa_r1cs_witness_only_test)
  add_test(NAME parallel_witness_equivalence COMMAND ecdsa_r1cs_witness_parts_test
           ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts/witness-parts)
  add_test(NAME exported_witness_mutations
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_exports.py
            $<TARGET_FILE:ecdsa_r1cs_arithmetic_test>
            ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts/arithmetic)
  add_test(NAME template_generation COMMAND ecdsa_r1cs_template
           ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts/ecdsa_secp256k1_v1)
  set_tests_properties(template_generation PROPERTIES FIXTURES_SETUP ecdsa_public_template)
  add_test(NAME template_layout
    COMMAND ecdsa_r1cs_template_layout_test
            ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts/ecdsa_secp256k1_v1.r1cs)
  set_tests_properties(template_layout PROPERTIES FIXTURES_REQUIRED ecdsa_public_template)
  add_test(NAME template_corruption
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/test_template.py
            $<TARGET_FILE:ecdsa_r1cs_template>
            ${CMAKE_CURRENT_BINARY_DIR}/test-artifacts/ecdsa_secp256k1_v1.r1cs)
  set_tests_properties(template_corruption PROPERTIES FIXTURES_REQUIRED ecdsa_public_template)

  # The full repository also exercises the prover's CPU arithmetic/byte helpers
  # in this portable GCC/Clang test build, without requiring the GPU runtime.
  # A standalone distribution containing only this library still builds as-is.
  get_filename_component(LIGERO_REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
  if(EXISTS "${LIGERO_REPO_ROOT}/tests/util/test_bulk_bytes.cpp" AND
     EXISTS "${LIGERO_REPO_ROOT}/tests/util/test_bn254_mul.cpp" AND
     EXISTS "${LIGERO_REPO_ROOT}/src/bn254.cpp")
    add_executable(test_bulk_bytes "${LIGERO_REPO_ROOT}/tests/util/test_bulk_bytes.cpp")
    add_executable(test_bn254_mul "${LIGERO_REPO_ROOT}/tests/util/test_bn254_mul.cpp"
                                 "${LIGERO_REPO_ROOT}/src/bn254.cpp")
    foreach(target IN ITEMS test_bulk_bytes test_bn254_mul)
      target_compile_features(${target} PRIVATE cxx_std_20)
      target_include_directories(${target} PRIVATE "${LIGERO_REPO_ROOT}/include")
      target_link_libraries(${target} PRIVATE ecdsa_r1cs_dependencies)
    endforeach()
    add_test(NAME util.test_bulk_bytes COMMAND test_bulk_bytes)
    add_test(NAME util.test_bn254_mul COMMAND test_bn254_mul)
  endif()
endif()
