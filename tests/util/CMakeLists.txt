cmake_minimum_required(VERSION 3.24)

# Use NEW behavior for CMP0144 (CMake ≥3.27) so find_package() honors UPPERCASE *_ROOT env vars.
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

# -----------------------------------------------------------------------------
# Test target
# -----------------------------------------------------------------------------
add_executable(test_mpz_get
  test_mpz_get.cpp
)
add_executable(test_bulk_bytes test_bulk_bytes.cpp)
target_link_libraries(test_bulk_bytes PRIVATE ecdsa_r1cs_dependencies)
target_include_directories(test_bulk_bytes PRIVATE ${PROJECT_SOURCE_DIR}/include)
add_executable(test_bn254_mul test_bn254_mul.cpp ${PROJECT_SOURCE_DIR}/src/bn254.cpp)
target_link_libraries(test_bn254_mul PRIVATE ecdsa_r1cs_dependencies)
target_include_directories(test_bn254_mul PRIVATE ${PROJECT_SOURCE_DIR}/include)

# When building with Emscripten, emit a .js launcher so Node can run it.
if(EMSCRIPTEN)
  set_target_properties(test_mpz_get PROPERTIES SUFFIX ".js")
  set_target_properties(test_bulk_bytes PROPERTIES SUFFIX ".js")
  set_target_properties(test_bn254_mul PROPERTIES SUFFIX ".js")
  target_link_options(test_bulk_bytes PRIVATE -sINVOKE_RUN=1 -sENVIRONMENT=node
    -sEXIT_RUNTIME=1 -sSTACK_SIZE=1048576 -sALLOW_MEMORY_GROWTH=1)
  add_test(NAME util.test_bulk_bytes COMMAND node $<TARGET_FILE:test_bulk_bytes>)
  target_link_options(test_bn254_mul PRIVATE -sINVOKE_RUN=1 -sENVIRONMENT=node
    -sEXIT_RUNTIME=1 -sSTACK_SIZE=1048576 -sALLOW_MEMORY_GROWTH=1)
  add_test(NAME util.test_bn254_mul COMMAND node $<TARGET_FILE:test_bn254_mul>)
else()
  add_test(NAME util.test_bulk_bytes COMMAND test_bulk_bytes)
  add_test(NAME util.test_bn254_mul COMMAND test_bn254_mul)
endif()

# -----------------------------------------------------------------------------
# Dependencies: Boost.Test (native + wasm) and GMP (native via pkg-config; wasm by name)
# -----------------------------------------------------------------------------

# --- Dependencies ---
if(NOT EMSCRIPTEN)
  find_package(Boost REQUIRED COMPONENTS unit_test_framework)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GMP   REQUIRED IMPORTED_TARGET gmp)
  pkg_check_modules(GMPXX REQUIRED IMPORTED_TARGET gmpxx)
endif()

# -----------------------------------------------------------------------------
# Includes
# -----------------------------------------------------------------------------
target_include_directories(test_mpz_get PRIVATE
  ${PROJECT_SOURCE_DIR}/include           # util/mpz_get.hpp lives here
)

# External library headers as SYSTEM to suppress warnings from them
if(NOT EMSCRIPTEN)
  target_include_directories(test_mpz_get SYSTEM PRIVATE ${Boost_INCLUDE_DIRS})
endif()
# WASM headers are already reachable via the parent's
# include_directories(SYSTEM ${CMAKE_PREFIX_PATH}/include)

# -----------------------------------------------------------------------------
# Linking
# -----------------------------------------------------------------------------
if(EMSCRIPTEN)
  target_link_libraries(test_mpz_get PRIVATE
    wasm::boost_unit_test_framework
    wasm::gmp
    wasm::gmpxx
  )
else()
  target_link_libraries(test_mpz_get PRIVATE
    Boost::unit_test_framework
    PkgConfig::GMP
    PkgConfig::GMPXX
  )
endif()

# -----------------------------------------------------------------------------
# Compile / Link options
# -----------------------------------------------------------------------------
# Skip -Wpedantic: Boost.Test macros use __COUNTER__ which is a C2y extension
target_compile_options(test_mpz_get PRIVATE -Wall -Wextra)

if(EMSCRIPTEN)
  # Reasonable defaults for Node-based unit tests
  target_link_options(test_mpz_get PRIVATE
    "SHELL:-s ALLOW_MEMORY_GROWTH=1"
    "SHELL:-s EXIT_RUNTIME=1"
    "SHELL:-s ERROR_ON_UNDEFINED_SYMBOLS=0"
    "SHELL:-s ENVIRONMENT=node"
  )
  message(STATUS "Configuring test_mpz_get for WASM/Emscripten (Node.js runner)")
endif()

# -----------------------------------------------------------------------------
# CTest registration
# -----------------------------------------------------------------------------
enable_testing()

if(EMSCRIPTEN)
  # The produced artifact is a JS launcher; run with Node
  add_test(NAME util.test_mpz_get
           COMMAND node $<TARGET_FILE:test_mpz_get>)
else()
  add_test(NAME util.test_mpz_get
           COMMAND test_mpz_get)
endif()

set_tests_properties(util.test_mpz_get PROPERTIES
  TIMEOUT 60
  LABELS "unit;util;mpz"
  ENVIRONMENT "BOOST_TEST_LOG_LEVEL=test_suite"
)

# Convenience target
add_custom_target(run_mpz_util_tests
  COMMAND ${CMAKE_CTEST_COMMAND} -R util.test_mpz_get --output-on-failure
  DEPENDS test_mpz_get
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "Running MPZ utility tests..."
)

# -----------------------------------------------------------------------------
# Nice diagnostics
# -----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "MPZ Util Tests Configuration:")
message(STATUS "  Test executable: $<TARGET_FILE:test_mpz_get>")
if(EMSCRIPTEN)
  message(STATUS "  (WASM) using wasm:: imported targets from ${CMAKE_PREFIX_PATH}")
else()
  message(STATUS "  Boost include:   ${Boost_INCLUDE_DIRS}")
  message(STATUS "  (Native) GMP via pkg-config")
endif()
message(STATUS "")
