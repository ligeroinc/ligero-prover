cmake_minimum_required(VERSION 3.24)

# Use NEW behavior for CMP0144 (CMake ≥3.27) so find_package() honors UPPERCASE *_ROOT env vars.
if(POLICY CMP0144)
  cmake_policy(SET CMP0144 NEW)
endif()

# Use NEW behavior for CMP0167 (CMake ≥3.29): FindBoost module is removed in favor of BoostConfig.cmake.
# We still use FindBoost for WASM builds, so suppress the deprecation warning.
if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

# -----------------------------------------------------------------------------
# Test target
# -----------------------------------------------------------------------------
add_executable(test_mpz_get
  test_mpz_get.cpp
)

# When building with Emscripten, emit a .js launcher so Node can run it.
if(EMSCRIPTEN)
  set_target_properties(test_mpz_get PROPERTIES SUFFIX ".js")
endif()

# -----------------------------------------------------------------------------
# Dependencies: Boost.Test (native + wasm) and GMP (native via pkg-config; wasm by name)
# -----------------------------------------------------------------------------

# --- Boost.Test ---
if(EMSCRIPTEN)
  # ---------------------------------------------------------------------------
  # Resolve WASM_LIBS_PREFIX from CMAKE_PREFIX_PATH
  # Search for known marker files to identify the correct prefix
  # ---------------------------------------------------------------------------
  set(WASM_LIBS_PREFIX "")
  if(DEFINED CMAKE_PREFIX_PATH)
    foreach(_prefix IN LISTS CMAKE_PREFIX_PATH)
      if(EXISTS "${_prefix}/include/boost/version.hpp" AND
         EXISTS "${_prefix}/lib/libboost_unit_test_framework.a")
        set(WASM_LIBS_PREFIX "${_prefix}")
        message(STATUS "Found WASM libs prefix via CMAKE_PREFIX_PATH: ${WASM_LIBS_PREFIX}")
        break()
      endif()
    endforeach()
  endif()

  if(NOT WASM_LIBS_PREFIX)
    message(FATAL_ERROR
      "Could not locate WASM libraries prefix. "
      "Ensure CMAKE_PREFIX_PATH contains a path with both "
      "include/boost/version.hpp and lib/libboost_unit_test_framework.a "
      "(e.g., -DCMAKE_PREFIX_PATH=/opt/wasm-libs)")
  endif()

  # Strong hints for FindBoost to look in the resolved prefix
  set(Boost_NO_BOOST_CMAKE ON)                  # force FindBoost.cmake (no BoostConfig.cmake)
  set(Boost_USE_STATIC_LIBS ON)                 # Emscripten uses static libs
  set(BOOST_ROOT "${WASM_LIBS_PREFIX}")
  set(BOOST_INCLUDEDIR "${WASM_LIBS_PREFIX}/include")
  set(BOOST_LIBRARYDIR "${WASM_LIBS_PREFIX}/lib")

  # First try the normal FindBoost path
  find_package(Boost QUIET COMPONENTS unit_test_framework)

  if(NOT Boost_FOUND)
    message(WARNING "FindBoost couldn't locate Boost.Test for WASM; "
                    "falling back to manual import from ${WASM_LIBS_PREFIX}")

    # Sanity-check expected artifacts
    set(_BOOST_HDR "${WASM_LIBS_PREFIX}/include/boost/version.hpp")
    set(_BOOST_UTF_LIB "${WASM_LIBS_PREFIX}/lib/libboost_unit_test_framework.a")

    # Create an imported target to mimic Boost::unit_test_framework
    add_library(Boost::unit_test_framework STATIC IMPORTED GLOBAL)
    set_target_properties(Boost::unit_test_framework PROPERTIES
      IMPORTED_LOCATION "${_BOOST_UTF_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "${WASM_LIBS_PREFIX}/include"
    )

    # Provide variables some tooling may expect
    set(Boost_INCLUDE_DIRS "${WASM_LIBS_PREFIX}/include")
    set(Boost_UNIT_TEST_FRAMEWORK_LIBRARY "${_BOOST_UTF_LIB}")
    set(Boost_FOUND TRUE)
  else()
    message(STATUS "Found Boost for WASM")
    message(STATUS "  Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
    message(STATUS "  Boost_LIBRARIES:    ${Boost_LIBRARIES}")
  endif()
else()
  # Native discovery
  find_package(Boost REQUIRED COMPONENTS unit_test_framework)
endif()

# --- GMP ---
if(NOT EMSCRIPTEN)
  # Native: use pkg-config imported targets
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
target_include_directories(test_mpz_get SYSTEM PRIVATE ${Boost_INCLUDE_DIRS})

if(EMSCRIPTEN)
  # Emscripten: ensure third-party headers (e.g., gmpxx.h) are reachable
  target_include_directories(test_mpz_get SYSTEM PRIVATE "${WASM_LIBS_PREFIX}/include")
endif()

# -----------------------------------------------------------------------------
# Linking
# -----------------------------------------------------------------------------
if(EMSCRIPTEN)
  # Ensure linker can resolve libs in the WASM prefix
  target_link_directories(test_mpz_get PRIVATE "${WASM_LIBS_PREFIX}/lib")

  target_link_libraries(test_mpz_get PRIVATE
    Boost::unit_test_framework
    gmp
    gmpxx
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
message(STATUS "  Boost include:   ${Boost_INCLUDE_DIRS}")
if(EMSCRIPTEN)
  message(STATUS "  (WASM) using ${WASM_LIBS_PREFIX} for headers/libs")
else()
  message(STATUS "  (Native) GMP via pkg-config")
endif()
message(STATUS "")
