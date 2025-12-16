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

# When building with Emscripten, emit a .js launcher so Node can run it.
if(EMSCRIPTEN)
  set_target_properties(test_mpz_get PROPERTIES SUFFIX ".js")
endif()

# -----------------------------------------------------------------------------
# Dependencies: Boost.Test (native + wasm) and GMP (native via pkg-config; wasm by name)
# -----------------------------------------------------------------------------

# --- Boost.Test ---
if(EMSCRIPTEN)
  # Strong hints for FindBoost to look in /opt/wasm-libs
  set(Boost_NO_BOOST_CMAKE ON)                  # force FindBoost.cmake (no BoostConfig.cmake)
  set(Boost_USE_STATIC_LIBS ON)                 # Emscripten uses static libs
  set(BOOST_ROOT "/opt/wasm-libs")
  set(BOOST_INCLUDEDIR "/opt/wasm-libs/include")
  set(BOOST_LIBRARYDIR "/opt/wasm-libs/lib")

  # Help CMake discovery for non-config packages
  if(DEFINED CMAKE_PREFIX_PATH)
    list(PREPEND CMAKE_PREFIX_PATH "/opt/wasm-libs")
  else()
    set(CMAKE_PREFIX_PATH "/opt/wasm-libs")
  endif()

  # First try the normal FindBoost path
  find_package(Boost QUIET COMPONENTS unit_test_framework)

  if(NOT Boost_FOUND)
    message(WARNING "FindBoost couldn't locate Boost.Test for WASM; "
                    "falling back to manual import from /opt/wasm-libs")

    # Sanity-check expected artifacts
    set(_BOOST_HDR "/opt/wasm-libs/include/boost/version.hpp")
    set(_BOOST_UTF_LIB "/opt/wasm-libs/lib/libboost_unit_test_framework.a")

    if(NOT EXISTS "${_BOOST_HDR}")
      message(FATAL_ERROR "Boost headers not found at ${_BOOST_HDR}")
    endif()
    if(NOT EXISTS "${_BOOST_UTF_LIB}")
      message(FATAL_ERROR "Boost UTF static lib not found at ${_BOOST_UTF_LIB}")
    endif()

    # Create an imported target to mimic Boost::unit_test_framework
    add_library(Boost::unit_test_framework STATIC IMPORTED GLOBAL)
    set_target_properties(Boost::unit_test_framework PROPERTIES
      IMPORTED_LOCATION "${_BOOST_UTF_LIB}"
      INTERFACE_INCLUDE_DIRECTORIES "/opt/wasm-libs/include"
    )

    # Provide variables some tooling may expect
    set(Boost_INCLUDE_DIRS "/opt/wasm-libs/include")
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
  ${Boost_INCLUDE_DIRS}
)

if(EMSCRIPTEN)
  # Emscripten: ensure third-party headers (e.g., gmpxx.h) are reachable
  target_include_directories(test_mpz_get PRIVATE /opt/wasm-libs/include)
endif()

# -----------------------------------------------------------------------------
# Linking
# -----------------------------------------------------------------------------
if(EMSCRIPTEN)
  # Ensure linker can resolve libs in /opt/wasm-libs/lib
  target_link_directories(test_mpz_get PRIVATE /opt/wasm-libs/lib)

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
target_compile_options(test_mpz_get PRIVATE -Wall -Wextra -Wpedantic)

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
  message(STATUS "  (WASM) using /opt/wasm-libs for headers/libs")
else()
  message(STATUS "  (Native) GMP via pkg-config")
endif()
message(STATUS "")
