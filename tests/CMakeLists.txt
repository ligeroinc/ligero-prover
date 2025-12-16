cmake_minimum_required(VERSION 3.24)

# Note: Don't call project() here - we're part of the parent LigeroVM project
# Calling project() creates a new scope that can interfere with test
# project(Tests)

enable_testing()

add_subdirectory(webgpu)
add_subdirectory(util)

file(GLOB TEST_FILES "${CMAKE_SOURCE_DIR}/tests/*.wat")

# Detect if we're building with Emscripten
if(EMSCRIPTEN)
    set(TEST_COMMAND node ${CMAKE_BINARY_DIR}/webgpu_prover.js)
else()
    set(TEST_COMMAND webgpu_prover)
endif()

foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME)

    if(EMSCRIPTEN)
        add_test(
            NAME ${TEST_NAME}
            COMMAND node ${CMAKE_BINARY_DIR}/webgpu_prover.js "{\"program\":\"${CMAKE_SOURCE_DIR}/tests/${TEST_NAME}\", \
                                          \"shader-path\": \"${CMAKE_SOURCE_DIR}/shader\"}"
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}  # Not ${CMAKE_BINARY_DIR}/tests!
        )
    else()
        add_test(
            NAME ${TEST_NAME}
            COMMAND webgpu_prover "{\"program\":\"${CMAKE_SOURCE_DIR}/tests/${TEST_NAME}\", \
                                    \"shader-path\": \"${CMAKE_SOURCE_DIR}/shader\"}"
        )
    endif()
endforeach()
