cmake_minimum_required(VERSION 3.24)

project(Tests)

enable_testing()

file(GLOB TEST_FILES "${CMAKE_SOURCE_DIR}/tests/*.wat")

foreach(TEST_FILE ${TEST_FILES})
    get_filename_component(TEST_NAME ${TEST_FILE} NAME)

    add_test(
        NAME ${TEST_NAME}
        COMMAND webgpu_prover "{\"program\":\"${CMAKE_SOURCE_DIR}/tests/${TEST_NAME}\", \
                                \"shader-path\": \"${CMAKE_SOURCE_DIR}/shader\"}"
    )
endforeach()
