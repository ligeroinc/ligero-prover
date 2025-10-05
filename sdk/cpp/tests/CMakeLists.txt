cmake_minimum_required(VERSION 3.15)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O2)
set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

add_executable(bn254fr_test bn254fr_test.cpp)
target_link_libraries(bn254fr_test ligetron)

