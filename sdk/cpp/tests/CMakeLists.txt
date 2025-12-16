cmake_minimum_required(VERSION 3.15)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O2)
set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

add_executable(bn254fr_test bn254fr_test.cpp)
target_link_libraries(bn254fr_test ligetron)

add_executable(uint256_test uint256_test.cpp)
target_link_libraries(uint256_test ligetron)

add_executable(uint256_cpp_test uint256_cpp_test.cpp)
target_link_libraries(uint256_cpp_test ligetron)

add_executable(prime_field_uint256_test prime_field_uint256_test.cpp)
target_link_libraries(prime_field_uint256_test ligetron)
