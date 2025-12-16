# Minimum CMake version
cmake_minimum_required(VERSION 3.15)

# Project name and version
project(ligetron VERSION 1.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the include directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Collect all source files in the src directory
file(GLOB_RECURSE SOURCES ${CMAKE_SOURCE_DIR}/src/*.cpp)

# Create a static or shared library
add_library(ligetron STATIC ${SOURCES})

target_compile_options(ligetron PRIVATE -O2)
target_include_directories(ligetron PUBLIC ${CMAKE_SOURCE_DIR}/include)

add_subdirectory(examples)
add_subdirectory(tests)
