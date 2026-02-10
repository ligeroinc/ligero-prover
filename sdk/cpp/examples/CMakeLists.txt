cmake_minimum_required(VERSION 3.15)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O2)
set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

# Edit Distance
# ------------------------------------------------------------
add_executable(edit edit_distance/edit_distance.cpp)
target_link_libraries(edit ligetron)

# SHA256
# ------------------------------------------------------------
add_executable(sha256 SHA256/sha256.cpp)
target_link_libraries(sha256 ligetron)

# Poseidon
# ------------------------------------------------------------
add_executable(poseidon_4to1 Poseidon/poseidon_4to1.cpp)
target_link_libraries(poseidon_4to1 ligetron)

add_executable(poseidon_batch_2to1 Poseidon/poseidon_batch_2to1.cpp)
target_link_libraries(poseidon_batch_2to1 ligetron)

add_executable(poseidon_batch_4to1 Poseidon/poseidon_batch_4to1.cpp)
target_link_libraries(poseidon_batch_4to1 ligetron)

# Poseidon 2
# ------------------------------------------------------------
add_executable(poseidon2 Poseidon2/poseidon2_bytes.cpp)
target_link_libraries(poseidon2 ligetron)

add_executable(poseidon2_batch Poseidon2/poseidon2_bytes_batch.cpp)
target_link_libraries(poseidon2_batch ligetron)


# EdDSA
# ------------------------------------------------------------
add_executable(eddsa EdDSA/eddsa_verify_no_args.cpp)
target_link_libraries(eddsa ligetron)

add_executable(eddsa_batch EdDSA/eddsa_batch_verify_no_args.cpp)
target_link_libraries(eddsa_batch ligetron)

# ECDSA
# ------------------------------------------------------------

add_executable(ecdsa_p256_verify ECDSA/ecdsa_p256_verify.cpp)
target_link_libraries(ecdsa_p256_verify ligetron)
target_link_options(ecdsa_p256_verify PRIVATE "-sSTACK_SIZE=100000000")

add_executable(ecdsa_p256_verify_prehashed ECDSA/ecdsa_p256_verify_prehashed.cpp)
target_link_libraries(ecdsa_p256_verify_prehashed ligetron)
target_link_options(ecdsa_p256_verify_prehashed PRIVATE "-sSTACK_SIZE=100000000")
