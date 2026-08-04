cmake_minimum_required(VERSION 3.15)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-O2)
set(CMAKE_EXECUTABLE_SUFFIX ".wasm")

# Edit Distance
# ------------------------------------------------------------
add_executable(edit_distance edit_distance/edit_distance.cpp)
target_link_libraries(edit_distance ligetron)

# SHA256
# ------------------------------------------------------------
add_executable(sha256 SHA256/sha256.cpp)
target_link_libraries(sha256 ligetron)

# SHA512
# ------------------------------------------------------------
add_executable(sha512 SHA512/sha512.cpp)
target_link_libraries(sha512 ligetron)

# Keccak-256 / Ethereum address
# ------------------------------------------------------------
add_executable(eth_address_verify Keccak256/eth_address_verify.cpp)
target_link_libraries(eth_address_verify ligetron)

# Poseidon
# ------------------------------------------------------------
add_executable(poseidon_2to1 Poseidon/poseidon_2to1.cpp)
target_link_libraries(poseidon_2to1 ligetron)

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

# Ed25519
# ------------------------------------------------------------
add_executable(ed25519_verify EdDSA/ed25519_sigver.cpp)
target_link_libraries(ed25519_verify ligetron)

# ECDSA
# ------------------------------------------------------------

add_executable(ecdsa_p256_verify ECDSA/p256_sha256_sigver.cpp)
target_link_libraries(ecdsa_p256_verify ligetron)
target_link_options(ecdsa_p256_verify PRIVATE "-sSTACK_SIZE=100000000")

add_executable(ecdsa_secp256k1_verify ECDSA/secp256k1_sha256_sigver.cpp)
target_link_libraries(ecdsa_secp256k1_verify ligetron)
target_link_options(ecdsa_secp256k1_verify PRIVATE "-sSTACK_SIZE=100000000")
