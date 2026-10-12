/* Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0. */
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <random>
#include <stdexcept>
#include <tuple>
#include <vector>
#include <util/csprng.hpp>
#include <util/mpz_get.hpp>
#include <util/mpz_vector.hpp>
#include <zkp/hash.hpp>

using namespace ligero::vm;
using namespace ligero::vm::zkp;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename T>
void check_hash(const std::vector<T>& values) {
    sha256 scalar, bulk;
    for (const auto& value : values) scalar << value;
    bulk << values;
    require(scalar.flush_digest() == bulk.flush_digest(), "vector hash changed bytes");
}

void check_vectors() {
    mpz_vector values;
    for (unsigned bits = 0; bits <= 256; ++bits) {
        mpz_class power = mpz_class(1) << bits;
        values.push_back(power - 1);
        if (bits < 256) values.push_back(power);
        values.push_back(-(power - 1));
    }
    for (const size_t word_bytes : {size_t(4), size_t(8)}) {
        const size_t words = 32 / word_bytes;
        std::vector<uint8_t> expected(values.size() * 32), actual(expected.size(), 0xff);
        size_t expected_count = 0;
        for (size_t i = 0; i < values.size(); ++i) {
            size_t count = 0;
            mpz_export(expected.data() + i * 32, &count, -1, word_bytes, -1, 0, values[i].get_mpz_t());
            expected_count += count;
        }
        const auto count = values.export_limbs(actual.data(), values.size() * words, word_bytes, words);
        require(actual == expected && count == expected_count, "fixed-width export changed");
        mpz_vector recovered;
        recovered.import_limbs(actual.data(), values.size() * words, word_bytes, words);
        for (size_t i = 0; i < values.size(); ++i)
            require(recovered[i] == abs(values[i]), "fixed-width import changed");
        // Reuse allocated limbs, including a negative prior value and all-zero input.
        std::fill(actual.begin(), actual.end(), 0);
        recovered.import_limbs(actual.data(), values.size() * words, word_bytes, words);
        for (const auto& value : recovered) require(value == 0, "zero import was not normalized");
    }
    // Non-native byte lengths and byte order exercise the general fallback.
    const std::array<uint8_t, 9> bytes{1,2,3,4,5,6,7,8,9};
    for (const int endian : {-1, 0, 1}) {
        mpz_class actual, expected;
        mpz_import_words(actual.get_mpz_t(), 3, 3, endian, bytes.data());
        mpz_import(expected.get_mpz_t(), 3, -1, 3, endian, 0, bytes.data());
        require(actual == expected, "non-native import changed");
    }
}

void check_random_stream() {
    unsigned char key[32], iv[16];
    for (size_t i = 0; i < sizeof(key); ++i) key[i] = static_cast<unsigned char>(i * 7 + 1);
    for (size_t i = 0; i < sizeof(iv); ++i) iv[i] = static_cast<unsigned char>(i * 13 + 2);
    mpz_random_engine engine(key, iv);
    std::array<uint64_t, mpz_random_engine::buffer_size> zeros{}, bytes{};
    auto* reference = EVP_CIPHER_CTX_new();
    require(reference != nullptr, "AES allocation failed");
    require(EVP_EncryptInit_ex(reference, EVP_aes_256_ctr(), nullptr, key, iv) == 1, "AES init failed");
    size_t offset = bytes.size();
    for (size_t i = 0; i < 4096; ++i) {
        const size_t count = 1 + i % 7;
        if (offset + count > bytes.size()) {
            int length = 0;
            require(EVP_EncryptUpdate(reference, reinterpret_cast<unsigned char*>(bytes.data()), &length,
                reinterpret_cast<const unsigned char*>(zeros.data()), sizeof(bytes)) == 1, "AES update failed");
            offset = 0;
        }
        mpz_class expected, actual;
        mpz_import(expected.get_mpz_t(), count, -1, sizeof(uint64_t), 0, 0, bytes.data() + offset);
        engine(actual, count * sizeof(uint64_t));
        require(actual == expected, "AES stream consumption changed");
        offset += count;
    }
    EVP_CIPHER_CTX_free(reference);
}

void check_truncation() {
    for (unsigned bits : {0, 31, 32, 63, 64, 65, 127, 128, 255, 256, 1023}) {
        mpz_class value = (mpz_class(1) << bits) + mpz_class("fedcba9876543210", 16);
        mpz_class low;
        mpz_fdiv_r_2exp(low.get_mpz_t(), value.get_mpz_t(), 64);
        uint64_t expected = 0;
        mpz_export(&expected, nullptr, -1, sizeof(expected), 0, 0, low.get_mpz_t());
        require(ligero::mpz_get_u64(value) == expected, "wide positive getter failed");
        value = -value;
        require(ligero::mpz_get_u64(value.get_mpz_t()) == expected, "wide negative getter failed");
    }
}

template <typename Fn>
double seconds(Fn&& fn) {
    const auto begin = std::chrono::steady_clock::now();
    fn();
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
}

void benchmark() {
    constexpr size_t count = 65536;
    std::vector<uint32_t> words(8 * count);
    std::mt19937 rng(7);
    for (auto& word : words) word = rng();
    sha256::digest result;
    const auto scalar = seconds([&] { for (unsigned j = 0; j < 24; ++j) {
        sha256 h; for (auto word : words) h << word; result = h.flush_digest();
    }});
    const auto bulk = seconds([&] { for (unsigned j = 0; j < 24; ++j) {
        sha256 h; h << words; result = h.flush_digest();
    }});
    mpz_vector values;
    values.import_limbs(words.data(), words.size(), 4, 8);
    std::vector<uint32_t> output(words.size());
    const auto old_export = seconds([&] { for (unsigned j = 0; j < 24; ++j) {
        std::memset(output.data(), 0, output.size() * sizeof(uint32_t));
        for (size_t i = 0; i < count; ++i) mpz_export(output.data() + i * 8, nullptr, -1, 4, -1, 0, values[i].get_mpz_t());
    }});
    const auto new_export = seconds([&] { for (unsigned j = 0; j < 24; ++j)
        values.export_limbs(output.data(), output.size(), 4, 8);
    });
    const auto old_import = seconds([&] { for (unsigned j = 0; j < 24; ++j)
        for (size_t i = 0; i < count; ++i) mpz_import(values[i].get_mpz_t(), 8, -1, 4, -1, 0, words.data() + i * 8);
    });
    const auto new_import = seconds([&] { for (unsigned j = 0; j < 24; ++j)
        values.import_limbs(words.data(), words.size(), 4, 8);
    });
    std::cout << "hash scalar=" << scalar << " bulk=" << bulk
              << "; export generic=" << old_export << " bulk=" << new_export
              << "; import generic=" << old_import << " bulk=" << new_import << '\n';
    require(output == words, "benchmark export changed values");
}

int main(int argc, char**) {
    try {
        check_hash(std::vector<uint32_t>{});
        check_hash(std::vector<uint32_t>{0,1,0xffffffffU,0x12345678});
        check_hash(std::vector<uint64_t>{0,1,UINT64_MAX,UINT64_C(0x123456789abcdef0)});
        check_hash(std::vector<int64_t>{INT64_MIN,-1,0,INT64_MAX});
        check_hash(std::vector<std::string>{"", "alpha", "beta"});
        check_vectors();
        check_random_stream();
        check_truncation();
        if (argc > 1) benchmark();
        std::cout << "PASS: byte-identical hashes, GMP serialization, AES stream, bounded getters\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
