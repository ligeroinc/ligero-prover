// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include "r1cs.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace ligero::ecdsa_r1cs_host {

using ecdsa_r1cs::Big;
using ecdsa_r1cs::LC;
using EcdsaRow = std::array<LC, 3>;
inline constexpr std::uint64_t expected_rows = 596424;
inline constexpr std::uint64_t expected_variables = 591290;
inline constexpr std::string_view expected_shape =
    "44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f";

struct FixedCircuit {
    std::vector<EcdsaRow> rows;
};

inline std::filesystem::path template_path() {
    if (const auto* path = std::getenv("LIGETRON_ECDSA_TEMPLATE")) return path;
    return "/ecdsa_secp256k1_v1.r1cs";
}

namespace template_detail {

class Reader {
public:
    explicit Reader(std::span<const unsigned char> bytes) : bytes_(bytes) {}
    std::span<const unsigned char> take(std::size_t count) {
        if (count > bytes_.size()) throw std::runtime_error("truncated ECDSA R1CS template");
        const auto result = bytes_.first(count);
        bytes_ = bytes_.subspan(count);
        return result;
    }
    std::uint32_t u32() {
        const auto bytes = take(4);
        std::uint32_t result = 0;
        for (unsigned i = 0; i < 4; ++i) result |= std::uint32_t(bytes[i]) << (8 * i);
        return result;
    }
    std::uint64_t u64() {
        const auto bytes = take(8);
        std::uint64_t result = 0;
        for (unsigned i = 0; i < 8; ++i) result |= std::uint64_t(bytes[i]) << (8 * i);
        return result;
    }
    Big field() {
        const auto bytes = take(32);
        Big value;
        mpz_import(value.get_mpz_t(), bytes.size(), -1, 1, 0, 0, bytes.data());
        return value;
    }
    bool empty() const { return bytes_.empty(); }
private:
    std::span<const unsigned char> bytes_;
};

inline void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

// This is exactly Builder::shape_hash: the domain, serialized row section,
// and little-endian u64 variable/public-input/row counts. Hash the bytes in a
// single pass before parsing; neither private inputs nor asset-supplied hashes
// can select the circuit accepted by this backend.
inline void validate_shape(std::span<const unsigned char> rows) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> hash(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(hash && EVP_DigestInit_ex(hash.get(), EVP_sha256(), nullptr) == 1,
            "ECDSA R1CS template SHA-256 initialization failed");
    constexpr std::string_view domain = "ecdsa_r1cs:BN254:shape:v1";
    std::array<unsigned char, 24> metadata{};
    constexpr std::array<std::uint64_t, 3> values{expected_variables, 20, expected_rows};
    for (unsigned i = 0; i < 3; ++i)
        for (unsigned j = 0; j < 8; ++j) metadata[8 * i + j] = (values[i] >> (8 * j)) & 255;
    require(EVP_DigestUpdate(hash.get(), domain.data(), domain.size()) == 1 &&
            EVP_DigestUpdate(hash.get(), rows.data(), rows.size()) == 1 &&
            EVP_DigestUpdate(hash.get(), metadata.data(), metadata.size()) == 1,
            "ECDSA R1CS template SHA-256 update failed");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    require(EVP_DigestFinal_ex(hash.get(), digest.data(), &size) == 1 && size == 32,
            "ECDSA R1CS template SHA-256 finalization failed");
    std::ostringstream hex;
    for (unsigned i = 0; i < size; ++i)
        hex << std::hex << std::setw(2) << std::setfill('0') << unsigned(digest[i]);
    require(hex.str() == expected_shape, "ECDSA R1CS template shape hash mismatch");
}

} // namespace template_detail

inline FixedCircuit load_fixed_circuit(const std::filesystem::path& path) {
    using namespace template_detail;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    require(bool(input), "missing precomputed ECDSA R1CS template: " + path.string());
    const auto size = input.tellg();
    // The pinned standard R1CS file has one exact layout. Bound the allocation
    // before reading or trusting any lengths stored inside the file.
    constexpr std::size_t file_size = 111833276;
    require(size == std::streampos(file_size), "unexpected ECDSA R1CS template size");
    std::vector<unsigned char> bytes(file_size);
    input.seekg(0);
    input.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
    require(bool(input), "could not read ECDSA R1CS template");
    Reader file(bytes);
    const auto magic = file.take(4);
    require(std::memcmp(magic.data(), "r1cs", 4) == 0 && file.u32() == 1 && file.u32() == 3,
            "unsupported ECDSA R1CS template format");
    require(file.u32() == 1 && file.u64() == 64, "unexpected ECDSA R1CS template header");
    require(file.u32() == 32 && file.field() == ecdsa_r1cs::native_modulus(),
            "unexpected ECDSA R1CS template field");
    require(file.u32() == expected_variables && file.u32() == 0 && file.u32() == 20 &&
            file.u32() == 0 && file.u64() == expected_variables && file.u32() == expected_rows,
            "unexpected ECDSA R1CS template counts");
    require(file.u32() == 2, "missing ECDSA R1CS template rows");
    const auto row_size = file.u64();
    require(row_size == 107102844, "unexpected ECDSA R1CS template row bytes");
    const auto row_bytes = file.take(static_cast<std::size_t>(row_size));
    validate_shape(row_bytes);
    require(file.u32() == 3 && file.u64() == 8 * expected_variables,
            "unexpected ECDSA R1CS template labels");
    for (std::uint64_t wire = 0; wire < expected_variables; ++wire)
        require(file.u64() == wire, "nonidentity ECDSA R1CS template labels");
    require(file.empty(), "trailing data in ECDSA R1CS template");

    Reader rows(row_bytes);
    FixedCircuit result;
    result.rows.reserve(expected_rows);
    for (std::uint64_t i = 0; i < expected_rows; ++i) {
        EcdsaRow row;
        for (auto& expression : row) {
            const auto count = rows.u32();
            require(count <= expected_variables, "too many ECDSA R1CS template terms");
            std::vector<ecdsa_r1cs::Term> terms;
            terms.reserve(count);
            for (std::uint32_t term = 0; term < count; ++term) {
                const auto wire = rows.u32();
                auto coefficient = rows.field();
                require(wire < expected_variables && (term == 0 || wire > terms.back().wire) &&
                        coefficient > 0 && coefficient < ecdsa_r1cs::native_modulus(),
                        "noncanonical ECDSA R1CS template term");
                terms.push_back({wire, std::move(coefficient)});
            }
            expression = LC(std::move(terms));
        }
        result.rows.push_back(std::move(row));
    }
    require(rows.empty(), "trailing ECDSA R1CS row bytes");
    return result;
}

} // namespace ligero::ecdsa_r1cs_host
