// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.

#include <zkp/ecdsa_r1cs_statement.hpp>

#include <iostream>
#include <memory>
#include <string>

#include <wabt/binary-reader-ir.h>
#include <wabt/binary-reader.h>
#include <wabt/error-formatter.h>
#include <wabt/wast-lexer.h>
#include <wabt/wast-parser.h>

namespace zkp = ligero::vm::zkp;
using Hasher = zkp::sha256;

namespace {

constexpr std::string_view shape =
    "44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f";
constexpr std::string_view ecdsa_program =
    "(module (import \"ecdsa_r1cs\" \"assert_secp256k1_v1\" (func)))";

void require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::unique_ptr<wabt::Module> parse(std::string_view wat) {
    wabt::Errors errors;
    auto lexer = wabt::WastLexer::CreateBufferLexer(
        "statement-test.wat", wat.data(), wat.size(), &errors);
    wabt::WastParseOptions options{wabt::Features{}};
    std::unique_ptr<wabt::Module> module;
    if (wabt::Failed(wabt::ParseWatModule(lexer.get(), &module, &errors, &options))) {
        throw std::runtime_error(wabt::FormatErrorsToString(
            errors, wabt::Location::Type::Text));
    }
    return module;
}

Hasher::digest program_hash(std::string_view bytes) {
    return zkp::hash<Hasher>(zkp::byte_view{
        reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()});
}

std::string hex(const Hasher::digest& digest) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    for (uint8_t byte : digest.data) {
        result.push_back(alphabet[byte >> 4]);
        result.push_back(alphabet[byte & 15]);
    }
    return result;
}

void test_import_detection() {
    for (auto wat : {
             "(module)",
             "(module (import \"env\" \"assert_secp256k1_v1\" (func)))",
             "(module (import \"ecdsa_r1cs_extra\" \"assert_secp256k1_v1\" (func)))",
             "(module (import \"ecdsa_r1c\" \"assert_secp256k1_v1\" (func)))",
             "(module (import \"ECDSA_R1CS\" \"assert_secp256k1_v1\" (func)))",
             "(module (func (export \"ecdsa_r1cs\")))"}) {
        require(!zkp::imports_ecdsa_r1cs(*parse(wat)),
                "unrelated import/export enabled ECDSA binding");
    }
    for (auto wat : {
             ecdsa_program,
             std::string_view{"(module (import \"ecdsa_r1cs\" \"unknown_function\" (func)))"},
             std::string_view{"(module (import \"env\" \"first\" (func)) "
                              "(import \"ecdsa_r1cs\" \"second\" (func)))"},
             std::string_view{"(module (import \"ecdsa_r1cs\" \"memory\" (memory 1)))"}}) {
        require(zkp::imports_ecdsa_r1cs(*parse(wat)),
                "ECDSA module import did not enable binding");
    }

    // A minimal binary module with an unused ECDSA function import.
    const std::vector<uint8_t> wasm = {
        0, 97, 115, 109, 1, 0, 0, 0,
        1, 4, 1, 96, 0, 0,
        2, 34, 1, 10, 'e', 'c', 'd', 's', 'a', '_', 'r', '1', 'c', 's',
        19, 'a', 's', 's', 'e', 'r', 't', '_', 's', 'e', 'c', 'p', '2', '5',
        '6', 'k', '1', '_', 'v', '1', 0, 0};
    wabt::Module binary_module;
    wabt::Errors errors;
    require(wabt::Succeeded(wabt::ReadBinaryIr(
                "statement-test.wasm", wasm.data(), wasm.size(),
                wabt::ReadBinaryOptions{}, &errors, &binary_module)),
            "binary import fixture did not parse");
    require(zkp::imports_ecdsa_r1cs(binary_module),
            "binary ECDSA import did not enable binding");
}

void test_statement_binding() {
    // This is the existing public-input hash sequence. Private inputs are omitted.
    Hasher::digest instance_hash;
    instance_hash = zkp::hash<Hasher>(instance_hash,
        std::vector<uint8_t>{'L', 'i', 'g', 'e', 'r', 'o', 0});
    instance_hash = zkp::hash<Hasher>(instance_hash,
        std::vector<uint8_t>{1, 2, 3});
    require(hex(instance_hash) ==
                "2a2f0ebd6044101079a7634ce6dc786a72e5a6a9e4e1f46197e2fd0f274b7bd2",
            "legacy instance hash changed");
    const auto module = parse(ecdsa_program);
    const auto program_digest = program_hash(ecdsa_program);
    const auto statement = zkp::bind_ecdsa_r1cs_statement<Hasher>(
        *module, program_digest, instance_hash, shape);
    // Fixed vectors independently generated with Python hashlib.sha256.
    require(hex(statement) ==
                "547a32a3072ab60e8120c30dcf924165ec9ec62d70fa28db445190ad608245f3",
            "ECDSA statement framing changed");
    const Hasher::digest stage1_root;
    const auto stage1_seed = zkp::hash<Hasher>(
        "LigetronStage1", stage1_root, statement);
    require(hex(stage1_seed) ==
                "a6abca43fa822269025e2c7c6444dea9d583ee117464553e48b953ee7f0df340",
            "ECDSA Stage 1 challenge vector changed");

    auto assert_changed = [&](const auto& changed, std::string_view what) {
        require(changed != statement, what);
        require(zkp::hash<Hasher>("LigetronStage1", stage1_root, changed) != stage1_seed,
                "changed statement did not change Stage 1 challenge");
    };
    const auto reformatted_program = std::string(ecdsa_program) + "\n";
    assert_changed(zkp::bind_ecdsa_r1cs_statement<Hasher>(
                       *parse(reformatted_program), program_hash(reformatted_program),
                       instance_hash, shape),
                   "exact program bytes are not bound");
    auto changed_shape = std::string(shape);
    changed_shape.front() = '5';
    assert_changed(zkp::bind_ecdsa_r1cs_statement<Hasher>(
                       *module, program_digest, instance_hash, changed_shape),
                   "circuit shape is not bound");
    auto changed_inputs = instance_hash;
    changed_inputs.data[0] ^= 1;
    assert_changed(zkp::bind_ecdsa_r1cs_statement<Hasher>(
                       *module, program_digest, changed_inputs, shape),
                   "public inputs are not bound");
    assert_changed(instance_hash, "ECDSA transcript is not domain separated");

    // Both drivers use this identical helper: repeated construction is deterministic.
    require(statement == zkp::bind_ecdsa_r1cs_statement<Hasher>(
                *module, program_digest, instance_hash, shape),
            "statement binding is not deterministic");

    for (auto wat : {"(module)",
                     "(module (import \"env\" \"assert_secp256k1_v1\" (func)))"}) {
        const auto legacy = parse(wat);
        require(zkp::bind_ecdsa_r1cs_statement<Hasher>(
                    *legacy, program_digest, instance_hash, shape) == instance_hash,
                "legacy transcript changed");
        require(zkp::bind_ecdsa_r1cs_statement<Hasher>(
                    *legacy, program_hash("different"), instance_hash,
                    changed_shape) == instance_hash,
                "legacy transcript acquired program or shape binding");
    }

    for (const auto& invalid_shape : {std::string{}, std::string(63, 'a'),
                                     std::string(65, 'a'), std::string(64, 'G')}) {
        bool rejected = false;
        try {
            (void)zkp::bind_ecdsa_r1cs_statement<Hasher>(
                *module, program_digest, instance_hash, invalid_shape);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "malformed circuit shape was accepted");
    }
}

}  // namespace

int main() {
    try {
        test_import_detection();
        test_statement_binding();
        std::cout << "ECDSA statement binding and legacy compatibility passed\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
