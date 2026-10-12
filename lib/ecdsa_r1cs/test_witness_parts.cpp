// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "witness_parts.hpp"

#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace ecdsa_r1cs;
namespace pw = ecdsa_r1cs::witness;
using Clock = std::chrono::steady_clock;

namespace {
void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
template <typename F> void rejects(F&& action) {
    try { action(); } catch (const std::runtime_error&) { return; }
    throw std::runtime_error("invalid witness part unexpectedly accepted");
}

struct TimedPart { pw::Part part; double seconds; };
TimedPart generate(unsigned kind, const std::array<Big, 5>& input) {
    const auto start = Clock::now();
    auto part = pw::generate(kind, input);
    return {std::move(part), std::chrono::duration<double>(Clock::now() - start).count()};
}

void fixture(const Big& secret, const Big& nonce, const Big& digest,
             const std::string& label, const std::filesystem::path& artifacts) {
    const auto curve = curve_by_name("secp256k1");
    const auto key = native_mul(curve, secret, {curve.gx, curve.gy, false});
    const auto signature = native_sign(curve, digest, secret, nonce);
    const std::array<Big, 5> inputs{key.x, key.y, signature.first, signature.second, digest};

    const auto checked_start = Clock::now();
    Builder checked;
    verify_ecdsa(checked, curve, digest, signature.first, signature.second, key);
    checked.finish();
    const auto checked_seconds = std::chrono::duration<double>(Clock::now() - checked_start).count();
    constexpr auto expected_shape =
        "44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f";
    require(checked.shape_hash() == expected_shape && checked.constraints() == 596424 &&
            checked.variables() == 591290 && checked.public_inputs() == 20,
        "pinned secp256k1 circuit changed for " + label + ": actual shape=" +
        checked.shape_hash() + ", rows=" + std::to_string(checked.constraints()) +
        ", variables=" + std::to_string(checked.variables()) +
        ", public_inputs=" + std::to_string(checked.public_inputs()) +
        "; expected shape=" + expected_shape +
        ", rows=596424, variables=591290, public_inputs=20");

    const auto parallel_start = Clock::now();
    auto fixed_job = std::async(std::launch::async, generate, 0, std::cref(inputs));
    auto variable_job = std::async(std::launch::async, generate, 1, std::cref(inputs));
    Builder merged(Builder::Mode::WitnessOnly);
    const auto prepared = pw::prepare(merged, curve, inputs);
    const auto fixed = fixed_job.get();
    const auto variable = variable_job.get();
    pw::merge(merged, curve, prepared, fixed.part, variable.part);
    merged.finish();
    const auto parallel_seconds = std::chrono::duration<double>(Clock::now() - parallel_start).count();
    require(merged.witness_values() == checked.witness_values(), "parallel witness vector changed");
    require(merged.variables() == 591290,
            "pinned merged witness count changed: actual=" + std::to_string(merged.variables()) +
            "; expected=591290");

    const auto fixed_path = artifacts / (label + "-fixed.bin");
    const auto variable_path = artifacts / (label + "-variable.bin");
    pw::save(fixed.part, fixed_path.string());
    pw::save(variable.part, variable_path.string());
    const auto loaded_fixed = pw::load(fixed_path.string(), pw::prefix_end, pw::fixed_end);
    const auto loaded_variable = pw::load(variable_path.string(), pw::fixed_end, pw::variable_end);
    Builder loaded(Builder::Mode::WitnessOnly);
    const auto loaded_prepared = pw::prepare(loaded, curve, inputs);
    pw::merge(loaded, curve, loaded_prepared, loaded_fixed, loaded_variable);
    loaded.finish();
    require(loaded.witness_values() == checked.witness_values(), "serialized witness vector changed");

    // Boundary checks supplement enforcement by the independently pinned rows.
    const auto reject_fixed = [&] {
        rejects([&] { pw::load(fixed_path.string(), pw::prefix_end, pw::fixed_end); });
    };
    rejects([&] { pw::load(fixed_path.string(), pw::fixed_end, pw::variable_end); });
    {
        std::ofstream append(fixed_path, std::ios::binary | std::ios::app);
        append.put(0);
    }
    reject_fixed();
    pw::save(fixed.part, fixed_path.string());
    {
        std::fstream mutate(fixed_path, std::ios::binary | std::ios::in | std::ios::out);
        mutate.seekp(12); // First hint follows magic, start, count.
        pw::integer(mutate, native_modulus());
    }
    reject_fixed();
    pw::save(fixed.part, fixed_path.string());
    {
        std::fstream mutate(fixed_path, std::ios::binary | std::ios::in | std::ios::out);
        mutate.seekp(8);
        pw::u32(mutate, static_cast<uint32_t>(fixed.part.values.size()) - 1);
    }
    reject_fixed();
    pw::save(fixed.part, fixed_path.string());
    std::filesystem::resize_file(fixed_path, std::filesystem::file_size(fixed_path) - 1);
    reject_fixed();
    auto invalid_point = fixed.part;
    invalid_point.point.x.limbs[0] = LC::wire(pw::fixed_end);
    pw::save(invalid_point, fixed_path.string());
    reject_fixed();
    std::filesystem::remove(fixed_path);
    std::filesystem::remove(variable_path);
    std::cout << "{\"fixture\":\"" << label << "\",\"checked_seconds\":" << checked_seconds
              << ",\"fixed_part_seconds\":" << fixed.seconds
              << ",\"variable_part_seconds\":" << variable.seconds
              << ",\"parallel_and_merge_seconds\":" << parallel_seconds
              << ",\"equal_witness_values\":" << merged.variables() << "}\n";
}
} // namespace

int main(int argc, char** argv) {
    try {
        const std::filesystem::path artifacts = argc > 1 ? argv[1] : "witness-parts-test-artifacts";
        std::filesystem::create_directories(artifacts);
        const Big digest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
        fixture(7, 11, digest, "public-template", artifacts);
        fixture(13, 19, digest + 1, "alternate-key", artifacts);
        fixture(23, 29, digest + 2, "third-key", artifacts);
        fixture(31, 37, Big(0), "zero-digest", artifacts);
        std::cout << "PASS: parallel generation and serialized merge equal every checked witness value\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
