// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include <ecdsa_r1cs/circuit.hpp>
#include <ecdsa_r1cs/template.hpp>
#include <ecdsa_r1cs/witness_parts.hpp>

#include <runtime.hpp>
#include <params.hpp>
#include <host_modules/host_interface.hpp>
#include <zkp/nonbatch_context.hpp>

#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <vector>

#ifdef __EMSCRIPTEN__
// Definitions live in src/ecdsa_r1cs_host.cpp, once per backend binary.
extern "C" int ligero_ecdsa_parallel_witness(const char* input);
// 0: verifier; 1: sequential witness with fixed-table preparation;
// 2: parallel witness workers prepared by the browser helper.
extern "C" int ligero_ecdsa_prepare(int witness_mode);
#endif

namespace ligero::ecdsa_r1cs_host {

// Load the template generated before deployment and validate its pinned shape.
// The verifier uses only this public asset. No private witness can select rows,
// coefficients, circuit branches, or the verifier's allocation schedule.
const FixedCircuit& fixed_circuit();

struct PrivateWitnessCache {
    std::array<Big, 20> input;
    std::vector<Big> values;
};

// This single-entry cache avoids regenerating the identical witness during the
// three native proving stages. Thread-local storage isolates concurrent native
// proofs; the browser uses a fresh worker per proof. The bounded single entry
// remains until overwritten or thread/runtime exit. The verifier never reads it.
inline const std::vector<Big>& private_witness(const std::array<Big, 20>& input) {
    static thread_local PrivateWitnessCache cache;
    if (!cache.values.empty() && cache.input == input) return cache.values;
    const auto started = std::chrono::steady_clock::now();
    const Big limb_limit = Big(1) << 64;
    std::array<Big, 5> components;
    for (std::size_t component = 0; component < components.size(); ++component) {
        components[component] = 0;
        for (int limb = 3; limb >= 0; --limb) {
            const auto& value = input[4 * component + limb];
            if (value < 0 || value >= limb_limit) {
                throw std::runtime_error("ECDSA input limb is outside 64 bits");
            }
            components[component] <<= 64;
            components[component] += value;
        }
    }
    const auto curve = ecdsa_r1cs::curve_by_name("secp256k1");
    ecdsa_r1cs::Builder builder(ecdsa_r1cs::Builder::Mode::WitnessOnly);
#ifdef __EMSCRIPTEN__
    const auto* parallel = std::getenv("LIGETRON_ECDSA_PARALLEL");
    if (parallel && std::string_view(parallel) == "1") {
        const auto prepared = ecdsa_r1cs::witness::prepare(builder, curve, components);
        std::string input_text;
        for (const auto& component : components) input_text += component.get_str(16) + '\n';
        if (ligero_ecdsa_parallel_witness(input_text.c_str()) != 0)
            throw std::runtime_error("parallel ECDSA witness generation failed");
        const auto fixed = ecdsa_r1cs::witness::load("/witness-fixed.bin",
            ecdsa_r1cs::witness::prefix_end, ecdsa_r1cs::witness::fixed_end);
        const auto variable = ecdsa_r1cs::witness::load("/witness-variable.bin",
            ecdsa_r1cs::witness::fixed_end, ecdsa_r1cs::witness::variable_end);
        ecdsa_r1cs::witness::merge(builder, curve, prepared, fixed, variable);
        std::remove("/witness-fixed.bin");
        std::remove("/witness-variable.bin");
    } else
#endif
    {
        ecdsa_r1cs::verify_ecdsa(builder, curve, components[4], components[2],
            components[3], {components[0], components[1], false});
    }
    builder.finish();
    // This pass produces untrusted witness hints only. Every value is still
    // constrained below by the independently validated immutable row template.
    if (builder.variables() != expected_variables || builder.public_inputs() != 20)
        throw std::runtime_error("ECDSA witness layout changed");
    PrivateWitnessCache next{input, builder.witness_values()};
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (next.values[i + 1] != input[i]) {
            throw std::runtime_error("ECDSA witness input ordering changed");
        }
    }
    // Publish only a fully built, validated cache entry. Failed generation
    // leaves the previous entry coherent, including when the caller retries.
    cache = std::move(next);
    std::cout << "ECDSA private-witness seconds: "
              << std::chrono::duration<double>(
                  std::chrono::steady_clock::now() - started).count() << '\n';
    return cache.values;
}

// Compose with the enclosing proof, sharing the original private entry wires.
// No public constants are taken from these values, and context.finalize() is
// deliberately left to the enclosing guest program.
template <typename Context>
void append(Context& context,
            const std::array<ligero::vm::zkp::lazy_witness*, 20>& input) {
    using Field = typename Context::field_type;
    using Witness = ligero::vm::zkp::lazy_witness;
    if (Field::modulus != ecdsa_r1cs::native_modulus()) {
        throw std::runtime_error("ECDSA R1CS host requires the BN254 scalar field");
    }
    const auto& circuit = fixed_circuit();
    auto& manager = context.backend().manager();
    using RandomPolicy = typename std::remove_reference_t<decltype(manager)>::random_policy;

    const std::vector<Big>* values = nullptr;
    if constexpr (Context::role == ligero::vm::zkp::context_role::prover) {
        std::array<Big, 20> actual;
        for (std::size_t i = 0; i < actual.size(); ++i) {
            actual[i] = *input[i]->value_ptr();
        }
        values = &private_witness(actual);
    }

    std::vector<Witness*> master;
    master.reserve(expected_variables);
    master.push_back(manager.acquire_witness(1u));
    manager.constrain_constant(*master[0], 1u);
    for (auto* witness : input) {
        // Aliasing is a direct wire identity: all input range checks and ECDSA
        // equations constrain the very handles bound to the guest bytes.
        witness->set_witness_status(true);
        master.push_back(witness);
    }
    // Allocate auxiliaries only on their first public-template occurrence.
    // Together with last-use release below, this lets the manager recycle
    // storage instead of keeping all 591290 wire handles live at once.
    master.resize(expected_variables, nullptr);
    auto master_for = [&](std::uint32_t wire) {
        auto*& witness = master[wire];
        if (!witness) witness = manager.acquire_witness(values ? (*values)[wire] : Big(0));
        return witness;
    };

    // Difference LCs are common. These exact field identities avoid modular
    // multiplication without changing the random-coefficient schedule.
    Big product, value, random, weighted_random;
    struct Operand { Witness* witness; bool temporary; };
    auto materialize = [&](const EcdsaExpression& expression) {
        // A unit LC is already the exact constrained value. Passing its
        // original handle avoids a redundant linear copy; the manager clones
        // handles that already occupy another quadratic slot when necessary.
        // This decision uses only the immutable public template.
        const auto& terms = circuit.terms(expression);
        if (terms.size() == 1 && terms.front().coefficient_index == coefficient_one) {
            return Operand{master_for(terms.front().wire), false};
        }
        value = 0;
        for (const auto& term : terms) {
            if (term.coefficient_index == coefficient_one) {
                Field::addmod(value, value, *master_for(term.wire)->value_ptr());
            } else if (term.coefficient_index == coefficient_minus_one) {
                Field::submod(value, value, *master_for(term.wire)->value_ptr());
            } else {
                Field::mulmod(product, circuit.coefficients[term.coefficient_index],
                              *master_for(term.wire)->value_ptr());
                Field::addmod(value, value, product);
            }
        }
        auto* output = manager.acquire_witness(value);
        // Commitment/replay passes need the same values and allocation order,
        // but have no linear challenge. The value loop above has already
        // acquired every source wire, so omitting this pass cannot change
        // handle allocation or committed rows. Stage 2 and verification retain
        // every challenge-weighted equation.
        if constexpr (RandomPolicy::enable_linear_check) {
            random = 0;
            manager.generate_linear_random(random);
            manager.witness_add_random(*output, random);
            for (const auto& term : terms) {
                if (term.coefficient_index == coefficient_one) {
                    manager.witness_sub_random(*master_for(term.wire), random);
                } else if (term.coefficient_index == coefficient_minus_one) {
                    manager.witness_add_random(*master_for(term.wire), random);
                } else {
                    Field::mulmod(weighted_random, random, circuit.coefficients[term.coefficient_index]);
                    manager.witness_sub_random(*master_for(term.wire), weighted_random);
                }
            }
        }
        return Operand{output, true};
    };
    for (std::size_t row_index = 0; row_index < circuit.rows.size(); ++row_index) {
        const auto& row = circuit.rows[row_index];
        std::array<Operand, 3> operands;
        for (std::size_t side = 0; side < operands.size(); ++side) {
            operands[side] = materialize(row[side]);
        }
        manager.constrain_quadratic(operands[2].witness, operands[0].witness, operands[1].witness);
        for (const auto& operand : operands)
            if (operand.temporary) manager.commit_release_witness(operand.witness);
        // Early release keeps shared quadratic slots bounded by the live
        // circuit wires. Guest-owned inputs and wire0 remain live until below.
        for (const auto& expression : row) {
            for (const auto& term : circuit.terms(expression)) {
                if (term.wire >= 21 && circuit.last_use[term.wire] == row_index && master[term.wire]) {
                    manager.commit_release_witness(master[term.wire]);
                    master[term.wire] = nullptr;
                }
            }
        }
    }

    // The guest owns handles1..20 and releases them after returning. Release
    // only newly allocated wire0 and auxiliaries; no existing caller handle
    // may be freed, overwritten, or converted to a public constant here.
    manager.commit_release_witness(master[0]);
    for (std::size_t i = 21; i < master.size(); ++i) {
        if (master[i]) manager.commit_release_witness(master[i]);
    }
    std::cout << "ECDSA R1CS rows: " << circuit.rows.size() << '\n';
    std::cout << "ECDSA bound private limbs: 20\n";
}

} // namespace ligero::ecdsa_r1cs_host

namespace ligero::vm {

template <typename Context>
struct ecdsa_r1cs_module : host_module {
    static constexpr auto module_name = "ecdsa_r1cs";
    explicit ecdsa_r1cs_module(Context* context) : context_(context) {}

    exec_result call_host(address_t, std::string_view name) override {
        if (name != "assert_secp256k1_v1") {
            throw wasm_trap("unknown ECDSA import");
        }
        const auto address = context_->stack_pop().as_u32();
        constexpr std::size_t input_bytes = 20 * sizeof(std::uint64_t);
        const auto memory_size = context_->memory_data().size();
        if (address > memory_size || input_bytes > memory_size - address) {
            throw wasm_trap("ECDSA handle array is outside guest memory");
        }
        std::array<zkp::lazy_witness*, 20> input;
        for (std::size_t i = 0; i < input.size(); ++i) {
            // Match bn254fr_module: guest handles are always eight bytes,
            // including when this host itself is compiled to wasm32.
            // This follows the existing SDK's live-handle ABI: the caller must
            // supply handles allocated by this context, not arbitrary pointers.
            const std::uint64_t handle = context_->template memory_load<std::uint64_t>(
                address + i * sizeof(std::uint64_t));
            if (handle == 0 || handle > std::numeric_limits<std::uintptr_t>::max()) {
                throw wasm_trap("invalid ECDSA handle");
            }
            input[i] = std::bit_cast<zkp::lazy_witness*>(static_cast<std::uintptr_t>(handle));
        }
        ligero::ecdsa_r1cs_host::append(*context_, input);
        return exec_ok();
    }
    void initialize() override {}
    void finalize() override {}

private:
    Context* context_;
};

} // namespace ligero::vm
