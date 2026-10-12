// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Exercise the complete ECDSA bridge with the native witness manager.
// This test uses CPU callbacks and does not initialize a GPU.
#include <runtime.hpp>
#include <wgpu.hpp>
#include <zkp/finite_field_gmp.hpp>

#include <host_modules/ecdsa_r1cs.hpp>

#include <iostream>
#include <iomanip>
#include <stdexcept>
#include <unordered_set>

namespace {
using Field = ligero::vm::zkp::bn254_gmp;
using Role = ligero::vm::zkp::context_role;
using Witness = ligero::vm::zkp::lazy_witness;

struct TestPolicy {
    static constexpr bool pad_encoding_random = false;
    static constexpr bool enable_linear_check = true;
    static constexpr bool enable_code_check = false;
    static constexpr bool enable_quadratic_check = false;
};

struct CommitmentPolicy : TestPolicy {
    static constexpr bool enable_linear_check = false;
};

template <typename Policy>
struct TestBackend {
    ligero::vm::zkp::witness_manager<Field, Policy> manager_{1024, 1024};
    auto& manager() { return manager_; }
};

template <Role ContextRole, typename Policy = TestPolicy>
struct TestContext {
    using field_type = Field;
    static constexpr Role role = ContextRole;

    TestBackend<Policy> backend_;
    mpz_class linear_sum = 0;
    bool quadratic_valid = true;
    std::size_t quadratic_callbacks = 0;
    std::size_t violated_quadratic_equations = 0;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> schedule_hash{
        EVP_MD_CTX_new(), EVP_MD_CTX_free};
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> value_hash{
        EVP_MD_CTX_new(), EVP_MD_CTX_free};
    bool capture_values;

    explicit TestContext(bool capture = false) : capture_values(capture) {
        if (!schedule_hash || EVP_DigestInit_ex(schedule_hash.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("schedule hash initialization failed");
        if (!value_hash || EVP_DigestInit_ex(value_hash.get(), EVP_sha256(), nullptr) != 1)
            throw std::runtime_error("value hash initialization failed");
        unsigned char key[32] = {}, iv[16] = {};
        key[0] = 42;
        auto& manager = backend_.manager();
        manager.linear_random_engine().init(key, iv);
        manager.register_linear_callback([this](auto row) {
            record_schedule(0, row);
            if (capture_values) record_value_schedule(0, row);
            if constexpr (Policy::enable_linear_check) {
                for (std::size_t i = 0; i < row.first.size(); ++i) {
                    accumulate(row.first[i], row.second[i]);
                }
            }
        });
        manager.register_quadratic_callback([this](auto a, auto b, auto c) {
            record_schedule(1, a, b, c);
            if (capture_values) record_value_schedule(1, a, b, c);
            for (std::size_t i = 0; i < a.first.size(); ++i) {
                if constexpr (Policy::enable_linear_check) {
                    accumulate(a.first[i], a.second[i]);
                    accumulate(b.first[i], b.second[i]);
                    accumulate(c.first[i], c.second[i]);
                }
                mpz_class product;
                Field::mulmod(product, a.first[i], b.first[i]);
                const bool satisfied = product == c.first[i];
                quadratic_valid &= satisfied;
                violated_quadratic_equations += !satisfied;
            }
            ++quadratic_callbacks;
        });
        manager.register_mask_callback([](auto&, auto&, auto&) {});
    }

    auto& backend() { return backend_; }

    // Include every coefficient and its position, rather than only the number
    // of callbacks. The verifier must replay the exact packing and randomness
    // schedule even though its private values are zero.
    template <typename... Rows>
    void record_schedule(unsigned char kind, const Rows&... rows) {
        std::vector<unsigned char> encoded(1 + (rows.second.size() + ...) * 32);
        encoded[0] = kind;
        std::size_t offset = 1;
        const auto append_row = [&](const auto& row) {
            for (const auto& coefficient : row.second) {
                if (coefficient < 0 || mpz_sizeinbase(coefficient.get_mpz_t(), 2) > 256)
                    throw std::runtime_error("noncanonical schedule coefficient");
                std::size_t count = 0;
                mpz_export(encoded.data() + offset, &count, -1, 1, 0, 0,
                           coefficient.get_mpz_t());
                offset += 32;
            }
        };
        (append_row(rows), ...);
        if (EVP_DigestUpdate(schedule_hash.get(), encoded.data(), encoded.size()) != 1)
            throw std::runtime_error("schedule hash update failed");
    }

    // Hash every committed field value, row kind and callback boundary. The
    // commitment/replay policies must pack the exact same witness as the
    // challenge-bearing pass, despite skipping inactive coefficient work.
    template <typename... Rows>
    void record_value_schedule(unsigned char kind, const Rows&... rows) {
        std::vector<unsigned char> encoded(1 + (rows.first.size() + ...) * 32);
        encoded[0] = kind;
        std::size_t offset = 1;
        const auto append_row = [&](const auto& row) {
            for (const auto& value : row.first) {
                if (value < 0 || mpz_sizeinbase(value.get_mpz_t(), 2) > 256)
                    throw std::runtime_error("noncanonical committed value");
                std::size_t count = 0;
                mpz_export(encoded.data() + offset, &count, -1, 1, 0, 0,
                           value.get_mpz_t());
                offset += 32;
            }
        };
        (append_row(rows), ...);
        if (EVP_DigestUpdate(value_hash.get(), encoded.data(), encoded.size()) != 1)
            throw std::runtime_error("value hash update failed");
    }

    static std::array<unsigned char, 32> digest(const EVP_MD_CTX* hash) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> copy(
            EVP_MD_CTX_new(), EVP_MD_CTX_free);
        std::array<unsigned char, 32> result{};
        unsigned size = 0;
        if (!copy || EVP_MD_CTX_copy_ex(copy.get(), hash) != 1 ||
            EVP_DigestFinal_ex(copy.get(), result.data(), &size) != 1 || size != result.size())
            throw std::runtime_error("schedule hash finalization failed");
        return result;
    }

    std::array<unsigned char, 32> schedule_digest() const {
        return digest(schedule_hash.get());
    }

    std::array<unsigned char, 32> value_digest() const {
        return digest(value_hash.get());
    }

    void accumulate(const mpz_class& value, const mpz_class& random) {
        mpz_class product;
        Field::mulmod(product, value, random);
        Field::addmod(linear_sum, linear_sum, product);
    }

    bool finish() {
        backend_.manager().finalize();
        Field::addmod(linear_sum, linear_sum, backend_.manager().constsum());
        return linear_sum == 0 && quadratic_valid;
    }
};

ecdsa_r1cs::Big limb(const ecdsa_r1cs::Big& value, unsigned index) {
    using ecdsa_r1cs::Big;
    return (value >> (64 * index)) & ((Big(1) << 64) - 1);
}

template <Role ContextRole>
std::array<Witness*, 20> checked_inputs(
    TestContext<ContextRole>& context,
    const std::array<ecdsa_r1cs::Big, 5>& components,
    const std::array<bool, 5>& is_public,
    const std::array<ecdsa_r1cs::Big, 5>* bound_public_values = nullptr) {
    std::array<Witness*, 20> inputs;
    auto& manager = context.backend().manager();
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            const auto slot = 4 * component + index;
            auto value = limb(components[component], index);
            if constexpr (ContextRole == Role::verifier) {
                if (!is_public[component]) value = 0;
            }
            if (is_public[component]) {
                // Match bn254fr_set_bytes_checked's public path: allocate an
                // instance, import its value, promote, then bind the constant.
                inputs[slot] = manager.acquire_instance();
                *inputs[slot]->value_ptr() = value;
                inputs[slot]->set_witness_status(true);
                const auto& binding = bound_public_values ? *bound_public_values : components;
                manager.constrain_constant(*inputs[slot], limb(binding[component], index));
            } else {
                inputs[slot] = manager.acquire_witness(value);
            }
        }
    }
    return inputs;
}

template <Role ContextRole>
void release_inputs(TestContext<ContextRole>& context,
                    const std::array<Witness*, 20>& inputs) {
    for (std::size_t i = inputs.size(); i != 0; --i)
        context.backend().manager().commit_release_witness(inputs[i - 1]);
}

void check_public_mode(const std::array<ecdsa_r1cs::Big, 5>& components,
                       const std::array<bool, 5>& is_public, const char* label) {
    TestContext<Role::prover> prover;
    auto inputs = checked_inputs(prover, components, is_public);
    ligero::ecdsa_r1cs_host::append(prover, inputs);
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            if (*inputs[4 * component + index]->value_ptr() != limb(components[component], index))
                throw std::runtime_error("public/mixed input handle changed");
        }
    }
    release_inputs(prover, inputs);
    if (!prover.finish()) throw std::runtime_error("public/mixed composed equations failed");

    TestContext<Role::verifier> verifier;
    inputs = checked_inputs(verifier, components, is_public);
    ligero::ecdsa_r1cs_host::append(verifier, inputs);
    release_inputs(verifier, inputs);
    verifier.backend().manager().finalize();
    if (verifier.quadratic_callbacks != prover.quadratic_callbacks ||
        verifier.schedule_digest() != prover.schedule_digest())
        throw std::runtime_error("public/mixed verifier schedule changed");
    std::cout << "Validated " << label << " input bindings and verifier schedule\n";
}

void check_shared_inputs() {
    using namespace ecdsa_r1cs;
    const auto curve = curve_by_name("secp256k1");
    const Big digest = 1;
    const auto key = native_mul(curve, Big(13), {curve.gx, curve.gy, false});
    const auto signature = native_sign(curve, digest, Big(13), Big(19));
    const std::array<Big, 5> components{
        key.x, key.y, signature.first, signature.second, digest};

    const auto run = [&](auto& context, bool tamper) {
        auto inputs = checked_inputs(context, components, {false, false, false, false, true});
        auto& manager = context.backend().manager();
        // The three high digest limbs share a single zero handle. Both zero
        // and one already occupy a guest quadratic slot before the host call,
        // and each is reused in all three positions of that slot.
        manager.commit_release_witness(inputs[18]);
        manager.commit_release_witness(inputs[19]);
        inputs[18] = inputs[19] = inputs[17];
        manager.constrain_quadratic(inputs[16], inputs[16], inputs[16]);
        manager.constrain_quadratic(inputs[17], inputs[17], inputs[17]);
        ligero::ecdsa_r1cs_host::append(context, inputs);
        if (*inputs[16]->value_ptr() != 1 || *inputs[17]->value_ptr() != 0)
            throw std::runtime_error("shared guest handle was changed or released");
        if (tamper) *inputs[17]->value_ptr() = 1;
        std::unordered_set<Witness*> released;
        for (std::size_t i = inputs.size(); i != 0; --i)
            if (released.insert(inputs[i - 1]).second)
                manager.commit_release_witness(inputs[i - 1]);
        return context.finish();
    };

    TestContext<Role::prover> prover;
    if (!run(prover, false)) throw std::runtime_error("shared zero/one input equations failed");
    TestContext<Role::verifier> verifier;
    run(verifier, false);
    if (verifier.schedule_digest() != prover.schedule_digest())
        throw std::runtime_error("shared input verifier schedule changed");
    TestContext<Role::prover> tampered;
    if (run(tampered, true) || tampered.linear_sum == 0)
        throw std::runtime_error("changed shared input lost its linear binding");
    if (tampered.schedule_digest() != prover.schedule_digest())
        throw std::runtime_error("private input value changed composition schedule");
    std::cout << "Validated shared zero/one inputs, existing quadratic slots, exact verifier schedule, "
                 "and post-composition tampering\n";
}

void check_decoded_template() {
    using namespace ligero::ecdsa_r1cs_host;
    const auto& circuit = fixed_circuit();
    std::vector<unsigned char> rows;
    rows.reserve(107102844);
    std::vector<std::uint32_t> last_use(expected_variables, UINT32_MAX);
    const auto append_u32 = [&](std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) rows.push_back((value >> (8 * i)) & 255);
    };
    for (std::size_t i = 0; i < circuit.rows.size(); ++i) {
        for (const auto& expression : circuit.rows[i]) {
            const auto terms = circuit.terms(expression);
            append_u32(static_cast<std::uint32_t>(terms.size()));
            for (const auto& term : terms) {
                append_u32(term.wire);
                std::array<unsigned char, 32> bytes{};
                std::size_t size = 0;
                mpz_export(bytes.data(), &size, -1, 1, 0, 0,
                           circuit.coefficients[term.coefficient_index].get_mpz_t());
                rows.insert(rows.end(), bytes.begin(), bytes.end());
                last_use[term.wire] = static_cast<std::uint32_t>(i);
            }
        }
    }
    template_detail::validate_shape(rows);
    if (last_use != circuit.last_use)
        throw std::runtime_error("template last-use metadata differs from decoded rows");
    std::cout << "Validated compact template reconstructs the exact pinned rows and wire lifetimes\n";
}

void run_test() {
    check_decoded_template();
    using namespace ecdsa_r1cs;
    const auto curve = curve_by_name("secp256k1");
    const Big digest("abcdef0123456789abcdef0123456789", 16);
    // Different from the fixed template's secret=7, nonce=11 fixture.
    const auto key = native_mul(curve, Big(13), {curve.gx, curve.gy, false});
    const auto signature = native_sign(curve, digest, Big(13), Big(19));
    const std::array<Big, 5> components{
        key.x, key.y, signature.first, signature.second, digest
    };

    TestContext<Role::prover> prover(true);
    std::array<Witness*, 20> inputs;
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            inputs[4 * component + index] = prover.backend().manager().acquire_witness(
                limb(components[component], index));
        }
    }
    ligero::ecdsa_r1cs_host::append(prover, inputs);

    // The host only borrows these handles. They must remain live and immutable
    // until the surrounding guest program releases them.
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            if (*inputs[4 * component + index]->value_ptr() !=
                limb(components[component], index)) {
                throw std::runtime_error("input handle changed");
            }
        }
    }
    for (std::size_t i = inputs.size(); i != 0; --i) {
        prover.backend().manager().commit_release_witness(inputs[i - 1]);
    }
    if (!prover.finish()) {
        throw std::runtime_error("composed ECDSA constraints failed");
    }

    TestContext<Role::prover, CommitmentPolicy> commitment(true);
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            inputs[4 * component + index] = commitment.backend().manager().acquire_witness(
                limb(components[component], index));
        }
    }
    ligero::ecdsa_r1cs_host::append(commitment, inputs);
    for (std::size_t i = inputs.size(); i != 0; --i)
        commitment.backend().manager().commit_release_witness(inputs[i - 1]);
    if (!commitment.finish() || commitment.value_digest() != prover.value_digest())
        throw std::runtime_error("commitment/replay values differ from linear-check pass");
    std::cout << "Identical committed values with/without linear check: ";
    for (const auto byte : commitment.value_digest())
        std::cout << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
    std::cout << std::dec << '\n';

    // Verification reconstructs the schedule from the fixed circuit. It must
    // never request or attempt to generate an ECDSA witness from these zeros.
    TestContext<Role::verifier> verifier;
    for (auto& input : inputs) {
        input = verifier.backend().manager().acquire_witness(0u);
    }
    ligero::ecdsa_r1cs_host::append(verifier, inputs);
    for (std::size_t i = inputs.size(); i != 0; --i) {
        verifier.backend().manager().commit_release_witness(inputs[i - 1]);
    }
    verifier.backend().manager().finalize();
    if (verifier.quadratic_callbacks != prover.quadratic_callbacks ||
        verifier.schedule_digest() != prover.schedule_digest()) {
        throw std::runtime_error("verifier schedule differs");
    }

    // A failed generation must not replace the valid cached key or values.
    std::array<Big, 20> cached_input;
    for (std::size_t component = 0; component < components.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            cached_input[4 * component + index] = limb(components[component], index);
        }
    }
    const auto cached_values = ligero::ecdsa_r1cs_host::private_witness(cached_input);
    auto zero_s = cached_input;
    for (std::size_t i = 12; i < 16; ++i) zero_s[i] = 0;
    bool failed_generation = false;
    try {
        ligero::ecdsa_r1cs_host::private_witness(zero_s);
    } catch (const std::exception&) {
        failed_generation = true;
    }
    if (!failed_generation ||
        ligero::ecdsa_r1cs_host::private_witness(cached_input) != cached_values) {
        throw std::runtime_error("failed witness generation corrupted the cache");
    }

    // The fast pass deliberately skips local satisfaction checks. Changing
    // the message must therefore be rejected by the actual composed rows,
    // even when witness generation completes successfully and keeps its shape.
    auto tampered = components;
    tampered[4] += 1;
    if (native_verify(curve, tampered[4], tampered[2], tampered[3], key)) {
        throw std::runtime_error("negative-test signature unexpectedly valid");
    }
    TestContext<Role::prover> invalid;
    for (std::size_t component = 0; component < tampered.size(); ++component) {
        for (unsigned index = 0; index < 4; ++index) {
            inputs[4 * component + index] = invalid.backend().manager().acquire_witness(
                limb(tampered[component], index));
        }
    }
    // Do not accept a witness-generator exception as this regression's pass:
    // it specifically tests the fixed template's downstream enforcement.
    ligero::ecdsa_r1cs_host::append(invalid, inputs);
    for (std::size_t i = inputs.size(); i != 0; --i) {
        invalid.backend().manager().commit_release_witness(inputs[i - 1]);
    }
    if (invalid.finish() || invalid.violated_quadratic_equations == 0 ||
        invalid.quadratic_callbacks != prover.quadratic_callbacks) {
        throw std::runtime_error("tampered message was not rejected by complete composed equations");
    }
    std::cout << "Tampered digest rejected by " << invalid.violated_quadratic_equations
              << " composed quadratic equations after complete fast witness generation\n";

    check_public_mode(components, {true, true, true, true, true}, "all-public");
    check_public_mode(components, {true, true, false, false, true},
                      "public-key/digest with private-signature");

    // A second valid signature satisfies every ECDSA row, but cannot replace a
    // previously bound public digest. This isolates constant binding from
    // ECDSA validity: the composed linear check must still reject the change.
    auto changed = components;
    changed[4] += 1;
    const auto changed_signature = native_sign(curve, changed[4], Big(13), Big(19));
    changed[2] = changed_signature.first;
    changed[3] = changed_signature.second;
    TestContext<Role::prover> changed_public;
    auto changed_inputs = checked_inputs(changed_public, changed,
        {true, true, false, false, true}, &components);
    ligero::ecdsa_r1cs_host::append(changed_public, changed_inputs);
    release_inputs(changed_public, changed_inputs);
    if (changed_public.finish() || !changed_public.quadratic_valid ||
        changed_public.linear_sum == 0) {
        throw std::runtime_error("public digest binding was lost during ECDSA composition");
    }
    std::cout << "Changed public digest rejected by linear binding while all ECDSA rows hold\n";

    check_shared_inputs();

    std::cout << "PASS: pinned exact row template; alternate private valid witness; "
                 "shared handles preserved; all composed equations satisfied; "
                 "zero-private verifier replay; failed generation preserves cache; "
                 "tampered digest rejected by fixed constraints; public/mixed bindings preserved\n";
}
} // namespace

int main() {
    try {
        run_test();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
