// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include <ecdsa_r1cs/circuit.hpp>
#include <ecdsa_r1cs/template.hpp>

#include <chrono>
#include <iostream>

namespace ligero::ecdsa_r1cs_host {
const FixedCircuit& fixed_circuit() {
    static const FixedCircuit result = [] {
        const auto started = std::chrono::steady_clock::now();
        auto circuit = load_fixed_circuit(template_path());
        std::cout << "ECDSA template-load seconds: "
                  << std::chrono::duration<double>(
                      std::chrono::steady_clock::now() - started).count() << '\n';
        return circuit;
    }();
    return result;
}

} // namespace ligero::ecdsa_r1cs_host

#ifdef __EMSCRIPTEN__
#include <emscripten.h>

EM_ASYNC_JS(int, ligero_ecdsa_parallel_witness, (const char* input), {
    try {
        await globalThis.ligeroGenerateEcdsaWitness(UTF8ToString(input));
        return 0;
    } catch (error) {
        console.error('ECDSA witness workers failed: ' + error.message);
        return 1;
    }
});

// Public, input-independent preparation runs before proof stage timers.
extern "C" EMSCRIPTEN_KEEPALIVE int ligero_ecdsa_prepare(int witness_mode) {
    try {
        if (witness_mode < 0 || witness_mode > 2) {
            throw std::invalid_argument("ECDSA witness mode must be 0, 1, or 2");
        }
        // Set libc's environment directly: Module.ENV can already have been
        // materialized by getenv() during runtime initialization.
        if (setenv("LIGETRON_ECDSA_PARALLEL", witness_mode == 2 ? "1" : "0", 1) != 0) {
            throw std::runtime_error("could not configure ECDSA witness mode");
        }
        ligero::ecdsa_r1cs_host::fixed_circuit();
        if (witness_mode == 1) {
            ecdsa_r1cs::Builder builder(ecdsa_r1cs::Builder::Mode::WitnessOnly);
            ecdsa_r1cs::CurveCircuit ec(builder, ecdsa_r1cs::curve_by_name("secp256k1"));
            ec.prepare_fixed_base_table();
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ECDSA template initialization failed: " << error.what() << '\n';
        return 1;
    }
}
#endif
