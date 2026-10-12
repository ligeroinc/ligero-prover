// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "circuit.hpp"

#include <chrono>
#include <iostream>
#include <optional>
#include <stdexcept>

using namespace ecdsa_r1cs;

int main(int argc, char** argv) {
    try {
        std::string name = "secp256k1";
        std::optional<std::filesystem::path> out;
        std::optional<Big> z, r, s, x, y;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--help") {
                std::cout << "Usage: ecdsa_r1cs [--curve secp256k1|p256] [--out PREFIX]\n"
                    "  [--digest HEX --r HEX --s HEX --qx HEX --qy HEX]\n"
                    "With no signature arguments, compile a deterministic test vector.\n"
                    "All five signature arguments are required together. No message hashing.\n"
                    "Exports standard BN254 .r1cs/.wtns; all 20 input limbs are public.\n";
                return 0;
            }
            if (i + 1 == argc) throw std::invalid_argument("missing option value");
            const std::string value = argv[++i];
            if (arg == "--curve") name = value;
            else if (arg == "--out") out = value;
            else if (arg == "--digest") z = Big(value, 16);
            else if (arg == "--r") r = Big(value, 16);
            else if (arg == "--s") s = Big(value, 16);
            else if (arg == "--qx") x = Big(value, 16);
            else if (arg == "--qy") y = Big(value, 16);
            else throw std::invalid_argument("unknown option: " + arg);
        }
        const Curve curve = curve_by_name(name);
        const unsigned supplied = z.has_value() + r.has_value() + s.has_value() + x.has_value() + y.has_value();
        if (supplied != 0 && supplied != 5) throw std::invalid_argument("supply all five signature values");
        if (!supplied) {
            z = Big("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
            const Big secret = 7, nonce = 11;
            NativePoint q = native_mul(curve, secret, {curve.gx, curve.gy, false});
            x = q.x; y = q.y;
            auto sig = native_sign(curve, *z, secret, nonce);
            r = sig.first; s = sig.second;
        }
        const auto start = std::chrono::steady_clock::now();
        Builder builder(out);
        verify_ecdsa(builder, curve, *z, *r, *s, {*x, *y, false});
        builder.finish();
        const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        std::cout << "curve=" << curve.name << "\nfield=BN254 scalar\n"
                  << "constraints=" << builder.constraints() << "\nvariables=" << builder.variables()
                  << "\npublic_inputs=" << builder.public_inputs() << "\nshape_sha256=" << builder.shape_hash()
                  << "\nseconds=" << seconds << '\n';
        for (const auto& [stage, count] : builder.stage_counts()) std::cout << stage << '=' << count << '\n';
        if (out) std::cout << "r1cs=" << out->string() << ".r1cs\nwitness=" << out->string() << ".wtns\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
