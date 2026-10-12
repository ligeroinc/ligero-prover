// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include "r1cs.hpp"

#include <string>
#include <utility>

namespace ecdsa_r1cs {

// Native arithmetic is used only to produce/check witnesses. These functions
// emit no R1CS constraints and must never substitute for circuit checks.
struct Curve {
    std::string name;
    Big p;
    Big n;
    Big a;
    Big b;
    Big gx;
    Big gy;
};

struct NativePoint {
    Big x;
    Big y;
    bool infinity = false;
};

Curve curve_by_name(const std::string& name);
Big mod(const Big& value, const Big& modulus);
Big inverse(const Big& value, const Big& modulus);

NativePoint native_add(const Curve& curve, const NativePoint& lhs,
                       const NativePoint& rhs);
NativePoint native_mul(const Curve& curve, const Big& scalar,
                       const NativePoint& point);
bool native_verify(const Curve& curve, const Big& z, const Big& r, const Big& s,
                   const NativePoint& public_key, bool low_s = true);

// Deterministic for the supplied secret and nonce; throws if either scalar is
// out of range or if the chosen nonce produces a zero signature component.
std::pair<Big, Big> native_sign(const Curve& curve, const Big& z,
                                const Big& secret, const Big& nonce);

// Signed a,b with |a|,|b| < 2^128 and scalar = a - lambda*b (mod k1.n).
std::pair<Big, Big> glv_split(const Big& scalar);

// Returns alpha,beta with 0 <= alpha < 2^128, 0 < |beta| < 2^128,
// and beta*scalar = alpha (mod curve.n). Zero maps to (0,1); the circuit
// must handle its point at infinity with complete group operations.
std::pair<Big, Big> fake_glv_split(const Curve& curve, const Big& scalar);

} // namespace ecdsa_r1cs
