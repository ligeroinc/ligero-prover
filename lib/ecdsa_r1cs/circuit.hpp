// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include "native.hpp"

#include <array>
#include <initializer_list>
#include <vector>

namespace ecdsa_r1cs {

// Four base-2^64 limbs. Coordinates and scalar residues are canonical;
// slopes may use bounded noncanonical representatives. Signed GLV
// magnitudes use signed limbs and are only passed to modular relations.
struct Number {
    std::array<LC, 4> limbs;
    Big value;
    std::vector<LC> bits;
};

struct Product { long coefficient; const Number* a; const Number* b; };
struct Linear { long coefficient; const Number* a; };

class ForeignField {
public:
    ForeignField(Builder& builder, Big modulus);
    Number constant(const Big& value) const;
    Number from_inputs(const std::array<LC, 4>& inputs, const Big& value);
    Number witness(const Big& value);
    Number bounded(const Big& value, unsigned bits);
    // Selectors must already be constrained Boolean values. Number operands
    // must come from this field's constructors or other bounded gadget outputs.
    Number signed_number(const Number& magnitude, const LC& negative);
    Number select(const LC& condition, const Number& yes, const Number& no);
    Number negate(const Number& a);
    Number multiply(const Number& a, const Number& b);
    Number divide(const Number& a, const Number& b);
    LC equal(const Number& a, const Number& b);
    void nonzero(const Number& a);
    void canonical(const Number& a, const Big& upper_exclusive);

    // Enforce enable * (sum c_i*a_i*b_i + sum d_i*a_i) == 0 mod m.
    // Bounded integer limbs and carries make this an integer identity,
    // rather than one potentially wrapping equation in BN254. Enable must
    // already be Boolean; operands require limbs of magnitude below 2^64.
    void relation(std::initializer_list<Product> products,
                  std::initializer_list<Linear> linear, const LC& enable = LC(1));

    Builder& builder;
    const Big modulus;
};

struct Point {
    Number x, y;
    LC infinity;
    NativePoint value;
};

class CurveCircuit {
public:
    CurveCircuit(Builder& builder, const Curve& curve);
    Point constant(const NativePoint& point);
    Point point_witness(const NativePoint& point);
    void on_curve(const Point& point);
    Point select(const LC& condition, const Point& yes, const Point& no);
    Point negate(const Point& point);
    Point add(const Point& a, const Point& b);
    Point twice(const Point& a);
    // Input-independent public generator tables, cached per thread and exact
    // curve parameters. This allocates no witnesses or constraints; callers
    // can run it during public setup before measuring witness computation.
    void prepare_fixed_base_table();
    Point fixed_mul(const Number& scalar);
    Point joint_mul(const Number& a, const Point& p, const Number& b, const Point& q);
    Point variable_mul(const Number& scalar, const Point& point, ForeignField& scalars);

    Builder& builder;
    const Curve curve;
    ForeignField field;
};

// Assert-valid relation, corresponding to assert(verify_signature(...)).
// Public inputs: Q.x, Q.y, r, s, digest; each four little-endian 64-bit limbs.
// No hashing, custom gates, lookup arguments, or transcript challenges.
struct PreparedEcdsa {
    Point q;
    Number r, u1, u2;
};
// Shared prefix/finalization also permit independent scalar-multiplication
// witness jobs. The checked circuit retains exactly the same wire order.
PreparedEcdsa prepare_ecdsa(Builder& builder, const Curve& curve, const Big& digest,
                           const Big& r, const Big& s, const NativePoint& public_key);
void finish_ecdsa(Builder& builder, const Curve& curve, const Point& p1,
                  const Point& p2, const Number& r);
void verify_ecdsa(Builder& builder, const Curve& curve, const Big& digest,
                  const Big& r, const Big& s, const NativePoint& public_key);

} // namespace ecdsa_r1cs
