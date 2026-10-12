// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "native.hpp"

#include <stdexcept>

namespace ecdsa_r1cs {
namespace {

Big hex(const char* value) { return Big(value, 16); }

NativePoint infinity() { return {Big(0), Big(0), true}; }

NativePoint canonical_point(const Curve& curve, const NativePoint& point)
{
    if (point.infinity) {
        return infinity();
    }
    return {mod(point.x, curve.p), mod(point.y, curve.p), false};
}

bool on_curve(const Curve& curve, const NativePoint& point)
{
    if (point.infinity || point.x < 0 || point.x >= curve.p || point.y < 0 ||
        point.y >= curve.p) {
        return false;
    }
    return mod(point.y * point.y - point.x * point.x * point.x -
                   curve.a * point.x - curve.b,
               curve.p) == 0;
}

Big centered(const Big& value, const Big& modulus)
{
    Big result = mod(value, modulus);
    if (result > modulus / 2) {
        result -= modulus;
    }
    return result;
}

Big magnitude(const Big& value) { return value < 0 ? Big(-value) : value; }

} // namespace

Curve curve_by_name(const std::string& name)
{
    // SEC 2 / NIST constants, matching the pinned Barretenberg curve headers:
    // https://github.com/AztecProtocol/aztec-packages/blob/
    // bb15fcbbe969f11a892272715fe59f0976b086ca/barretenberg/cpp/src/
    // barretenberg/ecc/curves/secp256k1/secp256k1.hpp
    // and ecc/curves/secp256r1/secp256r1.hpp at the same commit.
    if (name == "secp256k1") {
        return {
            "secp256k1",
            hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
            hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
            Big(0),
            Big(7),
            hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            hex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
        };
    }
    if (name == "p256" || name == "secp256r1") {
        return {
            "p256",
            hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            hex("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
            hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        };
    }
    throw std::invalid_argument("unsupported ECDSA curve: " + name);
}

Big mod(const Big& value, const Big& modulus)
{
    if (modulus <= 0) {
        throw std::invalid_argument("modulus must be positive");
    }
    Big result;
    mpz_mod(result.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
    return result;
}

Big inverse(const Big& value, const Big& modulus)
{
    if (modulus <= 1) {
        throw std::invalid_argument("inverse modulus must be greater than one");
    }
    Big result;
    if (mpz_invert(result.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t()) == 0) {
        throw std::domain_error("non-invertible field element");
    }
    return result;
}

NativePoint native_add(const Curve& curve, const NativePoint& lhs,
                       const NativePoint& rhs)
{
    if (lhs.infinity) {
        return canonical_point(curve, rhs);
    }
    if (rhs.infinity) {
        return canonical_point(curve, lhs);
    }
    const NativePoint p = canonical_point(curve, lhs);
    const NativePoint q = canonical_point(curve, rhs);
    Big slope;
    if (p.x == q.x) {
        if (mod(p.y + q.y, curve.p) == 0) {
            return infinity();
        }
        if (p.y != q.y) {
            throw std::domain_error("inconsistent points with equal x coordinates");
        }
        slope = mod((3 * p.x * p.x + curve.a) * inverse(2 * p.y, curve.p),
                    curve.p);
    } else {
        slope = mod((q.y - p.y) * inverse(q.x - p.x, curve.p), curve.p);
    }
    const Big x = mod(slope * slope - p.x - q.x, curve.p);
    const Big y = mod(slope * (p.x - x) - p.y, curve.p);
    return {x, y, false};
}

NativePoint native_mul(const Curve& curve, const Big& scalar,
                       const NativePoint& point)
{
    Big k = scalar;
    NativePoint base = canonical_point(curve, point);
    if (k < 0) {
        k = -k;
        base.y = mod(-base.y, curve.p);
    }
    NativePoint result = infinity();
    while (k != 0) {
        if (mpz_tstbit(k.get_mpz_t(), 0) != 0) {
            result = native_add(curve, result, base);
        }
        k >>= 1;
        if (k != 0) {
            base = native_add(curve, base, base);
        }
    }
    return result;
}

bool native_verify(const Curve& curve, const Big& z, const Big& r, const Big& s,
                   const NativePoint& public_key, bool low_s)
{
    if (r <= 0 || r >= curve.n || s <= 0 || s >= curve.n ||
        (low_s && s > curve.n / 2) || !on_curve(curve, public_key)) {
        return false;
    }
    const Big s_inv = inverse(s, curve.n);
    const Big u1 = mod(z * s_inv, curve.n);
    const Big u2 = mod(r * s_inv, curve.n);
    const NativePoint generator{curve.gx, curve.gy, false};
    const NativePoint result = native_add(curve, native_mul(curve, u1, generator),
                                         native_mul(curve, u2, public_key));
    return !result.infinity && mod(result.x, curve.n) == r;
}

std::pair<Big, Big> native_sign(const Curve& curve, const Big& z,
                                const Big& secret, const Big& nonce)
{
    if (secret <= 0 || secret >= curve.n || nonce <= 0 || nonce >= curve.n) {
        throw std::invalid_argument("secret and nonce must be in [1,n)");
    }
    const NativePoint generator{curve.gx, curve.gy, false};
    const NativePoint point = native_mul(curve, nonce, generator);
    if (point.infinity) {
        throw std::domain_error("nonce produced the point at infinity");
    }
    const Big r = mod(point.x, curve.n);
    Big s = mod(inverse(nonce, curve.n) * (z + r * secret), curve.n);
    if (r == 0 || s == 0) {
        throw std::domain_error("nonce produced a zero ECDSA component");
    }
    if (s > curve.n / 2) {
        s = curve.n - s;
    }
    return {r, s};
}

std::pair<Big, Big> glv_split(const Big& scalar)
{
    // Exact nearest-lattice decomposition. The basis vectors (a1,b1) and
    // (a2,b2) satisfy ai + lambda*bi == 0 mod n and det(basis) == n.
    // Before rounding, (b2*k/n, -b1*k/n) are the coordinates of (k,0).
    // Rounding each coefficient has error at most 1/2, hence
    // |first| <= (a1+a2)/2 < 2^128 and
    // |second| <= (|b1|+b2)/2 < 2^128.
    // The returned sign convention is k = first - lambda*second mod n.
    static const Big n = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    static const Big a1 = hex("3086d221a7d46bcde86c90e49284eb15");
    static const Big b1 = -hex("e4437ed6010e88286f547fa90abfe4c3");
    static const Big a2 = hex("114ca50f7a8e2f3f657c1108d9d44cfd8");
    static const Big b2 = a1;
    const Big k = mod(scalar, n);
    const Big c1 = (b2 * k + n / 2) / n;
    const Big c2 = (-b1 * k + n / 2) / n;
    const Big first = k - c1 * a1 - c2 * a2;
    const Big second = c1 * b1 + c2 * b2;
    const Big bound = Big(1) << 128;
    if (magnitude(first) >= bound || magnitude(second) >= bound) {
        throw std::logic_error("GLV decomposition exceeded 128 bits");
    }
    return {first, second};
}

std::pair<Big, Big> fake_glv_split(const Curve& curve, const Big& scalar)
{
    // Extended Euclid witness algorithm. Its trace is not circuit logic: the
    // circuit must constrain the short signed output and beta*k=alpha mod n.
    // https://github.com/AztecProtocol/aztec-packages/blob/bb15fcbbe969f11a892272715fe59f0976b086ca/barretenberg/cpp/src/barretenberg/stdlib/primitives/biggroup/biggroup_secp256r1.hpp#L62-L101
    Big u_prev = curve.n;
    Big u = mod(scalar, curve.n);
    Big v_prev = 0;
    Big v = 1;
    const Big bound = Big(1) << 128;
    while (u >= bound && u != 0) {
        const Big q = u_prev / u;
        const Big u_next = u_prev - q * u;
        const Big v_next = mod(v_prev - q * v, curve.n);
        u_prev = u;
        u = u_next;
        v_prev = v;
        v = v_next;
    }
    const Big beta = centered(v, curve.n);
    if (u < 0 || u >= bound || beta == 0 || magnitude(beta) >= bound) {
        throw std::logic_error("fake-GLV decomposition exceeded 128 bits");
    }
    return {u, beta};
}

} // namespace ecdsa_r1cs
