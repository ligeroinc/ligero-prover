// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// OpenSSL's low-level EC API lets this test supply an explicit nonce and
// independently produce deterministic ECDSA fixtures. It is test-only code.
#define OPENSSL_SUPPRESS_DEPRECATED

#include "circuit.hpp"
#include "native.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using namespace ecdsa_r1cs;
using Bn = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using BnContext = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using Group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using Key = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using Signature = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void require_openssl(int success, const char* operation)
{
    require(success == 1, std::string("OpenSSL failed: ") + operation);
}

Bn bn(const Big& value)
{
    BIGNUM* result = nullptr;
    require(BN_hex2bn(&result, value.get_str(16).c_str()) != 0, "BN_hex2bn failed");
    return Bn(result, BN_free);
}

Big integer(const BIGNUM* value)
{
    const int size = BN_num_bytes(value);
    std::vector<unsigned char> bytes(static_cast<size_t>(size));
    require(BN_bn2bin(value, bytes.data()) == size, "BN_bn2bin failed");
    Big result;
    mpz_import(result.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
    if (BN_is_negative(value)) {
        result = -result;
    }
    return result;
}

int curve_nid(const Curve& curve)
{
    return curve.name == "secp256k1" ? NID_secp256k1 : NID_X9_62_prime256v1;
}

std::array<unsigned char, 32> digest_bytes(const Big& z)
{
    require(z >= 0 && z < (Big(1) << 256), "digest does not fit 32 bytes");
    std::array<unsigned char, 32> bytes{};
    const Bn value = bn(z);
    require(BN_bn2binpad(value.get(), bytes.data(), bytes.size()) == 32,
            "BN_bn2binpad failed");
    return bytes;
}

struct Fixture {
    Big z;
    Big r;
    Big s;
    NativePoint public_key;
};

Fixture openssl_sign(const Curve& curve, const Big& z, const Big& secret,
                     const Big& nonce)
{
    BnContext context(BN_CTX_new(), BN_CTX_free);
    Group group(EC_GROUP_new_by_curve_name(curve_nid(curve)), EC_GROUP_free);
    Key key(EC_KEY_new_by_curve_name(curve_nid(curve)), EC_KEY_free);
    require(context && group && key, "OpenSSL allocation failed");
    Point public_key(EC_POINT_new(group.get()), EC_POINT_free);
    Point nonce_point(EC_POINT_new(group.get()), EC_POINT_free);
    require(public_key && nonce_point, "EC_POINT_new failed");

    const Bn d = bn(secret);
    const Bn k = bn(nonce);
    const Bn order = bn(curve.n);
    require_openssl(EC_POINT_mul(group.get(), public_key.get(), d.get(), nullptr,
                                 nullptr, context.get()), "derive public key");
    require_openssl(EC_KEY_set_private_key(key.get(), d.get()), "set private key");
    require_openssl(EC_KEY_set_public_key(key.get(), public_key.get()), "set public key");
    require_openssl(EC_KEY_check_key(key.get()), "check generated key");
    require_openssl(EC_POINT_mul(group.get(), nonce_point.get(), k.get(), nullptr,
                                 nullptr, context.get()), "derive nonce point");

    Bn x(BN_new(), BN_free);
    Bn y(BN_new(), BN_free);
    Bn rp(BN_new(), BN_free);
    require(x && y && rp, "BN_new failed");
    require_openssl(EC_POINT_get_affine_coordinates(group.get(), nonce_point.get(),
                                                     x.get(), nullptr, context.get()),
                    "get nonce x");
    require_openssl(BN_nnmod(rp.get(), x.get(), order.get(), context.get()), "reduce nonce x");
    Bn k_inverse(BN_mod_inverse(nullptr, k.get(), order.get(), context.get()), BN_free);
    require(static_cast<bool>(k_inverse), "invert nonce failed");
    const auto digest = digest_bytes(z);
    Signature signature(ECDSA_do_sign_ex(digest.data(), digest.size(), k_inverse.get(),
                                         rp.get(), key.get()), ECDSA_SIG_free);
    require(static_cast<bool>(signature), "OpenSSL ECDSA signing failed");
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(signature.get(), &r, &s);
    Big s_value = integer(s);
    if (s_value > curve.n / 2) {
        s_value = curve.n - s_value;
    }
    require_openssl(EC_POINT_get_affine_coordinates(group.get(), public_key.get(),
                                                     x.get(), y.get(), context.get()),
                    "get public key coordinates");
    return {z, integer(r), s_value, {integer(x.get()), integer(y.get()), false}};
}

bool openssl_verify(const Curve& curve, const Fixture& fixture)
{
    BnContext context(BN_CTX_new(), BN_CTX_free);
    Group group(EC_GROUP_new_by_curve_name(curve_nid(curve)), EC_GROUP_free);
    Key key(EC_KEY_new_by_curve_name(curve_nid(curve)), EC_KEY_free);
    require(context && group && key, "OpenSSL allocation failed");
    Point point(EC_POINT_new(group.get()), EC_POINT_free);
    require(static_cast<bool>(point), "EC_POINT_new failed");
    Bn x = bn(fixture.public_key.x);
    Bn y = bn(fixture.public_key.y);
    if (fixture.public_key.infinity ||
        EC_POINT_set_affine_coordinates(group.get(), point.get(), x.get(), y.get(),
                                        context.get()) != 1) {
        return false;
    }
    require_openssl(EC_KEY_set_public_key(key.get(), point.get()), "set verifier public key");
    Signature signature(ECDSA_SIG_new(), ECDSA_SIG_free);
    require(static_cast<bool>(signature), "ECDSA_SIG_new failed");
    Bn r = bn(fixture.r);
    Bn s = bn(fixture.s);
    require_openssl(ECDSA_SIG_set0(signature.get(), r.get(), s.get()), "set signature");
    r.release();
    s.release();
    const auto digest = digest_bytes(fixture.z);
    return ECDSA_do_verify(digest.data(), digest.size(), signature.get(), key.get()) == 1;
}

Fixture openssl_zero_digest_with_x_reduction(const Curve& curve)
{
    // Deliberately choose R.x >= n instead of searching for an astronomically
    // unlikely signing nonce. With z=0, s=1 and Q=r^-1*R, verification recovers
    // R and must compare R.x MOD n with r. All point work is done by OpenSSL.
    BnContext context(BN_CTX_new(), BN_CTX_free);
    Group group(EC_GROUP_new_by_curve_name(curve_nid(curve)), EC_GROUP_free);
    require(context && group, "OpenSSL allocation failed");
    Point r_point(EC_POINT_new(group.get()), EC_POINT_free);
    Point public_key(EC_POINT_new(group.get()), EC_POINT_free);
    require(r_point && public_key, "EC_POINT_new failed");
    const Bn order = bn(curve.n);
    for (unsigned candidate = 1; candidate <= 128; ++candidate) {
        const Big r(candidate);
        const Big target_x = curve.n + r;
        require(target_x < curve.p, "curve has no room for x-reduction test point");
        const Bn x_candidate = bn(target_x);
        if (EC_POINT_set_compressed_coordinates(group.get(), r_point.get(),
                                                 x_candidate.get(), 0, context.get()) != 1) {
            continue;
        }
        const Bn r_bn = bn(r);
        Bn r_inverse(BN_mod_inverse(nullptr, r_bn.get(), order.get(), context.get()), BN_free);
        require(static_cast<bool>(r_inverse), "test r inversion failed");
        require_openssl(EC_POINT_mul(group.get(), public_key.get(), nullptr,
                                     r_point.get(), r_inverse.get(), context.get()),
                        "derive x-reduction test public key");
        Bn x(BN_new(), BN_free), y(BN_new(), BN_free);
        require(x && y, "BN_new failed");
        require_openssl(EC_POINT_get_affine_coordinates(group.get(), public_key.get(),
                                                         x.get(), y.get(), context.get()),
                        "extract x-reduction test public key");
        Fixture fixture{Big(0), r, Big(1), {integer(x.get()), integer(y.get()), false}};
        require(openssl_verify(curve, fixture), "OpenSSL rejects constructed x-reduction fixture");
        return fixture;
    }
    throw std::runtime_error("could not find a point for x-reduction test");
}

bool same_point(const NativePoint& a, const NativePoint& b)
{
    return a.infinity == b.infinity && (a.infinity || (a.x == b.x && a.y == b.y));
}

template <class F> void rejects(F&& action, const std::string& label)
{
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("accepted invalid case: " + label);
}

void glv_lattice_bound_tests(const Curve& curve)
{
    if (curve.name != "secp256k1") return;
    const Big lambda("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16);
    const Big a1("3086d221a7d46bcde86c90e49284eb15", 16);
    const Big b1 = -Big("e4437ed6010e88286f547fa90abfe4c3", 16);
    const Big a2("114ca50f7a8e2f3f657c1108d9d44cfd8", 16);
    const Big b2 = a1;
    const Big bound = Big(1) << 128;
    require(a1*b2-a2*b1 == curve.n, "GLV lattice determinant");
    require(mod(a1+lambda*b1,curve.n) == 0 && mod(a2+lambda*b2,curve.n) == 0,
            "GLV basis belongs to kernel");
    require(a1+a2 < 2*bound && -b1+b2 < 2*bound, "GLV analytic 128-bit bound");
    std::vector<Big> cases{Big(0),Big(1),Big(2),Big(curve.n/2-1),Big(curve.n/2),
                           Big(curve.n/2+1),Big(curve.n-2),Big(curve.n-1),
                           Big(bound-1),bound,Big(bound+1),Big(1)<<255};
    // Include inputs immediately around exact nearest-rounding transitions.
    for (const Big coefficient : {b2, Big(-b1)}) {
        for (const Big j : {Big(0),Big(1),Big(coefficient/2),Big(coefficient-1)}) {
            const Big transition = ((2*j+1)*curve.n)/(2*coefficient);
            for (int delta=-1;delta<=1;++delta) cases.push_back(mod(transition+delta,curve.n));
        }
    }
    for (const auto& scalar : cases) {
        const auto [first,second]=glv_split(scalar);
        require(abs(first)<bound && abs(second)<bound, "GLV boundary component bound");
        require(mod(first-lambda*second-scalar,curve.n)==0, "GLV boundary relation");
    }
}

void native_tests(const Curve& curve)
{
    glv_lattice_bound_tests(curve);
    gmp_randclass random(gmp_randinit_mt);
    random.seed(17);
    const NativePoint generator{curve.gx, curve.gy, false};
    require(native_mul(curve, curve.n, generator).infinity, "n*G is not infinity");
    require(native_mul(curve, 0, generator).infinity, "0*G is not infinity");
    require(native_add(curve, generator, native_mul(curve, -1, generator)).infinity,
            "G + (-G) is not infinity");
    require(same_point(native_add(curve, generator, generator),
                       native_mul(curve, 2, generator)), "doubling mismatch");
    const Big lambda("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16);
    const Big beta("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16);
    for (unsigned i = 0; i < 2000; ++i) {
        const Big scalar = i == 0 ? Big(0) : i == 1 ? Big(1) : i == 2 ? Big(curve.n - 1)
                                                                     : Big(random.get_z_range(curve.n));
        const auto [alpha, signed_beta] = fake_glv_split(curve, scalar);
        require(alpha >= 0 && alpha < (Big(1) << 128), "fake-GLV alpha bound");
        require(signed_beta != 0 && abs(signed_beta) < (Big(1) << 128), "fake-GLV beta bound");
        require(mod(signed_beta * scalar - alpha, curve.n) == 0, "fake-GLV relation");
        if (curve.name == "secp256k1") {
            const auto [low, high] = glv_split(scalar);
            require(abs(low) < (Big(1) << 128) && abs(high) < (Big(1) << 128), "GLV bounds");
            require(mod(low - lambda * high - scalar, curve.n) == 0, "GLV relation");
            if (i < 20) {
                const NativePoint endo{mod(beta * generator.x, curve.p),
                                       mod(-generator.y, curve.p), false};
                require(same_point(native_mul(curve, scalar, generator),
                                   native_add(curve, native_mul(curve, low, generator),
                                               native_mul(curve, high, endo))),
                        "GLV group reconstruction");
            }
        }
        if (i < 20) {
            const Big z = random.get_z_bits(256);
            const Big secret = random.get_z_range(curve.n - 1) + 1;
            const Big nonce = random.get_z_range(curve.n - 1) + 1;
            const Fixture fixture = openssl_sign(curve, z, secret, nonce);
            const auto native_signature = native_sign(curve, z, secret, nonce);
            require(native_signature == std::make_pair(fixture.r, fixture.s),
                    "native signature differs from independent OpenSSL signature");
            require(same_point(fixture.public_key, native_mul(curve, secret, generator)),
                    "native public key differs from OpenSSL");
            require(openssl_verify(curve, fixture), "OpenSSL rejects its signature");
            require(native_verify(curve, z, fixture.r, fixture.s, fixture.public_key),
                    "native verifier rejects OpenSSL signature");
            require(!native_verify(curve, z + 1, fixture.r, fixture.s, fixture.public_key),
                    "native verifier accepts changed digest");
            require(!native_verify(curve, z, fixture.r, curve.n - fixture.s,
                                   fixture.public_key), "native verifier accepts high s");
            require(native_verify(curve, z, fixture.r, curve.n - fixture.s,
                                  fixture.public_key, false), "optional low-s normalization");
        }
    }
    const Fixture reduced_x = openssl_zero_digest_with_x_reduction(curve);
    require(native_verify(curve, reduced_x.z, reduced_x.r, reduced_x.s, reduced_x.public_key),
            "native verifier rejects x modulo n edge case");
    const NativePoint recovered = native_mul(curve, reduced_x.r, reduced_x.public_key);
    require(!recovered.infinity && recovered.x >= curve.n &&
                mod(recovered.x, curve.n) == reduced_x.r,
            "x-reduction fixture did not exercise x >= n");
    rejects([] { (void)inverse(0, 17); }, "zero inverse");
    std::cout << curve.name << ": native/OpenSSL tests passed (2000 decompositions)\n";
}

void builder_tests()
{
    Builder builder;
    const LC a = builder.input(17);
    const LC b = builder.input(9);
    const LC product = builder.mul(a, b);
    builder.equal(product, LC(153L));
    (void)builder.bits(product, 8);
    require(builder.value(product) == 153, "builder multiplication");
    require(builder.public_inputs() == 2, "builder public input accounting");
    rejects([&] { builder.equal(product, LC(154L)); }, "false R1CS equality");
    rejects([&] { (void)builder.bits(product, 7); }, "out-of-range bit decomposition");
    builder.finish();
    require(builder.shape_hash().size() == 64, "shape hash is not SHA-256");
}

uint64_t read_unsigned(std::istream& input, unsigned bytes)
{
    uint64_t result = 0;
    for (unsigned i = 0; i < bytes; ++i) {
        const int byte = input.get();
        require(byte != EOF, "truncated export header");
        result |= static_cast<uint64_t>(byte) << (8 * i);
    }
    return result;
}

void check_export_inputs(const std::filesystem::path& prefix, const Fixture& fixture)
{
    std::ifstream witness(prefix.string() + ".wtns", std::ios::binary);
    require(static_cast<bool>(witness), "witness export missing");
    std::array<char, 4> magic{};
    witness.read(magic.data(), magic.size());
    require(std::string(magic.data(), magic.size()) == "wtns", "invalid witness magic");
    require(read_unsigned(witness, 4) == 2, "unexpected witness version");
    const uint64_t sections = read_unsigned(witness, 4);
    bool checked = false;
    for (uint64_t i = 0; i < sections; ++i) {
        const uint64_t type = read_unsigned(witness, 4);
        const uint64_t size = read_unsigned(witness, 8);
        if (type != 2) {
            witness.seekg(static_cast<std::streamoff>(size), std::ios::cur);
            require(static_cast<bool>(witness), "invalid witness section length");
            continue;
        }
        require(size >= 21 * 32, "witness has too few public input entries");
        std::vector<Big> expected{Big(1)};
        const Big mask = (Big(1) << 64) - 1;
        for (const Big& value : {fixture.public_key.x, fixture.public_key.y,
                                fixture.r, fixture.s, fixture.z}) {
            for (unsigned limb = 0; limb < 4; ++limb) {
                expected.push_back((value >> (64 * limb)) & mask);
            }
        }
        for (const Big& value : expected) {
            std::array<unsigned char, 32> bytes{};
            witness.read(reinterpret_cast<char*>(bytes.data()), bytes.size());
            require(static_cast<bool>(witness), "truncated public witness");
            Big observed;
            mpz_import(observed.get_mpz_t(), bytes.size(), -1, 1, 0, 0, bytes.data());
            require(observed == value, "public input order or limb encoding mismatch");
        }
        checked = true;
        break;
    }
    require(checked, "witness data section missing");
    std::ifstream circuit(prefix.string() + ".r1cs", std::ios::binary);
    circuit.read(magic.data(), magic.size());
    require(circuit && std::string(magic.data(), magic.size()) == "r1cs", "invalid R1CS export magic");
}

struct CircuitShape {
    uint64_t constraints;
    uint64_t variables;
    std::string hash;
};

CircuitShape valid_circuit(const Curve& curve, const Fixture& fixture,
                           const std::string& label,
                           const std::optional<std::filesystem::path>& prefix = {})
{
    require(openssl_verify(curve, fixture), "invalid OpenSSL fixture: " + label);
    const auto start = std::chrono::steady_clock::now();
    Builder builder(prefix);
    verify_ecdsa(builder, curve, fixture.z, fixture.r, fixture.s, fixture.public_key);
    builder.finish();
    require(builder.public_inputs() == 20, "ECDSA circuit must expose exactly 20 public limbs");
    if (prefix) {
        check_export_inputs(*prefix, fixture);
    }
    const auto elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    std::cout << curve.name << '/' << label << ": " << builder.constraints() << " constraints, "
              << builder.variables() << " variables, " << elapsed << " s\n";
    return {builder.constraints(), builder.variables(), builder.shape_hash()};
}

void assert_same_shape(const CircuitShape& expected, const CircuitShape& actual,
                       const std::string& label)
{
    require(expected.constraints == actual.constraints && expected.variables == actual.variables &&
                expected.hash == actual.hash,
            "witness-dependent circuit structure in " + label);
}

void circuit_tests(const Curve& curve, bool extended,
                   const std::optional<std::filesystem::path>& export_dir)
{
    const Big digest("e83339c4518fbb21425d3b63411e45252f1451a098b415a822b53689c40f3f3a", 16);
    const Big secret = 123456789;
    const Big nonce = 987654321;
    const Fixture base = openssl_sign(curve, digest, secret, nonce);
    std::optional<std::filesystem::path> prefix;
    if (export_dir) {
        prefix = *export_dir / curve.name;
    }
    const CircuitShape shape = valid_circuit(curve, base, "OpenSSL", prefix);

    const Fixture zero_hash = openssl_zero_digest_with_x_reduction(curve);
    assert_same_shape(shape, valid_circuit(curve, zero_hash, "zero-hash-and-x-reduction"),
                      "zero digest and x modulo n");

    // R=G and d=3 give r=s=G.x mod n and z=r*(1-d) mod n. Both generators
    // have r<n/2. This valid signature exercises u2=1 and coincident points
    // in fake-GLV, an edge case rejected by the pinned BB implementation.
    const Big r_equal_s = mod(curve.gx, curve.n);
    require(r_equal_s <= curve.n / 2, "u2=1 fixture is not low-s");
    const Fixture unit_u2 = openssl_sign(curve, mod(-2 * r_equal_s, curve.n), Big(3), Big(1));
    require(unit_u2.r == unit_u2.s, "u2=1 fixture generation failed");
    assert_same_shape(shape, valid_circuit(curve, unit_u2, "unit-u2"), "unit u2");

    auto reject_fixture = [&](const Fixture& fixture, const std::string& label) {
        rejects([&] {
            Builder builder;
            verify_ecdsa(builder, curve, fixture.z, fixture.r, fixture.s, fixture.public_key);
            builder.finish();
        }, curve.name + '/' + label);
    };
    Fixture invalid = base;
    invalid.r = 0;
    reject_fixture(invalid, "zero-r");
    invalid = base;
    invalid.s = 0;
    reject_fixture(invalid, "zero-s");
    invalid = base;
    invalid.r = curve.n;
    reject_fixture(invalid, "r-equals-order");
    invalid = base;
    invalid.s = curve.n - base.s;
    require(openssl_verify(curve, invalid), "high-s pair should remain mathematically valid ECDSA");
    reject_fixture(invalid, "high-s");
    invalid = base;
    invalid.public_key.x = curve.p;
    reject_fixture(invalid, "noncanonical-x");
    invalid = base;
    invalid.public_key.y = curve.p;
    reject_fixture(invalid, "noncanonical-y");
    invalid = base;
    invalid.public_key.y = mod(base.public_key.y + 1, curve.p);
    require(!openssl_verify(curve, invalid), "off-curve fixture unexpectedly valid");
    reject_fixture(invalid, "off-curve-key");
    invalid = base;
    invalid.public_key = {Big(0), Big(0), true};
    reject_fixture(invalid, "infinity-key");

    if (extended) {
        invalid = base;
        invalid.z += 1;
        require(!openssl_verify(curve, invalid), "changed-digest fixture unexpectedly valid");
        reject_fixture(invalid, "changed-digest");
        invalid = base;
        invalid.s = base.s < curve.n / 2 ? Big(base.s + 1) : Big(base.s - 1);
        require(!openssl_verify(curve, invalid), "changed-signature fixture unexpectedly valid");
        reject_fixture(invalid, "changed-signature");
    }
    std::cout << curve.name << ": circuit shape and invalid-input tests passed\n";
}

} // namespace

int main(int argc, char** argv)
{
    try {
        bool native_only = false;
        bool extended = false;
        std::optional<std::filesystem::path> export_dir;
        std::vector<std::string> curves{"secp256k1", "p256"};
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--native-only" || arg == "--quick") {
                native_only = true;
            } else if (arg == "--extended") {
                extended = true;
            } else if (arg == "--curve" && i + 1 < argc) {
                std::string name = argv[++i];
                if (name == "k1") name = "secp256k1";
                curves = {curve_by_name(name).name};
            } else if (arg == "--export-dir" && i + 1 < argc) {
                export_dir = argv[++i];
            } else if (arg == "--help") {
                std::cout << "Usage: ecdsa_r1cs_test [--native-only|--quick] [--curve secp256k1|p256]\n"
                             "                       [--extended] [--export-dir DIR]\n"
                             "Default: native/OpenSSL tests plus three circuit witnesses per curve.\n"
                             "--extended adds full-cost invalid digest/signature circuit checks.\n";
                return 0;
            } else {
                throw std::invalid_argument("unknown or incomplete option: " + arg);
            }
        }
        builder_tests();
        for (const auto& name : curves) {
            const Curve curve = curve_by_name(name);
            native_tests(curve);
            if (!native_only) {
                circuit_tests(curve, extended, export_dir);
            }
        }
        std::cout << "All requested tests passed.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "TEST FAILURE: " << error.what() << '\n';
        return 1;
    }
}
