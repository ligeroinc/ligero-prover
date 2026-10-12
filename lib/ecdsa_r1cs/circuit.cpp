// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "circuit.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace ecdsa_r1cs {
namespace {
const Big B = Big(1) << 64;
const Big MASK = B - 1;

Big limb(const Big& value, unsigned i) { return Big((value >> (64 * i)) & MASK); }

Big centered(const Big& value) {
    return value > native_modulus() / 2 ? Big(value - native_modulus()) : value;
}

LC is_zero(Builder& builder, const LC& x) {
    const Big v = builder.value(x);
    LC flag = builder.witness(v == 0 ? Big(1) : Big(0));
    LC inv = builder.witness(v == 0 ? Big(0) : inverse(v, native_modulus()));
    builder.constrain(x, inv, LC(1) - flag);
    builder.constrain(x, flag, LC(0));
    return flag;
}

Number materialize(Builder& b, Number n) {
    for (auto& x : n.limbs) {
        // Keep short linear expressions directly in R1CS rows. Allocating
        // aliases for every mux adds a linear row without adding information.
        // Large constant-table combinations are still materialized so later
        // rows and exported matrices do not grow with the whole table.
        if (!x.constant() && x.terms().size() > 16) {
            LC w = b.witness(b.value(x));
            b.equal(w, x);
            x = w;
        }
    }
    return n;
}

void zero_when(Builder& b, const LC& condition, const Number& n) {
    for (const auto& x : n.limbs) b.constrain(condition, x, LC(0));
}

Point choose_table(CurveCircuit& ec, const std::vector<Point>& table,
                   const std::vector<LC>& bits, unsigned start, unsigned width,
                   bool constants) {
    std::vector<LC> window;
    unsigned index = 0;
    for (unsigned j = 0; j < width; ++j) {
        LC bit = start + j < bits.size() ? bits[start + j] : LC(0);
        window.push_back(bit);
        if (ec.builder.value(bit) == 1) index |= 1u << j;
    }
    if (!constants) {
        std::vector<Point> layer = table;
        for (unsigned j = 0; j < width; ++j) {
            std::vector<Point> next;
            for (size_t k = 0; k < layer.size(); k += 2)
                next.push_back(ec.select(window[j], layer[k + 1], layer[k]));
            layer = std::move(next);
        }
        return layer.front();
    }
    // Boolean selector tree. Every lookup is ordinary rank-one constraints.
    std::vector<LC> weights{LC(1)};
    for (unsigned j = 0; j < width; ++j) {
        std::vector<LC> next(weights.size() * 2);
        for (size_t k = 0; k < weights.size(); ++k) {
            LC right = ec.builder.mul(weights[k], window[j]);
            next[k] = weights[k] - right;
            next[k + weights.size()] = right;
        }
        weights = std::move(next);
    }
    Point result = ec.constant(table[index].value);
    result.x.limbs = {};
    result.y.limbs = {};
    result.infinity = LC(0);
    // Assemble each public table expression once. Repeated LC additions sort
    // and copy an ever-growing vector; one normalization gives identical rows.
    for (unsigned coordinate = 0; coordinate < 2; ++coordinate) {
        for (unsigned j = 0; j < 4; ++j) {
            std::vector<Term> terms;
            terms.reserve(2 * table.size());
            for (size_t k = 0; k < table.size(); ++k) {
                const Big coefficient = limb(coordinate ? table[k].value.y : table[k].value.x, j);
                if (coefficient == 0) continue;
                for (const auto& term : weights[k].terms())
                    terms.push_back({term.wire, Big(term.coefficient * coefficient)});
            }
            (coordinate ? result.y.limbs[j] : result.x.limbs[j]) = LC(std::move(terms));
        }
    }
    for (size_t k = 0; k < table.size(); ++k)
        if (table[k].value.infinity) result.infinity = result.infinity + weights[k];
    result.x = materialize(ec.builder, std::move(result.x));
    result.y = materialize(ec.builder, std::move(result.y));
    return result;
}

const std::vector<std::vector<Point>>& fixed_base_table(CurveCircuit& ec) {
    struct Entry {
        Curve curve;
        std::vector<std::vector<Point>> windows;
    };
    // Every Point below consists only of public constants. No private scalar,
    // auxiliary witness value, builder wire, or allocation state enters this
    // cache. Separate workers/threads prepare their own immutable copy.
    static thread_local std::vector<Entry> cache;
    const auto same_curve = [&](const Curve& curve) {
        return curve.name == ec.curve.name && curve.p == ec.curve.p &&
               curve.n == ec.curve.n && curve.a == ec.curve.a &&
               curve.b == ec.curve.b && curve.gx == ec.curve.gx &&
               curve.gy == ec.curve.gy;
    };
    for (const auto& entry : cache)
        if (same_curve(entry.curve)) return entry.windows;

    Entry entry{ec.curve, {}};
    entry.windows.reserve(29);
    NativePoint base{ec.curve.gx, ec.curve.gy, false};
    for (unsigned window = 0; window < 29; ++window) {
        std::vector<Point> table;
        table.reserve(512);
        NativePoint point{0, 0, true};
        for (unsigned i = 0; i < 512; ++i) {
            table.push_back(ec.constant(point));
            point = native_add(ec.curve, point, base);
        }
        entry.windows.push_back(std::move(table));
        for (unsigned i = 0; i < 9; ++i)
            base = native_add(ec.curve, base, base);
    }
    cache.push_back(std::move(entry));
    return cache.back().windows;
}
} // namespace

ForeignField::ForeignField(Builder& b, Big m) : builder(b), modulus(std::move(m)) {
    if (modulus <= (Big(1) << 255) || modulus >= (Big(1) << 256))
        throw std::invalid_argument("foreign modulus must have exactly 256 bits");
}

Number ForeignField::constant(const Big& input) const {
    Number n;
    n.value = mod(input, modulus);
    for (unsigned i = 0; i < 4; ++i) n.limbs[i] = LC(limb(n.value, i));
    return n;
}

Number ForeignField::bounded(const Big& value, unsigned width) {
    if (width > 256 || value < 0 || value >= (Big(1) << width))
        throw std::invalid_argument("foreign witness exceeds its bit bound");
    Number n;
    n.value = value;
    n.bits.reserve(width);
    for (unsigned i = 0; i < 4; ++i) {
        const unsigned w = width > 64 * i ? std::min(64u, width - 64 * i) : 0;
        n.limbs[i] = w ? builder.witness(limb(value, i)) : LC(0);
        if (w) {
            auto bits = builder.bits(n.limbs[i], w);
            n.bits.insert(n.bits.end(), std::make_move_iterator(bits.begin()),
                          std::make_move_iterator(bits.end()));
        }
    }
    return n;
}

Number ForeignField::from_inputs(const std::array<LC, 4>& inputs, const Big& value) {
    Number n{inputs, value, {}};
    n.bits.reserve(256);
    for (const auto& x : inputs) {
        auto bits = builder.bits(x, 64);
        n.bits.insert(n.bits.end(), std::make_move_iterator(bits.begin()),
                          std::make_move_iterator(bits.end()));
    }
    canonical(n, modulus);
    return n;
}

Number ForeignField::witness(const Big& value) {
    Number n = bounded(value, 256);
    canonical(n, modulus);
    return n;
}

void ForeignField::canonical(const Number& n, const Big& upper) {
    if (n.bits.size() != 256 || upper <= 0 || upper >= (Big(1) << 256))
        throw std::invalid_argument("canonical comparison requires 256 bounded bits");
    // Little-to-big recurrence for x < a constant: all intermediates are
    // Boolean consequences of already constrained input bits.
    LC less(0);
    for (unsigned i = 0; i < 256;) {
        const bool one = mpz_tstbit(upper.get_mpz_t(), i);
        unsigned end = i + 1;
        while (end < 256 && bool(mpz_tstbit(upper.get_mpz_t(), end)) == one) ++end;
        if (end - i < 4) {
            for (; i < end; ++i)
                less = one ? LC(1) - builder.mul(n.bits[i], LC(1) - less)
                           : builder.mul(LC(1) - n.bits[i], less);
        } else {
            // A run matches the public bound iff its mismatch count is zero.
            // The sum is in [0,256], so this native-field zero test cannot wrap.
            // Normalize the complete sum once. Repeated LC additions copy
            // increasingly long vectors for runs of hundreds of equal bits.
            std::vector<Term> terms;
            terms.reserve(end - i + 1);
            if (one) terms.push_back({0, Big(end - i)});
            for (; i < end; ++i)
                for (const auto& term : n.bits[i].terms())
                    terms.push_back({term.wire, one ? Big(-term.coefficient) : term.coefficient});
            const LC mismatches(std::move(terms));
            LC matches = is_zero(builder, mismatches);
            less = one ? LC(1) - builder.mul(matches, LC(1) - less)
                       : builder.mul(matches, less);
        }
    }
    builder.equal(less, LC(1));
}

Number ForeignField::signed_number(const Number& magnitude, const LC& negative) {
    Number n = magnitude;
    n.bits.clear();
    if (builder.value(negative) == 1) n.value = -n.value;
    for (unsigned i = 0; i < 4; ++i)
        n.limbs[i] = magnitude.limbs[i] - 2 * builder.mul(negative, magnitude.limbs[i]);
    return materialize(builder, std::move(n));
}

Number ForeignField::select(const LC& condition, const Number& yes, const Number& no) {
    Number n;
    n.value = builder.value(condition) == 1 ? yes.value : no.value;
    for (unsigned i = 0; i < 4; ++i)
        n.limbs[i] = no.limbs[i] + builder.mul(condition, yes.limbs[i] - no.limbs[i]);
    return materialize(builder, std::move(n));
}

void ForeignField::relation(std::initializer_list<Product> products,
                             std::initializer_list<Linear> linear, const LC& enable) {
    unsigned product_weight = 0, linear_weight = 0;
    Big total = 0;
    for (const auto& t : products) {
        product_weight += static_cast<unsigned>(std::abs(t.coefficient));
        total += t.coefficient * t.a->value * t.b->value;
    }
    for (const auto& t : linear) {
        linear_weight += static_cast<unsigned>(std::abs(t.coefficient));
        total += t.coefficient * t.a->value;
    }
    if (product_weight > 8 || linear_weight > 16)
        throw std::invalid_argument("foreign relation exceeds proved carry bounds");
    total *= builder.value(enable);
    // Signed quotient encoded with a constant offset. Its five limbs have
    // 64+64+64+64+6 bounded bits. No native-field packing of 256-bit values.
    const Big offset = Big(1) << 260;
    const Big qvalue = Big(total / modulus) + offset;
    if (qvalue < 0 || qvalue >= (Big(1) << 262))
        throw std::runtime_error("foreign quotient overflow");
    std::array<LC, 5> q;
    for (unsigned i = 0; i < 5; ++i) {
        q[i] = builder.witness(limb(qvalue, i));
        builder.bits(q[i], i == 4 ? 6 : 64);
    }
    std::array<LC, 8> coefficients{};
    for (const auto& t : products)
        for (unsigned i = 0; i < 4; ++i)
            for (unsigned j = 0; j < 4; ++j)
                coefficients[i + j] = coefficients[i + j] +
                    t.coefficient * builder.mul(t.a->limbs[i], t.b->limbs[j]);
    for (const auto& t : linear)
        for (unsigned i = 0; i < 4; ++i)
            coefficients[i] = coefficients[i] + t.coefficient * t.a->limbs[i];
    for (auto& coefficient : coefficients) coefficient = builder.mul(enable, coefficient);
    // Keep the offset digits unnormalized: 2^260*m = 16*B^4*m.
    // This avoids a ninth coefficient and its extra range-checked carry.
    for (unsigned i = 0; i < 4; ++i)
        coefficients[i + 4] = coefficients[i + 4] + LC(16 * limb(modulus, i));
    for (unsigned i = 0; i < 5; ++i)
        for (unsigned j = 0; j < 4; ++j)
            coefficients[i + j] = coefficients[i + j] - q[i] * limb(modulus, j);

    // Carry c is represented by s=c+C, C=64*2^64. Each s has 72 bits.
    // Check two radix-B coefficients per equation, saving every other carry
    // range check. Each coefficient is bounded by 40*B^2 and honest grouped
    // carries by 64*B. For any bounded s, a grouped residual is below 2^202,
    // well below BN254 Fr; thus field equality implies integer equality.
    const Big C = 64 * B;
    LC previous(C);
    Big carry = 0;
    const Big radix = B * B;
    for (unsigned i = 0; i < coefficients.size(); i += 2) {
        const LC grouped = coefficients[i] + coefficients[i + 1] * B;
        const Big coefficient = centered(builder.value(grouped));
        const Big numerator = coefficient + carry;
        Big next_carry = numerator / radix;
        LC next(C);
        if (i + 2 != coefficients.size()) {
            next = builder.witness(next_carry + C);
            builder.bits(next, 72);
        } else {
            next_carry = 0;
        }
        builder.equal(grouped + previous - next * radix + LC((radix - 1) * C), LC(0));
        previous = next;
        carry = next_carry;
    }
}

Number ForeignField::negate(const Number& a) {
    Number r = witness(mod(-a.value, modulus));
    relation({}, {{1, &a}, {1, &r}});
    return r;
}

Number ForeignField::multiply(const Number& a, const Number& b) {
    Number r = witness(mod(a.value * b.value, modulus));
    relation({{1, &a, &b}}, {{-1, &r}});
    return r;
}

Number ForeignField::divide(const Number& a, const Number& b) {
    nonzero(b);
    Number r = witness(mod(a.value * inverse(b.value, modulus), modulus));
    relation({{1, &r, &b}}, {{-1, &a}});
    return r;
}

LC ForeignField::equal(const Number& a, const Number& b) {
    LC result(1);
    for (unsigned i = 0; i < 4; ++i)
        result = builder.mul(result, is_zero(builder, a.limbs[i] - b.limbs[i]));
    return result;
}

void ForeignField::nonzero(const Number& a) {
    LC sum(0);
    for (const auto& x : a.limbs) sum = sum + x;
    LC inv = builder.witness(inverse(builder.value(sum), native_modulus()));
    builder.constrain(sum, inv, LC(1));
}

CurveCircuit::CurveCircuit(Builder& b, const Curve& c) : builder(b), curve(c), field(b, c.p) {}

Point CurveCircuit::constant(const NativePoint& point) {
    const NativePoint p = point.infinity ? NativePoint{0, 0, true} : point;
    return {field.constant(p.x), field.constant(p.y), LC(p.infinity ? 1 : 0), p};
}

Point CurveCircuit::point_witness(const NativePoint& point) {
    const NativePoint p = point.infinity ? NativePoint{0, 0, true} : point;
    LC inf = builder.witness(p.infinity ? Big(1) : Big(0));
    builder.bits(inf, 1);
    Point out{field.witness(p.x), field.witness(p.y), inf, p};
    zero_when(builder, inf, out.x);
    zero_when(builder, inf, out.y);
    on_curve(out);
    return out;
}

void CurveCircuit::on_curve(const Point& point) {
    Number square = field.multiply(point.x, point.x);
    Number a = field.constant(curve.a), b = field.constant(curve.b);
    field.relation({{1, &point.y, &point.y}, {-1, &square, &point.x}, {-1, &a, &point.x}},
                   {{-1, &b}}, LC(1) - point.infinity);
}

Point CurveCircuit::select(const LC& condition, const Point& yes, const Point& no) {
    return {field.select(condition, yes.x, no.x), field.select(condition, yes.y, no.y),
            no.infinity + builder.mul(condition, yes.infinity - no.infinity),
            builder.value(condition) == 1 ? yes.value : no.value};
}

Point CurveCircuit::negate(const Point& point) {
    Point result = point;
    result.y = field.negate(point.y);
    result.value.y = result.y.value;
    return result;
}

Point CurveCircuit::twice(const Point& p) {
    // This branch inspects only the circuit's literal constant, never a
    // witness value. It removes the known identity at the start of MSM.
    if (auto infinity = p.infinity.constant(); infinity && *infinity == 1) return p;
    LC active = builder.mul(LC(1) - p.infinity, LC(1) - field.equal(p.y, field.constant(0)));
    NativePoint result = native_add(curve, p.value, p.value);
    Big slope_value = 0;
    if (!result.infinity)
        slope_value = mod((3 * p.value.x * p.value.x + curve.a) * inverse(2 * p.value.y, curve.p), curve.p);
    // The slope participates only in modular identities; a bounded residue
    // is sufficient. Coordinates still require canonical representatives.
    Number slope = field.bounded(slope_value, 256);
    Number x = field.witness(result.infinity ? Big(0) : result.x);
    Number y = field.witness(result.infinity ? Big(0) : result.y);
    Number a = field.constant(curve.a);
    field.relation({{2, &slope, &p.y}, {-3, &p.x, &p.x}}, {{-1, &a}}, active);
    field.relation({{1, &slope, &slope}}, {{-1, &x}, {-2, &p.x}}, active);
    field.relation({{1, &slope, &p.x}, {-1, &slope, &x}}, {{-1, &y}, {-1, &p.y}}, active);
    zero_when(builder, LC(1) - active, x);
    zero_when(builder, LC(1) - active, y);
    return {x, y, LC(1) - active, result};
}

Point CurveCircuit::add(const Point& p, const Point& q) {
    if (auto infinity = p.infinity.constant(); infinity && *infinity == 1) return q;
    if (auto infinity = q.infinity.constant(); infinity && *infinity == 1) return p;
    LC finite = builder.mul(LC(1) - p.infinity, LC(1) - q.infinity);
    LC same_x = field.equal(p.x, q.x);
    LC same_y = field.equal(p.y, q.y);
    LC ordinary = builder.mul(finite, LC(1) - same_x);
    // Constraint and wire order is part of the pinned template. Sequence
    // emitting calls explicitly: function argument evaluation order is not
    // specified, even when each argument is individually well defined.
    LC finite_same_x = builder.mul(finite, same_x);
    LC finite_same_point = builder.mul(finite_same_x, same_y);
    LC y_zero = field.equal(p.y, field.constant(0));
    LC doubling = builder.mul(finite_same_point, LC(1) - y_zero);
    LC active = ordinary + doubling;
    NativePoint sum = native_add(curve, p.value, q.value);
    NativePoint candidate = builder.value(active) == 1 ? sum : NativePoint{0, 0, true};
    Big slope_value = 0;
    if (builder.value(ordinary) == 1)
        slope_value = mod((q.value.y - p.value.y) * inverse(q.value.x - p.value.x, curve.p), curve.p);
    else if (builder.value(doubling) == 1)
        slope_value = mod((3 * p.value.x * p.value.x + curve.a) * inverse(2 * p.value.y, curve.p), curve.p);
    Number slope = field.bounded(slope_value, 256);
    Number x = field.witness(candidate.x), y = field.witness(candidate.y);
    Number a = field.constant(curve.a);
    // The ordinary and tangent branches are disjoint. Mask their bounded
    // operands, then enforce both slope equations in one modular relation.
    // This shares one quotient and its carry checks without relaxing either
    // branch or multiplying two unconstrained native-field expressions.
    const Number zero = field.constant(0);
    Number ordinary_px = field.select(ordinary, p.x, zero);
    Number ordinary_qx = field.select(ordinary, q.x, zero);
    Number ordinary_py = field.select(ordinary, p.y, zero);
    Number ordinary_qy = field.select(ordinary, q.y, zero);
    Number double_px = field.select(doubling, p.x, zero);
    Number double_py = field.select(doubling, p.y, zero);
    Number double_a = field.select(doubling, a, zero);
    field.relation({{1, &slope, &ordinary_qx}, {-1, &slope, &ordinary_px},
                    {2, &slope, &double_py}, {-3, &double_px, &p.x}},
                   {{-1, &ordinary_qy}, {1, &ordinary_py}, {-1, &double_a}});
    field.relation({{1, &slope, &slope}}, {{-1, &x}, {-1, &p.x}, {-1, &q.x}}, active);
    field.relation({{1, &slope, &p.x}, {-1, &slope, &x}}, {{-1, &y}, {-1, &p.y}}, active);
    zero_when(builder, LC(1) - active, x);
    zero_when(builder, LC(1) - active, y);
    Point out{x, y, LC(1) - active, candidate};
    out = select(p.infinity, q, out);
    return select(q.infinity, p, out);
}

void CurveCircuit::prepare_fixed_base_table() {
    (void)fixed_base_table(*this);
}

Point CurveCircuit::fixed_mul(const Number& scalar) {
    if (scalar.bits.size() != 256) throw std::invalid_argument("fixed mul requires 256 bits");
    Point result = constant({0, 0, true});
    const auto& tables = fixed_base_table(*this);
    // Nine-bit constant windows minimize ordinary R1CS rows for this gadget.
    for (unsigned window = 0; window < 29; ++window) {
        Point selected = choose_table(*this, tables[window], scalar.bits, window * 9, 9, true);
        result = add(result, selected);
    }
    return result;
}

Point CurveCircuit::joint_mul(const Number& a, const Point& p, const Number& b, const Point& q) {
    if (a.bits.empty() || b.bits.empty()) throw std::invalid_argument("joint mul needs bounded scalars");
    constexpr unsigned width = 2;
    constexpr unsigned stride = 1u << width;
    std::vector<Point> pt{constant({0, 0, true}), p};
    std::vector<Point> qt{constant({0, 0, true}), q};
    for (unsigned i = 2; i < stride; ++i) {
        pt.push_back(add(pt.back(), p));
        qt.push_back(add(qt.back(), q));
    }
    // One 2D lookup combines both scalar windows, so each loop needs one add.
    std::vector<Point> table;
    for (unsigned row = 0; row < stride; ++row) {
        for (unsigned col = 0; col < stride; ++col) {
            table.push_back(row == 0 ? pt[col] : col == 0 ? qt[row] : add(pt[col], qt[row]));
        }
    }
    const unsigned windows = static_cast<unsigned>((std::max(a.bits.size(), b.bits.size()) + width - 1) / width);
    std::vector<LC> joint_bits;
    for (unsigned w = 0; w < windows; ++w) {
        for (unsigned j = 0; j < width; ++j) joint_bits.push_back(w * width + j < a.bits.size() ? a.bits[w * width + j] : LC(0));
        for (unsigned j = 0; j < width; ++j) joint_bits.push_back(w * width + j < b.bits.size() ? b.bits[w * width + j] : LC(0));
    }
    Point result = constant({0, 0, true});
    for (unsigned w = windows; w-- > 0;) {
        for (unsigned j = 0; j < width; ++j) result = twice(result);
        result = add(result, choose_table(*this, table, joint_bits, w * 2 * width, 2 * width, false));
    }
    return result;
}

Point CurveCircuit::variable_mul(const Number& scalar, const Point& p, ForeignField& scalars) {
    if (curve.name == "secp256k1") {
        auto [a, b] = glv_split(scalar.value);
        Number am = scalars.bounded(abs(a), 128), bm = scalars.bounded(abs(b), 128);
        LC aneg = builder.witness(a < 0 ? Big(1) : Big(0));
        LC bneg = builder.witness(b < 0 ? Big(1) : Big(0));
        builder.bits(aneg, 1); builder.bits(bneg, 1);
        Number sa = scalars.signed_number(am, aneg), sb = scalars.signed_number(bm, bneg);
        Number lambda = scalars.constant(Big("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72", 16));
        scalars.relation({{-1, &lambda, &sb}}, {{1, &sa}, {-1, &scalar}});
        Number beta = field.constant(Big("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16));
        Point phi = negate(p);
        phi.x = field.multiply(beta, p.x);
        phi.value.x = phi.x.value;
        // Emit the first signed point before the second on every compiler.
        // Calling both select gadgets as joint_mul arguments would leave
        // their constraint/wire allocation order implementation dependent.
        Point negative_p = negate(p);
        Point signed_p = select(aneg, negative_p, p);
        Point negative_phi = negate(phi);
        Point signed_phi = select(bneg, negative_phi, phi);
        return joint_mul(am, signed_p, bm, signed_phi);
    }
    auto [alpha, beta] = fake_glv_split(curve, scalar.value);
    Number am = scalars.bounded(alpha, 128), bm = scalars.bounded(abs(beta), 128);
    scalars.nonzero(bm);
    LC negative = builder.witness(beta < 0 ? Big(1) : Big(0));
    builder.bits(negative, 1);
    Number signed_beta = scalars.signed_number(bm, negative);
    scalars.relation({{1, &signed_beta, &scalar}}, {{-1, &am}});
    Point t = point_witness(native_mul(curve, scalar.value, p.value));
    Point minus_beta_t = select(negative, t, negate(t));
    Point check = joint_mul(am, p, bm, minus_beta_t);
    builder.equal(check.infinity, LC(1));
    return t;
}

PreparedEcdsa prepare_ecdsa(Builder& builder, const Curve& curve, const Big& digest,
                  const Big& rvalue, const Big& svalue, const NativePoint& public_key) {
    // Only public ABI range checks occur before allocating the fixed circuit.
    if (public_key.infinity) throw std::invalid_argument("ECDSA public key must be finite");
    const std::array<Big, 5> values{public_key.x, public_key.y, rvalue, svalue, digest};
    std::array<std::array<LC, 4>, 5> inputs;
    for (unsigned k = 0; k < 5; ++k) {
        if (values[k] < 0 || values[k] >= (Big(1) << 256))
            throw std::invalid_argument("input is not an unsigned 256-bit integer");
        for (unsigned i = 0; i < 4; ++i) inputs[k][i] = builder.input(limb(values[k], i));
    }
    builder.set_stage("input_validation");
    CurveCircuit ec(builder, curve);
    ForeignField scalars(builder, curve.n);
    Point q{ec.field.from_inputs(inputs[0], public_key.x),
            ec.field.from_inputs(inputs[1], public_key.y), LC(0),
            {public_key.x, public_key.y, false}};
    ec.on_curve(q);
    Number r = scalars.from_inputs(inputs[2], rvalue), s = scalars.from_inputs(inputs[3], svalue);
    scalars.nonzero(r); scalars.nonzero(s);
    scalars.canonical(s, Big(curve.n / 2) + 1);
    // Digest may be any 256-bit value, including values >= the curve order.
    Number z{inputs[4], digest, {}};
    for (auto& x : z.limbs) builder.bits(x, 64);
    builder.set_stage("scalar_divisions");
    Number u1 = scalars.divide(z, s), u2 = scalars.divide(r, s);
    return {q, r, u1, u2};
}

void finish_ecdsa(Builder& builder, const Curve& curve, const Point& p1,
                  const Point& p2, const Number& r) {
    CurveCircuit ec(builder, curve);
    ForeignField scalars(builder, curve.n);
    builder.set_stage("final_point_and_x_check");
    Point sum = ec.add(p1, p2);
    builder.equal(sum.infinity, LC(0));
    scalars.relation({}, {{1, &sum.x}, {-1, &r}});
}

void verify_ecdsa(Builder& builder, const Curve& curve, const Big& digest,
                  const Big& rvalue, const Big& svalue, const NativePoint& public_key) {
    const auto prepared = prepare_ecdsa(builder, curve, digest, rvalue, svalue, public_key);
    CurveCircuit ec(builder, curve);
    ForeignField scalars(builder, curve.n);
    builder.set_stage("fixed_base_multiplication");
    Point p1 = ec.fixed_mul(prepared.u1);
    builder.set_stage(curve.name == "secp256k1" ? "variable_base_glv" : "variable_base_fake_glv");
    Point p2 = ec.variable_mul(prepared.u2, prepared.q, scalars);
    finish_ecdsa(builder, curve, p1, p2, prepared.r);
}

} // namespace ecdsa_r1cs
