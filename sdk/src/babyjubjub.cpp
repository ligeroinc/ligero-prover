/*
 * Copyright (C) 2023-2025 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ligetron/babyjubjub.h>


namespace ligetron {


bn254fr_class jubjub_point::one = 1;
bn254fr_class jubjub_point::a   = 168700;
bn254fr_class jubjub_point::d   = 168696;

void jubjub_point::assert_equal(jubjub_point& p, jubjub_point& q) {
    ligetron::assert_equal(p.x, q.x);
    ligetron::assert_equal(p.y, q.y);
}

jubjub_point jubjub_point::to_montgomery() {
    bn254fr_class one_plus_y, one_minus_y;
    addmod(one_plus_y, one, y);
    submod(one_minus_y, one, y);

    jubjub_point mnt;
    divmod(mnt.x, one_plus_y, one_minus_y);
    mulmod(mnt.y, one_minus_y, x);
    divmod(mnt.y, one_plus_y, mnt.y);

    return mnt;
}

jubjub_point jubjub_point::to_twisted_edward() {
    jubjub_point ted;
    divmod(ted.x, x, y);

    bn254fr_class tmp;
    submod(ted.y, x, one);
    addmod(tmp, x, one);
    divmod(ted.y, ted.y, tmp);
    return ted;
}

jubjub_point jubjub_point::mux(bn254fr_class& cond,
                               jubjub_point& b0, jubjub_point& b1)
{
    jubjub_point r;
    bn254fr_class::mux(r.x, cond, b0.x, b1.x);
    bn254fr_class::mux(r.y, cond, b0.y, b1.y);

    return r;
}

jubjub_point jubjub_point::mux2(bn254fr_class& s0, bn254fr_class& s1,
                                jubjub_point& b0, jubjub_point& b1,
                                jubjub_point& b2, jubjub_point& b3)
{
    jubjub_point r;
    bn254fr_class::mux2(r.x,
               s0, s1,
               b0.x, b1.x, b2.x, b3.x);
    bn254fr_class::mux2(r.y,
               s0, s1,
               b0.y, b1.y, b2.y, b3.y);
    return r;
}

jubjub_point
jubjub_point::twisted_edward_add(jubjub_point& a, jubjub_point& b) {
    jubjub_point c;
    bn254fr_class lambda;
    mulmod(lambda, jubjub_point::d, a.x);
    mulmod(lambda, lambda, a.y);
    mulmod(lambda, lambda, b.x);
    mulmod(lambda, lambda, b.y);

    bn254fr_class t1, t2, t3;
    mulmod(t1, a.x, b.y);
    mulmod(t2, a.y, b.x);
    addmod(t3, jubjub_point::one, lambda);

    addmod(t1, t1, t2);
    divmod(c.x, t1, t3);

    mulmod(t1, a.y, b.y);
    mulmod(t2, a.x, b.x);
    mulmod(t2, jubjub_point::a, t2);
    submod(t3, jubjub_point::one, lambda);

    submod(t1, t1, t2);
    divmod(c.y, t1, t3);
    return c;
}

jubjub_point jubjub_point::montgomery_double(jubjub_point& p) {
    static bn254fr_class A = 168698;

    jubjub_point d;

    // 3x^2
    bn254fr_class lam = 3;
    mulmod(lam, lam, p.x);
    mulmod(lam, lam, p.x);

    // 2Ax
    bn254fr_class t1 = 2 * 168698;
    mulmod(t1, t1, p.x);

    // lam = 3x^2 + 2Ax
    addmod(lam, lam, t1);

    // lam = 3x^2 + 2Ax + 1
    addmod(lam, lam, jubjub_point::one);

    // t2 = 2y
    bn254fr_class t2 = 2;
    mulmod(t2, t2, p.y);

    // lam = lam / 2y
    divmod(lam, lam, t2);

    // x2 = lam^2 - 2x - A
    bn254fr_class t4 = 2;
    mulmod(d.x, lam, lam);
    mulmod(t4, t4, p.x);
    submod(d.x, d.x, t4);
    submod(d.x, d.x, A);

    bn254fr_class t5;
    submod(t5, p.x, d.x);
    mulmod(d.y, lam, t5);
    submod(d.y, d.y, p.y);

    return d;
}

jubjub_point jubjub_point::scalar_mul(bn254fr_class& x) {
    bn254fr_class bits[254]{};

    jubjub_point w0 = { 0, 1 };
    jubjub_point w1 = *this;
    jubjub_point w2 = jubjub_point::twisted_edward_add(*this, *this);
    jubjub_point w3 = jubjub_point::twisted_edward_add(w1, w2);

    x.to_bits(bits, 254);

    jubjub_point acc = jubjub_point::mux2(bits[252], bits[253], w0, w1, w2, w3);

    for (int i = 250; i >= 0; i -= 2) {
        acc = jubjub_point::twisted_edward_add(acc, acc);
        acc = jubjub_point::twisted_edward_add(acc, acc);

        auto temp = jubjub_point::mux2(bits[i], bits[i + 1], w0, w1, w2, w3);

        acc = jubjub_point::twisted_edward_add(
            acc,
            temp);
    }

    return acc;
}

jubjub_point jubjub_point::scalar_mul_extend(bn254fr_class& x1, bn254fr_class& x2) {
    bn254fr_class bits[254]{};

    jubjub_point w0 = { 0, 1 };
    jubjub_point w1 = *this;
    jubjub_point w2 = jubjub_point::twisted_edward_add(*this, *this);
    jubjub_point w3 = jubjub_point::twisted_edward_add(w1, w2);

    x2.to_bits(bits, 254);

    jubjub_point acc = jubjub_point::mux2(bits[252], bits[253], w0, w1, w2, w3);
    for (int i = 250; i >= 0; i -= 2) {
        acc = jubjub_point::twisted_edward_add(acc, acc);
        acc = jubjub_point::twisted_edward_add(acc, acc);

        auto temp = jubjub_point::mux2(bits[i], bits[i + 1], w0, w1, w2, w3);

        acc = jubjub_point::twisted_edward_add(
            acc,
            temp);
    }

    x1.to_bits(bits, 254);
    for (int i = 252; i >= 0; i -= 2) {
        acc = jubjub_point::twisted_edward_add(acc, acc);
        acc = jubjub_point::twisted_edward_add(acc, acc);

        auto tmp = jubjub_point::mux2(bits[i], bits[i + 1], w0, w1, w2, w3);

        acc = jubjub_point::twisted_edward_add(
            acc,
            tmp);
    }

    return acc;
}

//------------------------------------------------------------

const vbn254fr_constant jubjub_point_vec::one   = vbn254fr_constant_from_str("1");
const vbn254fr_constant jubjub_point_vec::a     = vbn254fr_constant_from_str("168700");
const vbn254fr_constant jubjub_point_vec::d     = vbn254fr_constant_from_str("168696");
const vbn254fr_constant jubjub_point_vec::A     = vbn254fr_constant_from_str("168698");
const vbn254fr_constant jubjub_point_vec::two_A = vbn254fr_constant_from_str("337396");

void jubjub_point_vec::assert_equal(const jubjub_point_vec& p, const jubjub_point_vec& q) {
    ligetron::assert_equal(p.x, q.x);
    ligetron::assert_equal(p.y, q.y);
}

jubjub_point_vec jubjub_point_vec::to_montgomery() const {
    vbn254fr_class one_plus_y, one_minus_y;
    addmod_constant(one_plus_y, y, jubjub_point_vec::one);
    constant_submod(one_minus_y, jubjub_point_vec::one, y);

    jubjub_point_vec mnt;
    divmod(mnt.x, one_plus_y, one_minus_y);
    mulmod(mnt.y, one_minus_y, x);
    divmod(mnt.y, one_plus_y, mnt.y);

    return mnt;
}

jubjub_point_vec jubjub_point_vec::to_twisted_edward() const {
    jubjub_point_vec ted;
    divmod(ted.x, x, y);

    vbn254fr_class tmp;
    submod_constant(ted.y, x, jubjub_point_vec::one);
    addmod_constant(tmp, x, jubjub_point_vec::one);
    divmod(ted.y, ted.y, tmp);
    return ted;
}

jubjub_point_vec
jubjub_point_vec::mux(const vbn254fr_class& cond,
                      const jubjub_point_vec& b0, const jubjub_point_vec& b1)
{
    jubjub_point_vec r;
    vbn254fr_class::mux(r.x, cond, b0.x, b1.x);
    vbn254fr_class::mux(r.y, cond, b0.y, b1.y);
    return r;
}

jubjub_point_vec
jubjub_point_vec::mux2(const vbn254fr_class& s0, const vbn254fr_class& s1,
                       const jubjub_point_vec& b0, const jubjub_point_vec& b1,
                       const jubjub_point_vec& b2, const jubjub_point_vec& b3)
{
    jubjub_point_vec r;
    vbn254fr_class::mux2(r.x,
                  s0, s1,
                  b0.x, b1.x, b2.x, b3.x);
    vbn254fr_class::mux2(r.y,
                  s0, s1,
                  b0.y, b1.y, b2.y, b3.y);
    return r;
}

jubjub_point_vec
jubjub_point_vec::twisted_edward_add(const jubjub_point_vec& a, const jubjub_point_vec& b) {
    jubjub_point_vec c;
    vbn254fr_class lambda;
    mulmod_constant(lambda, a.x, jubjub_point_vec::d);
    mulmod(lambda, lambda, a.y);
    mulmod(lambda, lambda, b.x);
    mulmod(lambda, lambda, b.y);

    vbn254fr_class t1, t2, t3;
    mulmod(t1, a.x, b.y);
    mulmod(t2, a.y, b.x);
    addmod_constant(t3, lambda, jubjub_point_vec::one);

    addmod(t1, t1, t2);
    divmod(c.x, t1, t3);

    mulmod(t1, a.y, b.y);
    mulmod(t2, a.x, b.x);
    mulmod_constant(t2, t2, jubjub_point_vec::a);
    constant_submod(t3, jubjub_point_vec::one, lambda);

    submod(t1, t1, t2);
    divmod(c.y, t1, t3);
    return c;
}

jubjub_point_vec jubjub_point_vec::montgomery_double(const jubjub_point_vec& p) {
    static vbn254fr_constant two = vbn254fr_constant_from_str("2");
    static vbn254fr_constant three = vbn254fr_constant_from_str("3");
    jubjub_point_vec d;

    // 3x^2
    vbn254fr_class lam;
    mulmod_constant(lam, p.x, three);
    mulmod(lam, lam, p.x);

    // 2Ax
    // vbn254fr_class t1 = 2 * 168698;
    vbn254fr_class t1;
    mulmod_constant(t1, p.x, jubjub_point_vec::two_A);

    // lam = 3x^2 + 2Ax
    addmod(lam, lam, t1);

    // lam = 3x^2 + 2Ax + 1
    addmod_constant(lam, lam, jubjub_point_vec::one);

    // t2 = 2y
    vbn254fr_class t2;
    mulmod_constant(t2, p.y, two);

    // lam = lam / 2y
    divmod(lam, lam, t2);

    // x2 = lam^2 - 2x - A
    vbn254fr_class t4;
    mulmod(d.x, lam, lam);
    mulmod_constant(t4, p.x, two);
    submod(d.x, d.x, t4);
    submod_constant(d.x, d.x, jubjub_point_vec::A);

    vbn254fr_class t5;
    submod(t5, p.x, d.x);
    mulmod(d.y, lam, t5);
    submod(d.y, d.y, p.y);

    return d;
}

jubjub_point_vec jubjub_point_vec::scalar_mul(const vbn254fr_class& x) const {
    vbn254fr_class bits[254]{};

    const jubjub_point_vec w0 = { 0, 1 };
    const jubjub_point_vec w1 = *this;
    const jubjub_point_vec w2 = jubjub_point_vec::twisted_edward_add(*this, *this);
    const jubjub_point_vec w3 = jubjub_point_vec::twisted_edward_add(w1, w2);

    x.bit_decompose(bits);

    jubjub_point_vec acc = jubjub_point_vec::mux2(bits[252], bits[253], w0, w1, w2, w3);

    for (int i = 250; i >= 0; i -= 2) {
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);

        acc = jubjub_point_vec::twisted_edward_add(
            acc,
            jubjub_point_vec::mux2(bits[i], bits[i + 1], w0, w1, w2, w3));
    }

    return acc;
}

jubjub_point_vec
jubjub_point_vec::scalar_mul_extend(const vbn254fr_class& x1, const vbn254fr_class& x2) const {
    vbn254fr_class bits[254]{};

    const jubjub_point_vec w0 = { 0, 1 };
    const jubjub_point_vec w1 = *this;
    const jubjub_point_vec w2 = jubjub_point_vec::twisted_edward_add(*this, *this);
    const jubjub_point_vec w3 = jubjub_point_vec::twisted_edward_add(w1, w2);

    x2.bit_decompose(bits);

    jubjub_point_vec acc = jubjub_point_vec::mux2(bits[252], bits[253], w0, w1, w2, w3);
    for (int i = 250; i >= 0; i -= 2) {
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);

        acc = jubjub_point_vec::twisted_edward_add(
            acc,
            jubjub_point_vec::mux2(bits[i], bits[i + 1], w0, w1, w2, w3));
    }

    x1.bit_decompose(bits);

    for (int i = 252; i >= 0; i -= 2) {
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);
        acc = jubjub_point_vec::twisted_edward_add(acc, acc);

        acc = jubjub_point_vec::twisted_edward_add(
            acc,
            jubjub_point_vec::mux2(bits[i], bits[i + 1], w0, w1, w2, w3));
    }

    return acc;
}

} // namespace ligetron
