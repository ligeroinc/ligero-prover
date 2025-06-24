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

#ifndef __LIGETRON_BABYJUBJUB__
#define __LIGETRON_BABYJUBJUB__

#include <ligetron/bn254fr_class.h>
#include <ligetron/vbn254fr_class.h>

namespace ligetron {

struct jubjub_point {
    static bn254fr_class one;
    static bn254fr_class a;
    static bn254fr_class d;

    static void  assert_equal(jubjub_point& p, jubjub_point& q);
    static jubjub_point mux(bn254fr_class& cond,
                            jubjub_point& b0, jubjub_point& b1);

    static jubjub_point mux2(bn254fr_class& s0, bn254fr_class& s1,
                             jubjub_point& b0, jubjub_point& b1,
                             jubjub_point& b2, jubjub_point& b3);

    static jubjub_point twisted_edward_add(jubjub_point& a, jubjub_point& b);
    static jubjub_point montgomery_double(jubjub_point& p);

    jubjub_point scalar_mul(bn254fr_class& x);
    jubjub_point scalar_mul_extend(bn254fr_class& x1, bn254fr_class& x2);

    jubjub_point to_montgomery();
    jubjub_point to_twisted_edward();

    bn254fr_class x, y;
};


// ------------------------------------------------------------

struct jubjub_point_vec {
    // Twisted Edwards Form (standard)
    // Equation: ax^2 + y^2 = 1 + dx^2y^2
    // Parameters: a = 168700, d = 168696
    // Generator:  (995203441582195749578291179787384436505546430278305826713579947235728471134, 5472060717959818805561601436314318772137091100104008585924551046643952123905)
    // Base Point: (5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203)
    const static vbn254fr_constant one;
    const static vbn254fr_constant a;
    const static vbn254fr_constant d;

    // Montgomery Form
    // Equation: By^2 = x^3 + A x^2 + x
    // Parameters: A = 168698, B = 1
    // Generator:  (7, 4258727773875940690362607550498304598101071202821725296872974770776423442226)
    // Base Point: (7117928050407583618111176421555214756675765419608405867398403713213306743542, 14577268218881899420966779687690205425227431577728659819975198491127179315626)
    const static vbn254fr_constant A;
    const static vbn254fr_constant two_A;

    static void assert_equal(const jubjub_point_vec& p, const jubjub_point_vec& q);

    static jubjub_point_vec mux(const vbn254fr_class& cond,
                                const jubjub_point_vec& b0, const jubjub_point_vec& b1);
    static jubjub_point_vec mux2(const vbn254fr_class& s0, const vbn254fr_class& s1,
                                 const jubjub_point_vec& b0, const jubjub_point_vec& b1,
                                 const jubjub_point_vec& b2, const jubjub_point_vec& b3);

    static jubjub_point_vec twisted_edward_add(const jubjub_point_vec& a, const jubjub_point_vec& b);
    static jubjub_point_vec montgomery_double(const jubjub_point_vec& p);

    jubjub_point_vec scalar_mul(const vbn254fr_class& x) const;
    jubjub_point_vec scalar_mul_extend(const vbn254fr_class& x1, const vbn254fr_class& x2) const;

    jubjub_point_vec to_montgomery() const;
    jubjub_point_vec to_twisted_edward() const;

    vbn254fr_class x, y;
};

} // namespace ligetron;

#endif