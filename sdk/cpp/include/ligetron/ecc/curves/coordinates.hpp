/*
 * Copyright (C) 2023-2026 Ligero, Inc.
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

#pragma once

#include <ligetron/bn254fr_class.h>
#include <ligetron/ff/concepts.h>

namespace ligetron::ecc::curves {

template <typename Field>
struct projective_coordinate;

template <typename Field>
struct extended_coordinate;

template <typename Field>
struct affine_coordinate {
    Field x, y;

    bn254fr_class operator==(const affine_coordinate& o) const {
        auto eqx = Field::eq(x, o.x);
        auto eqy = Field::eq(y, o.y);
        bn254fr_class out;
        bn254fr_land_checked(out.data(), eqx.data(), eqy.data());
        return out;
    }

    static affine_coordinate select(const bn254fr_class& cond,
                                    const affine_coordinate& a0, const affine_coordinate& a1);
    
    projective_coordinate<Field> to_projective() const;
    extended_coordinate<Field> to_extended() const;
};

template <typename Field>
struct projective_coordinate {
    Field x, y, z;

    bool operator==(const projective_coordinate& o) const {
        return Field::eq(x, o.x) & Field::eq(y, o.y) & Field::eq(z, o.z);
    }

    projective_coordinate operator-() const {
        Field neg_y;
        Field::neg(neg_y, y);
        return projective_coordinate{x, std::move(neg_y), z};
    }
    
    static projective_coordinate select(const bn254fr_class& cond, const projective_coordinate& a0,
                                        const projective_coordinate& a1);
    affine_coordinate<Field> to_affine() const;
    extended_coordinate<Field> to_extended() const;
};

template <typename Field>
struct extended_coordinate {
    Field x, y, z, t;

    static extended_coordinate select(const bn254fr_class& cond, const extended_coordinate& a0,
                                      const extended_coordinate& a1);
    affine_coordinate<Field> to_affine() const;
    projective_coordinate<Field> to_projective() const;
};

// ------------------------------------------------------------

template <typename Field>
affine_coordinate<Field> affine_coordinate<Field>::select(const bn254fr_class& cond,
                                                          const affine_coordinate& a0,
                                                          const affine_coordinate& a1) {
    return affine_coordinate<Field>{Field::mux(cond, a0.x, a1.x), Field::mux(cond, a0.y, a1.y)};
}

template <typename Field>
projective_coordinate<Field> affine_coordinate<Field>::to_projective() const {
    auto eqz = Field::eqz(x) && Field::eqz(y);
    return projective_coordinate<Field>::select(
        eqz, projective_coordinate{x, y, Field{1u}},
        projective_coordinate{Field{0}, Field{1}, Field{0}});
}

template <typename Field>
extended_coordinate<Field> affine_coordinate<Field>::to_extended() const {
    return extended_coordinate<Field>{x, y, Field{1u}, x * y};
}

// ------------------------------------------------------------

template <typename Field>
projective_coordinate<Field> projective_coordinate<Field>::select(const bn254fr_class& cond,
                                                                  const projective_coordinate& a0,
                                                                  const projective_coordinate& a1) {
    return projective_coordinate<Field>{Field::mux(cond, a0.x, a1.x), Field::mux(cond, a0.y, a1.y),
                                        Field::mux(cond, a0.z, a1.z)};
}

template <typename Field>
affine_coordinate<Field> projective_coordinate<Field>::to_affine() const {
    Field invz;
    auto eqz = Field::eqz(z);
    Field::inv(invz, Field::mux(eqz, z, Field{1}));
    return affine_coordinate<Field>{Field::mux(eqz, x * invz, z), Field::mux(eqz, y * invz, z)};
}

template <typename Field>
extended_coordinate<Field> projective_coordinate<Field>::to_extended() const {
    Field invz;
    Field::inv(invz, z);
    return extended_coordinate<Field>{x, y, z, x * y * invz};
}

// ------------------------------------------------------------

template <typename Field>
extended_coordinate<Field> extended_coordinate<Field>::select(const bn254fr_class& cond,
                                                              const extended_coordinate& a0,
                                                              const extended_coordinate& a1) {
    return extended_coordinate<Field>{Field::mux(cond, a0.x, a1.x), Field::mux(cond, a0.y, a1.y),
                                      Field::mux(cond, a0.z, a1.z), Field::mux(cond, a0.t, a1.t)};
}

template <typename Field>
affine_coordinate<Field> extended_coordinate<Field>::to_affine() const {
    Field invz;
    Field::inv(invz, z);
    return affine_coordinate<Field>{x * invz, y * invz};
}

template <typename Field>
projective_coordinate<Field> extended_coordinate<Field>::to_projective() const {
    return projective_coordinate<Field>{x, y, z};
}

} // namespace ligetron::ecc::curves
