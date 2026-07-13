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

/*
 * Definitions of elliptic curve coordinates.
 */

#ifndef __LIGETRON_EC_DETAIL_COORDINATES_HPP__
#define __LIGETRON_EC_DETAIL_COORDINATES_HPP__

#include <ligetron/ff/field_element.h>
#include <ligetron/bn254fr_class.h>


namespace ligetron::ec::detail {


template <typename FieldElement>
class affine_coordinate {
public:
    affine_coordinate() = default;

    template <typename X, typename Y>
    requires (std::constructible_from<FieldElement, X> &&
              std::constructible_from<FieldElement, Y>)
    affine_coordinate(X && px, Y && py):
        x_(std::forward<X>(px)), y_(std::forward<Y>(py)) {}

    const FieldElement& x() const { return x_; }
    const FieldElement& y() const { return y_; }

    FieldElement& x() { return x_; }
    FieldElement& y() { return y_; }

    static bool eq(const affine_coordinate& p1,
                   const affine_coordinate& p2) {
        auto x_eq = FieldElement::eqz(p1.x_ - p2.x_);
        auto y_eq = FieldElement::eqz(p1.y_ - p2.y_);

        auto x_eq_u64 = witness_cast_u64(x_eq.get_u64());
        bn254fr_assert_equal_u64(x_eq.data(), x_eq_u64);
        auto y_eq_u64 = witness_cast_u64(y_eq.get_u64());
        bn254fr_assert_equal_u64(y_eq.data(), y_eq_u64);

        return x_eq_u64 && y_eq_u64;
    }

    static affine_coordinate mux(const bn254fr_class &c,
                                 const affine_coordinate &p1,
                                 const affine_coordinate &p2) {
        auto x = FieldElement::mux(c, p1.x(), p2.x());
        auto y = FieldElement::mux(c, p1.y(), p2.y());
        return affine_coordinate{x, y};
    }

    static affine_coordinate add(const affine_coordinate &p1,
                                 const affine_coordinate &p2) {
        return affine_coordinate{p1.x() + p2.x(), p1.y() + p2.y()};
    }

private:
    FieldElement x_, y_;
};


}


#endif // __LIGETRON_EC_DETAIL_COORDINATES_HPP__
