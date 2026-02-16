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

private:
    FieldElement x_, y_;
};


}


#endif // __LIGETRON_EC_DETAIL_COORDINATES_HPP__
