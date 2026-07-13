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

#include <cassert>
#include <cstddef>
#include <ligetron/bn254fr_class.h>
#include <vector>

namespace ligetron::ecc {

template <typename Point>
Point point_select(size_t num_bits, const bn254fr_class* bits, const Point* points) {
    if (num_bits == 1) {
        return Point::select(bits[0], points[0], points[1]);
    } else {
        const size_t half = 1u << (num_bits - 1);
        auto lo = point_select(num_bits - 1, bits, points);
        auto hi = point_select(num_bits - 1, bits, points + half);
        return Point::select(bits[num_bits - 1], lo, hi);
    }
}

template <typename Point>
Point point_select_2d(size_t num_bits, const bn254fr_class* xbits, const bn254fr_class* ybits,
                      const Point* points) {
    const size_t stride = 1u << num_bits;
    std::vector<Point> tmp;
    for (size_t i = 0; i < stride; i++) {
        tmp.push_back(point_select(num_bits, xbits, points + i * stride));
    }
    return point_select(num_bits, ybits, tmp.data());
}

} // namespace ligetron::ecc
