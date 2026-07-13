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
 * Generic generator point lookup table implementation
 */

#ifndef __LIGETRON_EC_DETAIL_GENERATOR_TABLE_HPP__
#define __LIGETRON_EC_DETAIL_GENERATOR_TABLE_HPP__

#include "concepts.hpp"
#include "coordinates.hpp"
#include <ligetron/bn254fr_class.h>


namespace ligetron::ec::detail {


/// Generator table definition
template <typename CurveDef>
concept GeneratorTableDef =
        requires(size_t window_index, size_t index) {

    typename CurveDef::point;

    { CurveDef::window_bit_size } ->
        std::convertible_to<size_t>;

    { CurveDef::table()[window_index][index] } ->
        std::convertible_to <typename CurveDef::point>;
};

/// Elliptic curve definition with provided generator table
template <typename CurveDef>
concept EllipticCurveDefWithGeneratorTable = requires {
    typename CurveDef::generator_table;
    requires GeneratorTableDef<typename CurveDef::generator_table>;
};

/// Helper class for definining generator tables.
/// Contains common definitions for table types and sizes.
/// Should be used as base class for table definitions.
template <typename Point, size_t WindowBitSize>
struct generator_table_def {
    static constexpr size_t window_bit_size = WindowBitSize;
    static constexpr size_t table_size = 2 << window_bit_size;

    using point = Point;
    using window_t = std::array<point, table_size>;
    using table_t = std::array<window_t, 256 / window_bit_size>;
};

/// Alias for generator table definition with affine coordinates
template <typename FieldElement, size_t WindowBitSize>
using affine_generator_table_def = generator_table_def <
    affine_coordinate<FieldElement>,
    WindowBitSize
>;

/// Generic generator table implementation
template <GeneratorTableDef TableDef>
struct generator_table {
    using point = typename TableDef::point;
    static constexpr size_t window_bit_size = TableDef::window_bit_size;
    static constexpr size_t window_size = 2 << (window_bit_size - 1);

    /// Performs oblivious table lookup for specified window index
    /// and index in window
    static point lookup(size_t window_index, bn254fr_class &index) {
        // decode index into array of selectors
        std::array<bn254fr_class, window_size> selectors;
        decompose_index(selectors, index);

        point zero;

        // the result is the sum of products of selectors and table items
        point sum;

        for (int i = 0; i < window_size; ++i) {
            auto p = TableDef::table()[window_index][i];
            auto mux_res = point::mux(selectors[i], zero, p);
            sum = point::add(sum, mux_res);
        }

        return sum;
    }

    /// Decomposes index into selector bits.
    /// Assumes selectors array is initialized with zeros.
    static void decompose_index(
            std::array<bn254fr_class, window_size> &selectors,
            bn254fr_class &index) {

        bn254fr_class bn254fr_index{index};
        bn254fr_class bn254fr_zero;

        bn254fr_class sum;      // sum of all selectors

        for (int i = 0; i < window_size; ++i) {
            // calculate value of selector without constraints
            if (i == bn254fr_index) {
                selectors[i].set_u32(1);
            } else {
                // selectors[i] should be previously initialized to zero
            }

            // add selectors[i] * (index - i) === 0 constraint
            bn254fr_class bn254fr_i{i};
            bn254fr_class index_minus_i;
            submod(index_minus_i, bn254fr_index, bn254fr_i);
            bn254fr_class mul_res;
            mulmod(mul_res, selectors[i], index_minus_i);
            bn254fr_class::assert_equal(mul_res, bn254fr_zero);

            addmod(sum, sum, selectors[i]);
        }

        // sum of all selectors must be 1
        bn254fr_class one{1};
        bn254fr_class::assert_equal(sum, one);
    }
};

}


#endif // __LIGETRON_EC_DETAIL_GENERATOR_TABLE_HPP__
