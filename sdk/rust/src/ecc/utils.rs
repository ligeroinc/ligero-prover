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

//! Oblivious table lookup over curve points.

use super::coordinates::Affine;
use crate::bn254fr::Bn254Fr;
use crate::ff::PrimeField;

/// Selects `points[index]` where `index` is the little-endian integer formed by
/// `bits[0..num_bits]`.
///
/// Builds a balanced mux tree, so the selection reveals nothing about `index`. `points` must
/// hold `2^num_bits` entries.
pub fn point_select<F: PrimeField>(
    num_bits: usize,
    bits: &[Bn254Fr],
    points: &[Affine<F>],
) -> Affine<F> {
    if num_bits == 1 {
        Affine::select(&bits[0], &points[0], &points[1])
    } else {
        let half = 1usize << (num_bits - 1);
        let lo = point_select(num_bits - 1, bits, points);
        let hi = point_select(num_bits - 1, bits, &points[half..]);
        Affine::select(&bits[num_bits - 1], &lo, &hi)
    }
}

/// Two-dimensional variant: `xbits` picks the column, `ybits` the row, of a row-major
/// `2^num_bits × 2^num_bits` table.
pub fn point_select_2d<F: PrimeField>(
    num_bits: usize,
    xbits: &[Bn254Fr],
    ybits: &[Bn254Fr],
    points: &[Affine<F>],
) -> Affine<F> {
    let stride = 1usize << num_bits;
    let rows: Vec<Affine<F>> = (0..stride)
        .map(|i| point_select(num_bits, xbits, &points[i * stride..]))
        .collect();
    point_select(num_bits, ybits, &rows)
}
