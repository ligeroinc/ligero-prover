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

//! Shared access to the generator precompute tables.

use crate::bn254fr::Bn254Fr;
use crate::ecc::coordinates::Affine;
use crate::ecc::utils::point_select;
use crate::ff::{FieldElement, PrimeField};

/// Scalar bits consumed per window.
pub const GEN_TABLE_BITS: usize = 8;
/// Number of windows covering a 256-bit scalar.
pub const GEN_TABLE_WINDOWS: usize = 32;
/// Entries per window.
pub const GEN_TABLE_ENTRIES: usize = 1 << GEN_TABLE_BITS;
/// Total rows in a table.
pub const GEN_TABLE_TOTAL: usize = GEN_TABLE_WINDOWS * GEN_TABLE_ENTRIES;

/// A generator precompute table: row `w * 256 + j` is `[j * 2^(8w)] G`, each coordinate
/// 32 bytes little-endian.
pub type GenTable = [[[u8; 32]; 2]; GEN_TABLE_TOTAL];

/// Materialises window `w`, selects the entry addressed by `bits[8w..8w+8]`, and drops the
/// rest.
///
/// If a circuit calls `scalar_mul_generator` often enough for the repeated materialisation to
/// matter, memoise the windows inside the curve struct; that is a local change with no API
/// impact.
pub fn select_window<F: PrimeField>(raw: &'static GenTable, w: usize, bits: &[Bn254Fr]) -> Affine<F> {
    let base = w * GEN_TABLE_ENTRIES;
    let points: Vec<Affine<F>> = (0..GEN_TABLE_ENTRIES)
        .map(|j| {
            Affine::new(
                field_from_le_bytes::<F>(&raw[base + j][0]),
                field_from_le_bytes::<F>(&raw[base + j][1]),
            )
        })
        .collect();
    point_select(GEN_TABLE_BITS, &bits[w * GEN_TABLE_BITS..], &points)
}

/// Builds a field element from 32 little-endian bytes.
fn field_from_le_bytes<F: PrimeField>(bytes: &[u8; 32]) -> FieldElement<F> {
    let mut e = FieldElement::<F>::zero();
    e.import_bytes_little(bytes);
    e
}
