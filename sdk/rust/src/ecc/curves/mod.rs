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

//! Concrete curves.
//!
//! Each curve carries a 512 KB generator precompute table. The tables are referenced only from
//! their own curve's `scalar_mul_generator`, so link-time garbage collection drops the ones a
//! circuit does not use — a program that touches only Ed25519 does not pay for P-256.

pub mod gen_table;

pub mod ed25519;
pub mod p256;
pub mod secp256k1;

#[rustfmt::skip]
mod ed25519_precomp;
#[rustfmt::skip]
mod p256_precomp;
#[rustfmt::skip]
mod secp256k1_precomp;

pub use ed25519::{Ed25519, Ed25519Base, Ed25519Scalar};
pub use p256::{P256Base, P256Scalar, P256};
pub use secp256k1::{Secp256k1, Secp256k1Base, Secp256k1Scalar};

#[cfg(test)]
mod tests {
    use super::gen_table::{GEN_TABLE_ENTRIES, GEN_TABLE_TOTAL, GEN_TABLE_WINDOWS};
    use crate::ecc::curve::AffineCurve;

    /// The big-endian constants are duplicated data — the modulus also appears as a hex string
    /// in the `impl_prime_field!` call. This is exactly the kind of thing that silently drifts,
    /// so check the two agree.
    #[test]
    fn order_and_base_field_constants_match_moduli() {
        use crate::ff::PrimeField;

        fn as_hex(bytes: &[u8; 32]) -> String {
            format!(
                "0x{}",
                bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            )
        }

        assert_eq!(
            as_hex(super::P256::BASE_FIELD_BE),
            super::P256Base::MODULUS_STR
        );
        assert_eq!(as_hex(super::P256::ORDER_BE), super::P256Scalar::MODULUS_STR);

        assert_eq!(
            as_hex(super::Secp256k1::BASE_FIELD_BE),
            super::Secp256k1Base::MODULUS_STR
        );
        assert_eq!(
            as_hex(super::Secp256k1::ORDER_BE),
            super::Secp256k1Scalar::MODULUS_STR
        );

        assert_eq!(
            as_hex(super::Ed25519::BASE_FIELD_BE),
            super::Ed25519Base::MODULUS_STR
        );
        assert_eq!(
            as_hex(super::Ed25519::ORDER_BE),
            super::Ed25519Scalar::MODULUS_STR
        );
    }

    /// Row `j = 0` of every window must be the curve identity: `(0, 0)` for the Weierstrass
    /// curves, `(0, 1)` for Ed25519.
    #[test]
    fn window_zero_rows_are_the_identity() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1;

        for w in 0..GEN_TABLE_WINDOWS {
            let row = w * GEN_TABLE_ENTRIES;

            assert_eq!(super::p256_precomp::P256_G_PRECOMP[row], [zero, zero]);
            assert_eq!(
                super::secp256k1_precomp::SECP256K1_G_PRECOMP[row],
                [zero, zero]
            );
            assert_eq!(super::ed25519_precomp::ED25519_G_PRECOMP[row], [zero, one]);
        }
    }

    /// Row `j = 1` of window 0 is the generator itself.
    #[test]
    fn window_zero_row_one_is_the_generator() {
        // Ed25519 generator x, little-endian.
        let gx_le: [u8; 32] = {
            let mut b = [0u8; 32];
            let be =
                hex_to_bytes("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a");
            for (i, v) in be.iter().rev().enumerate() {
                b[i] = *v;
            }
            b
        };
        assert_eq!(super::ed25519_precomp::ED25519_G_PRECOMP[1][0], gx_le);
    }

    #[test]
    fn tables_have_the_expected_shape() {
        assert_eq!(super::p256_precomp::P256_G_PRECOMP.len(), GEN_TABLE_TOTAL);
        assert_eq!(
            super::secp256k1_precomp::SECP256K1_G_PRECOMP.len(),
            GEN_TABLE_TOTAL
        );
        assert_eq!(
            super::ed25519_precomp::ED25519_G_PRECOMP.len(),
            GEN_TABLE_TOTAL
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }
}
