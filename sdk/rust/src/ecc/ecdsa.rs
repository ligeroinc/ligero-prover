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

//! ECDSA signature verification.
//!
//! ## Overview
//!
//! Works over any [`AffineCurve`]; P-256 and secp256k1 are provided. All wire values are
//! big-endian, matching SEC1.
use super::coordinates::Affine;
use super::curve::AffineCurve;
use crate::bn254fr::{land_all, lnot, Bn254Fr};
use crate::bn254fr_bigint::Bn254FrBigint;
use crate::ff::FieldElement;

/// Verifies ECDSA signatures against a fixed public key.
pub struct EcdsaContext<C: AffineCurve> {
    curve: C,
    pubkey: Affine<C::Base>,
}

impl<C: AffineCurve + Default> EcdsaContext<C> {
    /// Field element width in bytes.
    pub const FIELD_BYTES: usize = C::BASE_FIELD_BYTES;
    /// Scalar width in bytes, and therefore the digest width `verify_digest` consumes.
    pub const SCALAR_BYTES: usize = C::SCALAR_FIELD_BYTES;
    /// Uncompressed public key width: `X || Y`.
    pub const PUBKEY_BYTES: usize = 2 * Self::FIELD_BYTES;
    /// Signature width: `r || s`.
    pub const SIGNATURE_BYTES: usize = 2 * Self::SCALAR_BYTES;

    /// Binds to an uncompressed public key `X || Y`, big-endian.
    ///
    /// The key is untrusted: it is checked against the curve equation inside
    /// [`EcdsaContext::verify_digest`], and that verdict gates the result.
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        assert_eq!(
            pubkey.len(),
            Self::PUBKEY_BYTES,
            "ECDSA public key must be {} bytes",
            Self::PUBKEY_BYTES
        );
        Self::from_coords(&pubkey[..Self::FIELD_BYTES], &pubkey[Self::FIELD_BYTES..])
    }

    /// Binds to separate big-endian `X` and `Y` coordinates.
    ///
    /// Use this when the coordinates live in distinct buffers, e.g. as separate witnesses.
    pub fn from_coords(x_bytes: &[u8], y_bytes: &[u8]) -> Self {
        assert_eq!(x_bytes.len(), Self::FIELD_BYTES, "bad X coordinate width");
        assert_eq!(y_bytes.len(), Self::FIELD_BYTES, "bad Y coordinate width");

        let mut x = FieldElement::<C::Base>::zero();
        let mut y = FieldElement::<C::Base>::zero();
        x.import_bytes_big(x_bytes);
        y.import_bytes_big(y_bytes);

        Self {
            curve: C::default(),
            pubkey: Affine::new(x, y),
        }
    }

    /// The public key this context verifies against.
    pub fn pubkey(&self) -> &Affine<C::Base> {
        &self.pubkey
    }

    /// Verifies a signature over an already-computed digest, big-endian.
    ///
    /// ECDSA fixes no message hash — the choice is an ecosystem convention (SHA-256 for
    /// Bitcoin and TLS, keccak256 for Ethereum and TRON). `digest` must be exactly
    /// [`SCALAR_BYTES`](Self::SCALAR_BYTES) long; for a wider hash pass only the leading
    /// `SCALAR_BYTES` bytes, per SEC1 §4.1.4.`
    pub fn verify_digest(&self, sig: &[u8], digest: &[u8]) -> Bn254Fr {
        assert_eq!(
            sig.len(),
            Self::SIGNATURE_BYTES,
            "ECDSA signature must be {} bytes",
            Self::SIGNATURE_BYTES
        );
        assert_eq!(
            digest.len(),
            Self::SCALAR_BYTES,
            "ECDSA digest must be {} bytes",
            Self::SCALAR_BYTES
        );

        let pubkey_valid = self.curve.on_curve(&self.pubkey);

        let (r_bytes, s_bytes) = sig.split_at(Self::SCALAR_BYTES);

        // r and s must lie in [1, n-1].
        let mut upper_bound = Bn254FrBigint::new();
        upper_bound.set_bytes_big(C::ORDER_BE);

        let mut r_storage = Bn254FrBigint::new();
        let mut s_storage = Bn254FrBigint::new();
        r_storage.set_bytes_big(r_bytes);
        s_storage.set_bytes_big(s_bytes);

        let r_is_zero = r_storage.eqz();
        let r_is_small = Bn254FrBigint::lt(&r_storage, &upper_bound);
        let s_is_zero = s_storage.eqz();
        let s_is_small = Bn254FrBigint::lt(&s_storage, &upper_bound);

        let r_not_zero = lnot(&r_is_zero);
        let s_not_zero = lnot(&s_is_zero);
        let rs_valid = land_all(&[&r_not_zero, &s_not_zero, &r_is_small, &s_is_small]);

        // Substitute 1 for an out-of-range r or s so the inversion below cannot divide by
        // zero. The substitution is invisible in the verdict because `rs_valid` already
        // records the failure.
        let imported_r = FieldElement::<C::Scalar>::from_bigint(r_storage, false);
        let imported_s = FieldElement::<C::Scalar>::from_bigint(s_storage, false);
        let one = FieldElement::<C::Scalar>::one();
        let r = FieldElement::mux(&rs_valid, &one, &imported_r);
        let s = FieldElement::mux(&rs_valid, &one, &imported_s);

        let mut z = FieldElement::<C::Scalar>::zero();
        z.import_bytes_big(digest);
        z.reduce();

        let invs = s.inv();
        let u1 = &z * &invs;
        let u2 = &r * &invs;

        let p1 = self.curve.scalar_mul_generator(&u1);
        let p2 = self.curve.scalar_mul(&u2, &self.pubkey);

        // point_add does not handle p1 == p2, so that case is routed to point_double.
        // select(cond, a0, a1) picks a1 when cond is 1.
        let same = p1.eq(&p2);
        let psum = Affine::select(
            &same,
            &self.curve.point_add(&p1, &p2),
            &self.curve.point_double(&p1),
        );

        let is_not_inf = lnot(&self.curve.is_inf(&psum));

        // Reinterpret the x-coordinate in the scalar field: SEC1's "x mod n".
        let scalar_x = FieldElement::<C::Scalar>::from_other_field(&psum.x);
        scalar_x.reduce();
        let sig_valid = FieldElement::eq(&scalar_x, &r);

        land_all(&[&pubkey_valid, &rs_valid, &is_not_inf, &sig_valid])
    }

    /// Verifies a signature over `msg` hashed with SHA-256 — the binding used by Bitcoin and
    /// TLS.
    pub fn verify_sha256(&self, sig: &[u8], msg: &[u8]) -> Bn254Fr {
        assert_eq!(
            Self::SCALAR_BYTES,
            32,
            "verify_sha256 assumes a 256-bit scalar"
        );
        let digest = crate::sha2::sha256(msg);
        self.verify_digest(sig, &digest)
    }
}

/// ECDSA over NIST P-256.
pub type P256Ecdsa = EcdsaContext<super::curves::P256>;
/// ECDSA over secp256k1.
pub type Secp256k1Ecdsa = EcdsaContext<super::curves::Secp256k1>;
