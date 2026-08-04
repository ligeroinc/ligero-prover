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

//! EdDSA signature verification (RFC 8032).
//!
//! ## Overview
//!
//! Ed25519 is the only instantiation today. All wire values are little-endian, which is the
//! opposite of [`super::ecdsa`] — RFC 8032 and SEC1 disagree, and the difference is easy to
//! get wrong.
//!
//! Not to be confused with [`crate::eddsa`], which is EdDSA over BabyJubJub with a Poseidon
//! challenge.

use super::coordinates::Affine;
use super::curve::AffineCurve;
use super::curves::Ed25519;
use super::host;
use crate::bn254fr::{
    eq_checked, eqz_checked, land_all, land_checked, lor_checked, Bn254Fr,
};
use crate::bn254fr_bigint::Bn254FrBigint;
use crate::ff::{FieldElement, PrimeField};
use crate::uint256::Uint256;

/// Per-curve EdDSA parameters fixed by RFC 8032.
///
/// Ed448 is documented here only as the contrast that shows which constants are genuinely
/// per-curve: it would need SHAKE256 with a 114-byte output, a 57-byte encoding over a 56-byte
/// field, a different pruning rule, and a non-empty domain prefix.
pub trait EddsaParams: 'static {
    type Curve: AffineCurve + Default;

    /// RFC 8032's `b/8`: the width of a point encoding, a secret seed, and each half of a
    /// signature. Deliberately not derived from the base field — they coincide at 32 for
    /// Ed25519 but not for Ed448.
    const ENCODED_BYTES: usize;

    /// Output width of `H()`. 64 for Ed25519 (SHA-512).
    const HASH_BYTES: usize;

    /// `H()`. Writes exactly [`HASH_BYTES`](Self::HASH_BYTES) bytes.
    fn hash(out: &mut [u8], input: &[u8]);

    /// `dom()`: the domain-separation prefix hashed ahead of `R || A || M`. Empty for pure
    /// Ed25519, which is the exception rather than the rule.
    fn domain_prefix() -> &'static [u8] {
        &[]
    }

    /// RFC 8032 §5.1.5 step 2, "prune the buffer": clear the low three bits so the scalar is a
    /// multiple of the cofactor 8, clear the top bit, and set the second-highest.
    fn clamp_scalar(s: &mut [u8]);
}

/// Ed25519 parameters: SHA-512, 32-byte encodings, no domain prefix.
pub struct Ed25519Params;

impl EddsaParams for Ed25519Params {
    type Curve = Ed25519;

    const ENCODED_BYTES: usize = 32;
    const HASH_BYTES: usize = 64;

    fn hash(out: &mut [u8], input: &[u8]) {
        assert_eq!(out.len(), Self::HASH_BYTES);
        let d = crate::sha2::sha512(input);
        out.copy_from_slice(&d);
    }

    fn clamp_scalar(s: &mut [u8]) {
        assert_eq!(s.len(), Self::ENCODED_BYTES);
        let hi = Self::ENCODED_BYTES - 1;
        s[0] &= 248;
        s[hi] &= 63;
        s[hi] |= 64;
    }
}

type Base<P> = <<P as EddsaParams>::Curve as AffineCurve>::Base;
type Scalar<P> = <<P as EddsaParams>::Curve as AffineCurve>::Scalar;

/// Verifies EdDSA signatures against a fixed public key.
pub struct EddsaContext<P: EddsaParams> {
    curve: P::Curve,
    bn_p: Bn254FrBigint,
    enc_pubkey: Vec<u8>,
    pubkey: Affine<Base<P>>,
    pubkey_valid: Bn254Fr,
}

impl<P: EddsaParams> EddsaContext<P> {
    /// Compressed public key width.
    pub const PUBKEY_BYTES: usize = P::ENCODED_BYTES;
    /// Signature width: `Enc(R) || S`.
    pub const SIGNATURE_BYTES: usize = 2 * P::ENCODED_BYTES;
    /// Secret seed width.
    pub const SEED_BYTES: usize = P::ENCODED_BYTES;
    /// Point encoding width.
    pub const ENCODED_POINT_BYTES: usize = P::ENCODED_BYTES;
    /// RFC 8032's `b`: `y` occupies bits `0..b-2` and the sign of `x` sits in bit `b-1`.
    pub const ENCODED_POINT_BITS: usize = 8 * P::ENCODED_BYTES;
    /// Base field width in bytes.
    pub const BASE_FIELD_BYTES: usize = <P::Curve as AffineCurve>::BASE_FIELD_BYTES;

    /// Binds to a compressed public key received from the wire.
    ///
    /// The key is untrusted: [`EddsaContext::point_decompress`] establishes whether it is a
    /// well-formed curve point, and that verdict gates every [`EddsaContext::verify`] result.
    pub fn from_pubkey(pk: &[u8]) -> Self {
        assert_eq!(
            pk.len(),
            Self::PUBKEY_BYTES,
            "EdDSA public key must be {} bytes",
            Self::PUBKEY_BYTES
        );

        let curve = P::Curve::default();
        let bn_p = Self::init_modulus();

        let (pubkey, pubkey_valid) = Self::decompress(&curve, &bn_p, pk);

        Self {
            curve,
            bn_p,
            enc_pubkey: pk.to_vec(),
            pubkey,
            pubkey_valid,
        }
    }

    /// Derives the key pair from a secret seed per RFC 8032 §5.1.5 and binds to the derived
    /// public key.
    pub fn from_seed(seed: &[u8]) -> Self {
        assert_eq!(
            seed.len(),
            Self::SEED_BYTES,
            "EdDSA seed must be {} bytes",
            Self::SEED_BYTES
        );

        let mut h = vec![0u8; P::HASH_BYTES];
        P::hash(&mut h, seed);
        P::clamp_scalar(&mut h[..P::ENCODED_BYTES]);

        let mut s = FieldElement::<Scalar<P>>::zero();
        s.import_bytes_little(&h[..P::ENCODED_BYTES]);

        let curve = P::Curve::default();
        let pk = curve.scalar_mul_generator(&s);
        let enc = Self::point_encode(&pk);
        let valid = curve.on_curve(&pk);

        Self {
            bn_p: Self::init_modulus(),
            enc_pubkey: enc,
            pubkey: pk,
            pubkey_valid: valid,
            curve,
        }
    }

    /// The compressed public key this context verifies against.
    ///
    /// Assert it against a public input to prove ownership of a seed without deriving the key
    /// a second time.
    pub fn encoded_pubkey(&self) -> &[u8] {
        &self.enc_pubkey
    }

    /// Loads the base field modulus used by the decompression range checks.
    ///
    /// Needed on both construction paths: `verify` decompresses `R` even when the public key
    /// was derived from a seed.
    fn init_modulus() -> Bn254FrBigint {
        let mut bn_p = Bn254FrBigint::new();
        bn_p.set_bytes_big(<P::Curve as AffineCurve>::BASE_FIELD_BE);
        bn_p
    }

    /// Recovers a point from its compressed encoding and returns a well-formedness verdict.
    ///
    /// The host decompression is untrusted, so the circuit re-establishes everything: the
    /// error code is zero, both coordinates are below `p`, the point satisfies the curve
    /// equation, and the recovered coordinates re-encode to exactly the input bits.
    pub fn point_decompress(&self, bytes: &[u8]) -> (Affine<Base<P>>, Bn254Fr) {
        Self::decompress(&self.curve, &self.bn_p, bytes)
    }

    fn decompress(
        curve: &P::Curve,
        bn_p: &Bn254FrBigint,
        bytes: &[u8],
    ) -> (Affine<Base<P>>, Bn254Fr) {
        assert_eq!(bytes.len(), Self::ENCODED_POINT_BYTES);

        let nb = Self::BASE_FIELD_BYTES;
        let mut x_bytes = vec![0u8; nb];
        let mut y_bytes = vec![0u8; nb];
        let errc = host::point_decompress(
            <P::Curve as AffineCurve>::CURVE_TYPE,
            &mut x_bytes,
            &mut y_bytes,
            bytes,
        );
        let errc_fr = Bn254Fr::from_u32(errc as u32);

        // Bit-level consistency: enc[b-1] is the sign of x, enc[0..b-2] is y.
        let mut enc_storage = Uint256::new();
        let mut x_storage = Uint256::new();
        let mut y_storage = Uint256::new();
        enc_storage.set_bytes_little(bytes);
        x_storage.set_bytes_little(&x_bytes);
        y_storage.set_bytes_little(&y_bytes);

        let enc_bits = enc_storage.to_bits();
        let x_bits = x_storage.to_bits();
        let y_bits = y_storage.to_bits();

        let mut bit_eq = Bn254Fr::new();
        eq_checked(&mut bit_eq, &x_bits[0], &enc_bits[Self::ENCODED_POINT_BITS - 1]);
        for i in 0..Self::ENCODED_POINT_BITS - 1 {
            let mut i_eq = Bn254Fr::new();
            eq_checked(&mut i_eq, &y_bits[i], &enc_bits[i]);
            let mut land = Bn254Fr::new();
            land_checked(&mut land, &bit_eq, &i_eq);
            bit_eq = land;
        }

        // Both coordinates must be canonical, i.e. strictly below p.
        let mut bn_x = Bn254FrBigint::new();
        let mut bn_y = Bn254FrBigint::new();
        bn_x.set_bytes_little(&x_bytes);
        bn_y.set_bytes_little(&y_bytes);

        let x_in_range = Bn254FrBigint::lt(&bn_x, bn_p);
        let y_in_range = Bn254FrBigint::lt(&bn_y, bn_p);

        let point = Affine::new(
            FieldElement::<Base<P>>::from_bigint(bn_x, false),
            FieldElement::<Base<P>>::from_bigint(bn_y, false),
        );

        let is_valid_point = curve.on_curve(&point);

        let mut errc_zero = Bn254Fr::new();
        eqz_checked(&mut errc_zero, &errc_fr);

        let verdict = land_all(&[
            &errc_zero,
            &x_in_range,
            &y_in_range,
            &is_valid_point,
            &bit_eq,
        ]);

        (point, verdict)
    }

    /// Encodes a point: `y` little-endian with the low bit of `x` folded into the top bit
    /// (RFC 8032 §5.1.2). Inverse of [`EddsaContext::point_decompress`].
    pub fn point_encode(p: &Affine<Base<P>>) -> Vec<u8> {
        let x_bits = p.x.to_bits();
        let y_bits = p.y.to_bits();

        let mut enc_bits: Vec<Bn254Fr> = Vec::with_capacity(Base::<P>::NUM_ROUNDED_BITS);
        for bit in y_bits.iter().take(Self::ENCODED_POINT_BITS - 1) {
            enc_bits.push(bit.clone());
        }

        // y < p < 2^(b-1), so bit b-1 of y is always zero and the OR just deposits the sign
        // of x there.
        let mut top = Bn254Fr::new();
        lor_checked(&mut top, &y_bits[Self::ENCODED_POINT_BITS - 1], &x_bits[0]);
        enc_bits.push(top);

        let enc = Uint256::from_bits(&enc_bits);
        enc.to_bytes_little()[..Self::ENCODED_POINT_BYTES].to_vec()
    }

    /// Verifies `S·G == R + H(dom || R || A || M)·A`.
    pub fn verify(&self, sig: &[u8], msg: &[u8]) -> Bn254Fr {
        assert_eq!(
            sig.len(),
            Self::SIGNATURE_BYTES,
            "EdDSA signature must be {} bytes",
            Self::SIGNATURE_BYTES
        );

        // RFC 8032 §3.4: a signature is ENC(R) || S, each exactly b/8 bytes.
        let (r_bytes, s_bytes) = sig.split_at(Self::ENCODED_POINT_BYTES);

        let (r_point, r_valid) = self.point_decompress(r_bytes);

        // S must be below the group order.
        let mut upper_bound = Bn254FrBigint::new();
        upper_bound.set_bytes_big(<P::Curve as AffineCurve>::ORDER_BE);
        let mut s_storage = Bn254FrBigint::new();
        s_storage.set_bytes_little(s_bytes);
        let s_valid = Bn254FrBigint::lt(&s_storage, &upper_bound);
        let s = FieldElement::<Scalar<P>>::from_bigint(s_storage, false);

        // Challenge scalar k = H(dom || R || A || M), reduced mod the group order on import.
        let dom = P::domain_prefix();
        let mut input =
            Vec::with_capacity(dom.len() + 2 * Self::ENCODED_POINT_BYTES + msg.len());
        input.extend_from_slice(dom);
        input.extend_from_slice(r_bytes);
        input.extend_from_slice(&self.enc_pubkey);
        input.extend_from_slice(msg);

        let mut digest = vec![0u8; P::HASH_BYTES];
        P::hash(&mut digest, &input);

        let mut k = FieldElement::<Scalar<P>>::zero();
        k.import_bytes_little(&digest);

        let lhs = self.curve.scalar_mul_generator(&s);
        let rhs = self
            .curve
            .point_add(&r_point, &self.curve.scalar_mul(&k, &self.pubkey));

        let equation_holds = lhs.eq(&rhs);

        land_all(&[
            &self.pubkey_valid,
            &r_valid,
            &s_valid,
            &equation_holds,
        ])
    }
}

/// EdDSA over Ed25519.
pub type Ed25519Eddsa = EddsaContext<Ed25519Params>;

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §5.1.5 step 2, checked directly — no VM needed.
    #[test]
    fn clamp_scalar_matches_rfc8032() {
        let mut s = [0xffu8; 32];
        Ed25519Params::clamp_scalar(&mut s);
        assert_eq!(s[0], 0xf8, "low three bits must be cleared");
        assert_eq!(s[31], 0x7f, "top bit cleared, second-highest set");

        let mut z = [0x00u8; 32];
        Ed25519Params::clamp_scalar(&mut z);
        assert_eq!(z[0], 0x00);
        assert_eq!(z[31], 0x40, "second-highest bit must be set even from zero");
    }

    #[test]
    fn ed25519_widths() {
        assert_eq!(Ed25519Eddsa::PUBKEY_BYTES, 32);
        assert_eq!(Ed25519Eddsa::SIGNATURE_BYTES, 64);
        assert_eq!(Ed25519Eddsa::SEED_BYTES, 32);
        assert_eq!(Ed25519Eddsa::ENCODED_POINT_BITS, 256);
        // point_encode and point_decompress decompose through the base field's own bit width,
        // so the encoding width has to match it.
        assert_eq!(
            Ed25519Eddsa::ENCODED_POINT_BITS,
            <Ed25519 as AffineCurve>::Base::NUM_ROUNDED_BITS
        );
    }
}
