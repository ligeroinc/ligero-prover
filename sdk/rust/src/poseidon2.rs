/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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

//! Poseidon2 Hash Function for Ligetron
//!
//! ## Algorithm Details
//!
//! Poseidon2 uses a t=2 state size with:
//! - **External MDS Matrix**: [2, 1; 1, 2]
//! - **Internal MDS Matrix**: [2, 1; 1, 3]
//! - **Round Structure**: 8 full rounds, 56 partial rounds
//! - **S-box**: x^5 power function
//! ```
//!
//! ## Performance Considerations
//!
//! - **Byte Processing**: Data is processed in 31-byte chunks (field element size)
//! - **Padding**: Automatic padding applied to incomplete chunks

use crate::bn254fr::{Bn254Fr, addmod_checked, mulmod_checked};
use crate::vbn254fr::{VBn254Fr, addmod_vec, mulmod_vec};
use crate::poseidon2_constant::{
    POSEIDON2_T2_RC_STR, POSEIDON2_T2_RC_VEC,
    POSEIDON2_BN254_RF, POSEIDON2_BN254_RP, POSEIDON2_BN254_T
};

/// Constants for Poseidon2 BN254 with t=2 (state size 2)
pub struct Poseidon2Params {
    pub r_f: usize,  // Full rounds
    pub r_p: usize,  // Partial rounds
    pub t: usize,    // State size
}

impl Default for Poseidon2Params {
    fn default() -> Self {
        Poseidon2Params {
            r_f: POSEIDON2_BN254_RF,
            r_p: POSEIDON2_BN254_RP,
            t: POSEIDON2_BN254_T,
        }
    }
}

/// Poseidon2 hash context for BN254 field elements (t=2)
pub struct Poseidon2Context {
    state: [Bn254Fr; 2],
    params: Poseidon2Params,
    buffer: Vec<u8>,
    buffer_len: usize,
    temp: Bn254Fr,
    rc: Vec<Bn254Fr>,
}

impl Poseidon2Context {
    pub fn new() -> Self {
        let rc = POSEIDON2_T2_RC_STR.iter()
            .map(|&s| Bn254Fr::from_str(s))
            .collect();

        let ctx = Poseidon2Context {
            state: [
                Bn254Fr::from_u32(0),
                Bn254Fr::from_u32(0),
            ],
            params: Poseidon2Params::default(),
            buffer: vec![0u8; 31],
            buffer_len: 0,
            temp: Bn254Fr::new(),
            rc,
        };
        ctx
    }

    // resets the internal context state
    pub fn digest_init(&mut self) {
        self.state[0] = Bn254Fr::from_u32(0);
        self.state[1] = Bn254Fr::from_u32(0);
        self.buffer_len = 0;
        for i in 0..31 {
            self.buffer[i] = 0;
        }
    }

    pub fn digest_update(&mut self, data: &Bn254Fr) {
        self.state[0].addmod_checked(data);
        self.permute();
    }

    pub fn digest_update_bytes(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut remaining = data.len();

        // Process 31-byte chunks
        while remaining >= 31 {
            let chunk = &data[offset..offset + 31];
            self.temp.set_bytes_big(chunk);
            self.state[0].addmod_checked(&self.temp);
            self.permute();
            offset += 31;
            remaining -= 31;
        }

        // Handle remaining bytes
        for &byte in &data[offset..] {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len >= 31 {
                self.temp.set_bytes_big(&self.buffer[..31]);
                self.state[0].addmod_checked(&self.temp);
                self.permute();
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize the hash computation and get the result
    pub fn digest_final(&mut self) -> Bn254Fr {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        while self.buffer_len < 31 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        self.temp.set_bytes_big(&self.buffer[..31]);
        self.state[0].addmod_checked(&self.temp);
        self.permute();

        self.state[0].clone()
    }

    /// Internal permutation function for Poseidon2
    fn permute(&mut self) {
        // External MDS multiplication
        self.multiply_external_mds();

        let mut round = 0;

        // First half of full rounds
        for _ in 0..4 {
            self.add_round_constants(round);
            self.sbox_full();
            self.multiply_external_mds();
            round += 1;
        }

        // Partial rounds
        for _ in 0..self.params.r_p {
            self.add_round_constants_partial(round);
            self.sbox_partial();
            self.multiply_internal_mds();
            round += 1;
        }

        // Second half of full rounds
        for _ in 0..4 {
            self.add_round_constants(round);
            self.sbox_full();
            self.multiply_external_mds();
            round += 1;
        }
    }

    /// Add round constants to the state (full rounds)
    fn add_round_constants(&mut self, round: usize) {
        self.state[0].addmod_checked(&self.rc[round * 2]);
        self.state[1].addmod_checked(&self.rc[round * 2 + 1]);
    }

    /// Add round constants to the state (partial rounds - only first element)
    fn add_round_constants_partial(&mut self, round: usize) {
        self.state[0].addmod_checked(&self.rc[round * 2]);
    }

    /// Apply S-box (x^5) to all elements
    fn sbox_full(&mut self) {
        self.state[0] = self.pow5(&self.state[0]);
        self.state[1] = self.pow5(&self.state[1]);
    }

    /// Apply S-box (x^5) to first element only
    fn sbox_partial(&mut self) {
        self.state[0] = self.pow5(&self.state[0]);
    }

    /// Compute x^5 for field element
    fn pow5(&self, x: &Bn254Fr) -> Bn254Fr {
        let mut x2 = Bn254Fr::new();
        let mut result = Bn254Fr::new();
        mulmod_checked(&mut x2, x, x);          // x^2
        mulmod_checked(&mut result, &x2, &x2);  // x^4
        result.mulmod_checked(x);    // x^5 = x^4 * x
        result
    }

    /// External MDS matrix multiplication for t=2
    /// External MDS = [2, 1]
    ///                [1, 2]
    fn multiply_external_mds(&mut self) {
        addmod_checked(&mut self.temp, &self.state[0], &self.state[1]);
        self.state[0].addmod_checked(&self.temp);
        self.state[1].addmod_checked(&self.temp);
    }

    /// Internal MDS matrix multiplication for t=2
    /// Internal MDS = [2, 1]
    ///                [1, 3]
    fn multiply_internal_mds(&mut self) {
        addmod_checked(&mut self.temp, &self.state[0], &self.state[1]);
        self.state[0].addmod_checked(&self.temp);
        self.temp.addmod_checked(&self.state[1]);
        self.state[1].addmod_checked(&self.temp);
    }
}

/// Poseidon2 hash context for vectorized BN254 field elements (t=2)
pub struct VPoseidon2Context {
    state: [VBn254Fr; 2],
    params: Poseidon2Params,
    buffer: Vec<u8>,
    buffer_len: usize,
    temp: VBn254Fr,
}

impl VPoseidon2Context {
    pub fn new() -> Self {
        let ctx = VPoseidon2Context {
            state: [
                VBn254Fr::from_ui_scalar(0),
                VBn254Fr::from_ui_scalar(0),
            ],
            params: Poseidon2Params::default(),
            buffer: vec![0u8; 31],
            buffer_len: 0,
            temp: VBn254Fr::new(),
        };
        ctx
    }

    // resets the internal context state
    pub fn digest_init(&mut self) {
        self.state[0].set_ui_scalar(0);
        self.state[1].set_ui_scalar(0);
        self.buffer_len = 0;
        for i in 0..31 {
            self.buffer[i] = 0;
        }
    }

    pub fn digest_update(&mut self, data: &VBn254Fr) {
        // Add the data to state[0] and perform permutation
        self.state[0].addmod_vec(data);
        self.permute();
    }

    pub fn digest_update_bytes(&mut self, data: &[u8]) {
        let mut offset = 0;
        let mut remaining = data.len();

        // Process 31-byte chunks
        while remaining >= 31 {
            let chunk = &data[offset..offset + 31];
            self.temp.set_bytes_scalar(chunk);
            self.state[0].addmod_vec(&self.temp);
            self.permute();
            offset += 31;
            remaining -= 31;
        }

        // Handle remaining bytes
        for &byte in &data[offset..] {
            self.buffer[self.buffer_len] = byte;
            self.buffer_len += 1;

            if self.buffer_len >= 31 {
                self.temp.set_bytes_scalar(&self.buffer[..31]);
                self.state[0].addmod_vec(&self.temp);
                self.permute();
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize the hash computation and get the result
    pub fn digest_final(&mut self) -> VBn254Fr {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        while self.buffer_len < 31 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        self.temp.set_bytes_scalar(&self.buffer[..31]);
        self.state[0].addmod_vec(&self.temp);
        self.permute();

        self.state[0].clone()
    }

    fn permute(&mut self) {
        // External MDS multiplication
        self.multiply_external_mds();

        let mut round = 0;

        // First half of full rounds
        for _ in 0..4 {
            self.add_round_constants(round);
            self.sbox_full();
            self.multiply_external_mds();
            round += 1;
        }

        // Partial rounds
        for _ in 0..self.params.r_p {
            self.add_round_constants_partial(round);
            self.sbox_partial();
            self.multiply_internal_mds();
            round += 1;
        }

        // Second half of full rounds
        for _ in 0..4 {
            self.add_round_constants(round);
            self.sbox_full();
            self.multiply_external_mds();
            round += 1;
        }
    }

    fn add_round_constants(&mut self, round: usize) {
        self.state[0].addmod_vec(&POSEIDON2_T2_RC_VEC[round * 2]);
        self.state[1].addmod_vec(&POSEIDON2_T2_RC_VEC[round * 2 + 1]);
    }

    fn add_round_constants_partial(&mut self, round: usize) {
        self.state[0].addmod_vec(&POSEIDON2_T2_RC_VEC[round * 2]);
    }

    /// Apply S-box (x^5) to all elements
    fn sbox_full(&mut self) {
        self.state[0] = self.pow5(&self.state[0]);
        self.state[1] = self.pow5(&self.state[1]);
    }

    /// Apply S-box (x^5) to first element only
    fn sbox_partial(&mut self) {
        self.state[0] = self.pow5(&self.state[0]);
    }

    /// Compute x^5 for vectorized field element
    fn pow5(&self, x: &VBn254Fr) -> VBn254Fr {
        let mut result = VBn254Fr::new();
        let mut square = VBn254Fr::new();
        mulmod_vec(&mut square, x, x); // square = x^2
        mulmod_vec(&mut result, &square, &square); // result = x^4
        result.mulmod_vec(&x); // result = x^5
        result
    }

    /// External MDS matrix multiplication for t=2
    fn multiply_external_mds(&mut self) {
        addmod_vec(&mut self.temp, &self.state[0], &self.state[1]);
        self.state[0].addmod_vec(&self.temp);
        self.state[1].addmod_vec(&self.temp);
    }

    /// Internal MDS matrix multiplication for t=2
    fn multiply_internal_mds(&mut self) {
        addmod_vec(&mut self.temp, &self.state[0], &self.state[1]);
        self.state[0].addmod_vec(&self.temp);
        self.temp.addmod_vec(&self.state[1]);
        self.state[1].addmod_vec(&self.temp);
    }
}

/// Convenience function to compute Poseidon2 hash from field elements
pub fn poseidon2_hash(inputs: &[Bn254Fr]) -> Bn254Fr {
    let mut ctx = Poseidon2Context::new();

    for input in inputs {
        ctx.digest_update(input);
    }

    ctx.digest_final()
}

/// Convenience function to compute Poseidon2 hash from bytes
pub fn poseidon2_hash_bytes(data: &[u8]) -> Bn254Fr {
    let mut ctx = Poseidon2Context::new();
    ctx.digest_update_bytes(data);
    ctx.digest_final()
}

/// Convenience function to compute vectorized Poseidon2 hash from field elements
pub fn vposeidon2_hash(inputs: &[VBn254Fr]) -> VBn254Fr {
    let mut ctx = VPoseidon2Context::new();

    for input in inputs {
        ctx.digest_update(input);
    }

    ctx.digest_final()
}

/// Convenience function to compute vectorized Poseidon2 hash from bytes
pub fn vposeidon2_hash_bytes(data: &[u8]) -> VBn254Fr {
    let mut ctx = VPoseidon2Context::new();
    ctx.digest_update_bytes(data);
    ctx.digest_final()
}