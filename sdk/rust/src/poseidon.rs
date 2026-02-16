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

//! Poseidon Hash Function for Ligetron
//!
//! ## Algorithm Details
//!
//! The Poseidon hash function uses:
//! - **S-box**: x^5 power function
//! - **Linear Layer**: mds_const matrix multiplication
//! - **Round Constants**: Prevent symmetry attacks
//! - **Full Rounds**: Apply S-box to all state elements
//! - **Partial Rounds**: Apply S-box only to first element (efficiency)
//!
//! ## Security Parameters
//!
//! - **t=3**: 8 full rounds, 57 partial rounds
//! - **t=5**: 8 full rounds, 60 partial rounds

use crate::bn254fr::{Bn254Fr, mulmod_checked};
use crate::vbn254fr::{VBn254Fr, VBn254FrConstant, mulmod_vec, mulmod_constant, mont_mul_constant};
use crate::poseidon_constant::*;
use lazy_static::lazy_static;

pub trait PoseidonParam {
    const R_F: usize;  // Full rounds
    const R_P: usize;  // Partial rounds
    const T: usize;    // State size

    /// Get the round constant string literals
    fn arc_str() -> &'static [&'static str];

    /// Get the mds_const matrix string literals
    fn mds_str() -> &'static [&'static str];

    /// Get the mds_const Montgomery matrix string literals
    fn mds_montgomery_str() -> &'static [&'static str];
}

/// Parameters for Poseidon with t=5 (state size 5)
pub struct PoseidonPermx5Bit254T5;

impl PoseidonParam for PoseidonPermx5Bit254T5 {
    const R_F: usize = 8;
    const R_P: usize = 60;
    const T: usize = 5;

    fn arc_str() -> &'static [&'static str] {
        &POSEIDON_5_ARC_STR
    }

    fn mds_str() -> &'static [&'static str] {
        &POSEIDON_5_MDS_STR
    }

    fn mds_montgomery_str() -> &'static [&'static str] {
        &POSEIDON_5_MDS_MONTGOMERY_STR
    }
}
/// Parameters for Poseidon with t=3 (state size 3)
pub struct PoseidonPermx5Bit254T3;

impl PoseidonParam for PoseidonPermx5Bit254T3 {
    const R_F: usize = 8;
    const R_P: usize = 57;
    const T: usize = 3;

    fn arc_str() -> &'static [&'static str] {
        &POSEIDON_3_ARC_STR
    }

    fn mds_str() -> &'static [&'static str] {
        &POSEIDON_3_MDS_STR
    }

    fn mds_montgomery_str() -> &'static [&'static str] {
        &POSEIDON_3_MDS_MONTGOMERY_STR
    }
}


lazy_static! {
    static ref VPOSEIDON_3_ARC_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T3::arc_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };

    static ref VPOSEIDON_5_ARC_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T5::arc_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };

    static ref VPOSEIDON_3_MDS_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T3::mds_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };

    static ref VPOSEIDON_5_MDS_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T5::mds_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };

    static ref VPOSEIDON_3_MDS_MONTGOMERY_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T3::mds_montgomery_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };

    static ref VPOSEIDON_5_MDS_MONTGOMERY_INIT: Vec<VBn254FrConstant> = {
        PoseidonPermx5Bit254T5::mds_montgomery_str().iter()
            .map(|s| VBn254FrConstant::from_str(s))
            .collect()
    };
}



pub struct PoseidonContext<P: PoseidonParam> {
    state: Vec<Bn254Fr>,
    curr: usize,
    arc_const: Vec<Bn254Fr>,
    mds_const: Vec<Bn254Fr>,
    _params: std::marker::PhantomData<P>,
}


impl<P: PoseidonParam> PoseidonContext<P> {
    pub fn new() -> Self {
        let arc_const = P::arc_str().iter()
            .map(|s| Bn254Fr::from_str(s))
            .collect();
        let mds_const = P::mds_str().iter()
            .map(|s| Bn254Fr::from_str(s))
            .collect();

        let ctx = PoseidonContext {
            state: vec![Bn254Fr::from_u32(0); P::T],
            curr: 0,
            arc_const,
            mds_const,
            _params: std::marker::PhantomData,
        };
        ctx
    }

    pub fn reset(&mut self) {
        for i in 0..P::T {
            self.state[i].set_u32(0);
        }
        self.curr = 0;
    }

    pub fn update(&mut self, data: &Bn254Fr) {
        // Absorb to the sponge
        self.state[self.curr].addmod_checked(data);

        self.curr += 1;

        if self.curr >= P::T {
            self.internal_round_update();
            self.curr = 0;
        }
    }

    pub fn finalize(&mut self) -> Bn254Fr {
        if self.curr != 0 {
            self.internal_round_update();
            self.curr = 0;
        }
        self.state[0].clone()
    }

    fn internal_round_update(&mut self) {
        let r_f_half = P::R_F / 2;
        let mut arc_counter = 0;

        // First half full rounds
        for _ in 0..r_f_half {
            self.perm(&mut arc_counter, true);
        }

        // R_P partial rounds
        for _ in 0..P::R_P {
            self.perm(&mut arc_counter, false);
        }

        // Last half full rounds
        for _ in 0..r_f_half {
            self.perm(&mut arc_counter, true);
        }
    }

    fn perm(&mut self, arc_counter: &mut usize, full_round: bool) {
        // Add round constants
        for i in 0..P::T {
            self.state[i].addmod_checked(&self.arc_const[*arc_counter]);
            *arc_counter += 1;
        }

        // Apply S-box (x^5)
        let num_s_box = if full_round { P::T } else { 1 };
        for i in 0..num_s_box {
            self.state[i] = self.pow5(&self.state[i]);
        }

        let old_state = self.state.clone();

        for i in 0..P::T {
            let mut sum = Bn254Fr::from_u32(0);
            for j in 0..P::T {
                let mut temp = Bn254Fr::new();
                mulmod_checked(&mut temp, &self.mds_const[i * P::T + j], &old_state[j]);
                sum.addmod_checked(&temp);
            }
            self.state[i] = sum;
        }
    }

    /// Compute x^5 for field element
    fn pow5(&self, x: &Bn254Fr) -> Bn254Fr {
        let mut x2 = Bn254Fr::new();
        let mut x4 = Bn254Fr::new();
        let mut result = Bn254Fr::new();
        mulmod_checked(&mut x2, x, x);          // x^2
        mulmod_checked(&mut x4, &x2, &x2);      // x^4
        mulmod_checked(&mut result, &x4, x);    // x^5 = x^4 * x
        result
    }
}

/// Type alias for Poseidon5 context
pub type PoseidonContext5 = PoseidonContext<PoseidonPermx5Bit254T5>;

/// Type alias for poseidon_t3 context
pub type PoseidonContext3 = PoseidonContext<PoseidonPermx5Bit254T3>;

// ============= Vectorized Implementation with Montgomery Support =============

pub struct VPoseidonContext<P: PoseidonParam, const USE_MONTGOMERY: bool = false> {
    state: Vec<VBn254Fr>,
    curr: usize,
    _params: std::marker::PhantomData<P>,
}

impl<P: PoseidonParam, const USE_MONTGOMERY: bool> VPoseidonContext<P, USE_MONTGOMERY> {
    /// Static arc_const constants
    fn arc() -> &'static [VBn254FrConstant] {
        match P::T {
            3 => &VPOSEIDON_3_ARC_INIT,
            5 => &VPOSEIDON_5_ARC_INIT,
            _ => panic!("Unsupported Poseidon state size"),
        }
    }

    /// Static mds_const constants
    /// Initialized from P::mds_str() or P::mds_montgomery_str() depending on USE_MONTGOMERY
    fn mds() -> &'static [VBn254FrConstant] {
        if USE_MONTGOMERY {
            match P::T {
                3 => &VPOSEIDON_3_MDS_MONTGOMERY_INIT,
                5 => &VPOSEIDON_5_MDS_MONTGOMERY_INIT,
                _ => panic!("Unsupported Poseidon state size"),
            }
        } else {
            match P::T {
                3 => &VPOSEIDON_3_MDS_INIT,
                5 => &VPOSEIDON_5_MDS_INIT,
                _ => panic!("Unsupported Poseidon state size"),
            }
        }
    }
}

impl<P: PoseidonParam, const USE_MONTGOMERY: bool> VPoseidonContext<P, USE_MONTGOMERY> {
    pub fn new() -> Self {
        let ctx = VPoseidonContext {
            state: (0..P::T).map(|_| VBn254Fr::from_ui_scalar(0)).collect(),
            curr: 0,
            _params: std::marker::PhantomData,
        };
        ctx
    }

    pub fn reset(&mut self) {
        for i in 0..P::T {
            self.state[i].set_ui_scalar(0);
        }
        self.curr = 0;
    }

    pub fn update(&mut self, data: &VBn254Fr) {
        self.state[self.curr].addmod_vec(data);

        self.curr += 1;

        if self.curr >= P::T {
            self.internal_round_update();
            self.curr = 0;
        }
    }

    pub fn finalize(&mut self) -> VBn254Fr {
        if self.curr != 0 {
            self.internal_round_update();
            self.curr = 0;
        }
        self.state[0].clone()
    }

    fn internal_round_update(&mut self) {
        let r_f_half = P::R_F / 2;
        let mut arc_counter = 0;

        // First half full rounds
        for _ in 0..r_f_half {
            self.perm(&mut arc_counter, true);
        }

        // R_P partial rounds
        for _ in 0..P::R_P {
            self.perm(&mut arc_counter, false);
        }

        // Last half full rounds
        for _ in 0..r_f_half {
            self.perm(&mut arc_counter, true);
        }
    }

    fn perm(&mut self, arc_counter: &mut usize, full_round: bool) {
        // Add round constants
        for i in 0..P::T {
            self.state[i].addmod_constant(&Self::arc()[*arc_counter]);
            *arc_counter += 1;
        }

        // Apply S-box (x^5)
        let num_s_box = if full_round { P::T } else { 1 };
        for i in 0..num_s_box {
            self.state[i] = self.pow5(&self.state[i]);
        }

        // mds_const matrix multiplication with Montgomery support
        let old_state = self.state.clone();
        for i in 0..P::T {
            let mut sum = VBn254Fr::new();
            sum.set_ui_scalar(0);
            for j in 0..P::T {
                let mut temp = VBn254Fr::new();
                if USE_MONTGOMERY {
                    mont_mul_constant(&mut temp, &old_state[j], &Self::mds()[i * P::T + j]);
                } else {
                    mulmod_constant(&mut temp, &old_state[j], &Self::mds()[i * P::T + j]);
                }
                sum.addmod_vec(&temp);
            }
            self.state[i] = sum;
        }
    }

    /// Compute x^5 for vectorized field element
    fn pow5(&self, x: &VBn254Fr) -> VBn254Fr {
        let mut x2 = VBn254Fr::new();
        let mut x4 = VBn254Fr::new();
        let mut result = VBn254Fr::new();
        mulmod_vec(&mut x2, x, x);          // x^2
        mulmod_vec(&mut x4, &x2, &x2);      // x^4
        mulmod_vec(&mut result, &x4, x);    // x^5 = x^4 * x
        result
    }
}

/// Type alias for vectorized Poseidon5 context
pub type VPoseidonContext5<const USE_MONTGOMERY: bool> = VPoseidonContext<PoseidonPermx5Bit254T5, USE_MONTGOMERY>;

/// Type alias for vectorized poseidon_t3 context
pub type VPoseidonContext3<const USE_MONTGOMERY: bool> = VPoseidonContext<PoseidonPermx5Bit254T3, USE_MONTGOMERY>;

/// Convenience function to compute Poseidon hash with t=5
pub fn poseidon_t5_hash(inputs: &[Bn254Fr]) -> Bn254Fr {
    let mut ctx = PoseidonContext5::new();

    for input in inputs {
        ctx.update(input);
    }

    ctx.finalize()
}

/// Convenience function to compute Poseidon hash with t=3
pub fn poseidon_t3_hash(inputs: &[Bn254Fr]) -> Bn254Fr {
    let mut ctx = PoseidonContext3::new();

    for input in inputs {
        ctx.update(input);
    }

    ctx.finalize()
}


// ============= Vectorized Convenience Functions =============

/// Convenience function to compute vectorized Poseidon hash with t=5
pub fn vposeidon_t5_hash<const USE_MONTGOMERY: bool>(inputs: &[VBn254Fr]) -> VBn254Fr {
    let mut ctx = VPoseidonContext5::<USE_MONTGOMERY>::new();

    for input in inputs {
        ctx.update(input);
    }

    ctx.finalize()
}

/// Convenience function to compute vectorized Poseidon hash with t=3
pub fn vposeidon_t3_hash<const USE_MONTGOMERY: bool>(inputs: &[VBn254Fr]) -> VBn254Fr {
    let mut ctx = VPoseidonContext3::<USE_MONTGOMERY>::new();

    for input in inputs {
        ctx.update(input);
    }

    ctx.finalize()
}