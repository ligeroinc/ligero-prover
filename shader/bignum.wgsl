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

const nail_bytes     : u32 = 4;  // u32
const nail_bits      : u32 = nail_bytes * 8;
const num_nails      : u32 = 4;  // uint128 = vec4<u32>
const limb_bytes     : u32 = nail_bytes * num_nails;
const limb_bits      : u32 = nail_bits  * num_nails;
const num_limbs      : u32 = 2;
const num_wide_limbs : u32 = num_limbs * 2;
const num_total_nails : u32 = num_limbs * num_nails;
const bignum_bytes   : u32 = num_total_nails * nail_bytes;

const thread_block_size : u32 = 256;
const ntt_cache_size    : u32 = thread_block_size * 2;

const num_sampling : u32 = 192;

struct uint128      { limbs : vec4u  }
struct bigint       { @align(bignum_bytes) limbs : array<uint128, num_limbs> }
struct u32_cc       { sum   : u32,     carry : bool }
struct uint128_cc   { sum   : uint128, carry : bool }
struct bigint_cc    { sum   : bigint,  carry : bool }
struct u32_wide     { lo    : u32,     hi : u32     }
struct uint128_wide { lo    : uint128, hi : uint128 }
struct bigint_wide  { lo    : bigint,  hi : bigint  }

// P = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
const Fp_p : bigint = bigint(array<uint128, 2>(
    uint128(vec4u(0xF0000001, 0x43E1F593, 0x79B97091, 0x2833E848)),
    uint128(vec4u(0x8181585D, 0xB85045B6, 0xE131A029, 0x30644E72))
));

// 2P = 0x60c89ce5c263405370a08b6d0302b0ba5067d090f372e12287c3eb27e0000002
const Fp_2p : bigint = bigint(array<uint128, 2>(
    uint128(vec4u(0xE0000002, 0x87C3EB27, 0xF372E122, 0x5067D090)),
    uint128(vec4u(0x0302B0BA, 0x70A08B6D, 0xC2634053, 0x60C89CE5))
));

// Montgomery factor J = p^(-1) mod 2^256
const Fp_J : bigint = bigint(array<uint128, 2>(
    uint128(vec4u(0x10000001, 0x3D1E0A6C, 0xB396EE4C, 0x9A7979B4)),
    uint128(vec4u(0x66F9DC6E, 0x1C6567D7, 0xF27CBE4D, 0x8C07D0E2))
));

// Barrett factor Mu = 2^(254 * 2) // p
const Fp_mu : bigint = bigint(array<uint128, 2>(
    uint128(vec4u(0xBE1DE925, 0x620703A6, 0x09E880AE, 0x71448520)),
    uint128(vec4u(0x68073014, 0xAB074A58, 0x623A04A7, 0x54A47462))
));

// Padded to 256 bytes to use dynamic offsets
// params[0]: N
// params[1]: log2N
// params[2]: M
// params[3]: <unused>
const ntt_padding_size = (16 - 1 - num_limbs);
struct ntt_config_t {
    N_inv          : bigint,
    params         : vec4u,
    _padding       : array<vec4u, ntt_padding_size>
}

var<workgroup> ntt_workgroup_cache : array<bigint, ntt_cache_size>;

@group(0) @binding(0) var<storage, read_write> ntt_buffer    : array<bigint>;
@group(0) @binding(1) var<storage, read>       vector_x      : array<bigint>;
@group(0) @binding(2) var<storage, read>       vector_y      : array<bigint>;
@group(0) @binding(3) var<storage, read_write> vector_out    : array<bigint>;
// Buffer for computing out = coeff * r^exp mod p for some base r in precompute table
@group(0) @binding(4) var<storage, read>       powmod_exp    : array<u32>;
@group(0) @binding(5) var<storage, read>       powmod_coeff  : array<bigint>;
@group(0) @binding(6) var<storage, read_write> powmod_out    : array<bigint>;

@group(1) @binding(0) var<uniform>             ntt_config    : ntt_config_t;
@group(1) @binding(1) var<storage, read>       ntt_omegas    : array<bigint>;
@group(1) @binding(2) var<uniform>             input_scalar  : bigint;
@group(1) @binding(3) var<uniform>             sample_index  : array<vec4u, num_sampling>;
// Precomputed lookup table r^(2^0), r^(2^1), r^(2^2), ..., r^(2^31) in Montgomery form
@group(1) @binding(4) var<uniform>             powmod_table  : array<bigint, 32>;


fn uint128_from_u32(x : u32) -> uint128 {
    return uint128(vec4u(x, 0u, 0u, 0u));
}

fn bigint_from_u32(x : u32) -> bigint {
    var r : bigint;
    r.limbs[0] = uint128_from_u32(x);
    return r;
}

fn u32_add_cc(a : u32, b : u32) -> u32_cc {
    let sum   = a + b;
    let carry = sum < a;
    return u32_cc(sum, carry);
}

fn u32_addc_cc(a : u32, b : u32, carry : bool) -> u32_cc {
    let cc1 = u32_add_cc(a, b);
    var cc2 = u32_add_cc(cc1.sum, u32(carry));
    cc2.carry |= cc1.carry;
    return cc2;
}

fn uint128_addu32_cc(a : uint128, b : u32) -> uint128_cc {
    let cc0 = u32_add_cc(a.limbs[0], b);
    let cc1 = u32_add_cc(a.limbs[1], u32(cc0.carry));
    let cc2 = u32_add_cc(a.limbs[2], u32(cc1.carry));
    let cc3 = u32_add_cc(a.limbs[3], u32(cc2.carry));

    return uint128_cc(uint128(vec4u(cc0.sum, cc1.sum, cc2.sum, cc3.sum)), cc3.carry);
}

fn uint128_add_cc(a : uint128, b : uint128) -> uint128_cc {
    var out = a.limbs + b.limbs;
    let cc  = out < a.limbs;
    
    let cc1 = u32_add_cc(out[1], u32(cc[0]));
    let cc2 = u32_add_cc(out[2], u32(cc[1] || cc1.carry));
    let cc3 = u32_add_cc(out[3], u32(cc[2] || cc2.carry));

    out[1] = cc1.sum;
    out[2] = cc2.sum;
    out[3] = cc3.sum;
    return uint128_cc(uint128(out), cc[3] || cc3.carry);
}

fn uint128_addc_cc(a : uint128, b : uint128, carry : bool) -> uint128_cc {
    var sum = a.limbs + b.limbs;
    let cc  = sum < a.limbs;
    
    let cc0 = u32_add_cc(sum[0], u32(carry));
    let cc1 = u32_add_cc(sum[1], u32(cc[0] || cc0.carry));
    let cc2 = u32_add_cc(sum[2], u32(cc[1] || cc1.carry));
    let cc3 = u32_add_cc(sum[3], u32(cc[2] || cc2.carry));

    sum[0] = cc0.sum;
    sum[1] = cc1.sum;
    sum[2] = cc2.sum;
    sum[3] = cc3.sum;

    return uint128_cc(uint128(sum), cc[3] || cc3.carry);
}

fn bigint_add_cc(pa : bigint, pb : bigint) -> bigint_cc {
    var a   : bigint = pa;
    var b   : bigint = pb;
    var out : bigint_cc;
    for (var i : u32 = 0; i < num_limbs; i++) {
        let cc = uint128_addc_cc(a.limbs[i], b.limbs[i], out.carry);
        out.sum.limbs[i] = cc.sum;
        out.carry = cc.carry;
    }
    return out;
}

fn bigint_add(a : bigint, b : bigint) -> bigint {
    return bigint_add_cc(a, b).sum;
}


// ---------- subtruct ----------

fn u32_sub_cc(a : u32, b : u32) -> u32_cc {
    let sub    = a - b;
    let borrow = a < b;
    return u32_cc(sub, borrow);
}

fn u32_subc_cc(a : u32, b : u32, borrow : bool) -> u32_cc {
    let cc1 = u32_sub_cc(a, b);
    var cc2 = u32_sub_cc(cc1.sum, u32(borrow));
    cc2.carry |= cc1.carry;
    return cc2;
}

fn uint128_subc_cc(a : uint128, b : uint128, borrow : bool) -> uint128_cc {
    var sub = a.limbs - b.limbs;
    let cc  = a.limbs < b.limbs;
    
    let cc0 = u32_sub_cc(sub[0], u32(borrow));
    let cc1 = u32_sub_cc(sub[1], u32(cc[0] || cc0.carry));
    let cc2 = u32_sub_cc(sub[2], u32(cc[1] || cc1.carry));
    let cc3 = u32_sub_cc(sub[3], u32(cc[2] || cc2.carry));

    sub[0] = cc0.sum;
    sub[1] = cc1.sum;
    sub[2] = cc2.sum;
    sub[3] = cc3.sum;

    return uint128_cc(uint128(sub), cc[3] || cc3.carry);
}

fn bigint_sub_cc(pa : bigint, pb : bigint) -> bigint_cc {
    var a   : bigint = pa;
    var b   : bigint = pb;
    var out : bigint_cc;
    for (var i :u32 = 0; i < num_limbs; i++) {
        let cc = uint128_subc_cc(a.limbs[i], b.limbs[i], out.carry);
        out.sum.limbs[i] = cc.sum;
        out.carry = cc.carry;
    }
    return out;
}

fn bigint_sub(a : bigint, b : bigint) -> bigint {
    return bigint_sub_cc(a, b).sum;
}


// ---------- multiply ----------

fn u32_mul_wide(a : u32, b : u32) -> u32_wide {
    let a_lo = a & 0xFFFF;
    let a_hi = a >> 16;
    let b_lo = b & 0xFFFF;
    let b_hi = b >> 16;

    let ab_low = a_lo * b_lo;
    let ab_mid = a_lo * b_hi;
    let ba_mid = a_hi * b_lo;
    let ab_high = a_hi * b_hi;
    
    let lo_cc1 = u32_add_cc(ab_low, (ab_mid << 16));
    let lo_cc2 = u32_add_cc(lo_cc1.sum, (ba_mid << 16));

    let lo = lo_cc2.sum;
    let hi = ab_high + (ab_mid >> 16) + (ba_mid >> 16) + u32(lo_cc1.carry) + u32(lo_cc2.carry);

    return u32_wide(lo, hi);
}

fn uint128_mul_lo(a : uint128, b : uint128) -> uint128 {
    var out            : uint128;

    // c0 = a0b0.lo
    let a0b0 = u32_mul_wide(a.limbs[0], b.limbs[0]);
    out.limbs[0] = a0b0.lo;

    // c1 = a0b1.lo + a1b0.lo + a0b0.hi
    let a0b1  = u32_mul_wide(a.limbs[0], b.limbs[1]);
    let a1b0  = u32_mul_wide(a.limbs[1], b.limbs[0]);
    let cc0   = u32_add_cc(a0b1.lo, a1b0.lo);
    let cc1   = u32_add_cc(cc0.sum, a0b0.hi);
    out.limbs[1] = cc1.sum;

    // c2 = (a0b2.lo + a1b1.lo + a2b0.lo) +
    //      (a0b1.hi + a1b0.hi)
    let a0b2  = u32_mul_wide(a.limbs[0], b.limbs[2]);
    let a1b1  = u32_mul_wide(a.limbs[1], b.limbs[1]);
    let a2b0  = u32_mul_wide(a.limbs[2], b.limbs[0]);

    let cc2   = u32_add_cc(a0b1.hi, a1b0.hi);
    let cc3   = u32_add_cc(a0b2.lo, a1b1.lo);
    let cc4   = u32_add_cc(a2b0.lo, u32(cc0.carry) + u32(cc1.carry));

    let cc5   = u32_add_cc(cc2.sum, cc3.sum);
    let cc6   = u32_add_cc(cc4.sum, cc5.sum);
    out.limbs[2] = cc6.sum;

    // c3 = (a0b3 + a1b2 + a2b1 + a3b0) + 
    //      (a0b2.hi + a1b1.hi + a2b0.hi)
    let a0b3 = a.limbs[0] * b.limbs[3];
    let a1b2 = a.limbs[1] * b.limbs[2];
    let a2b1 = a.limbs[2] * b.limbs[1];
    let a3b0 = a.limbs[3] * b.limbs[0];
    out.limbs[3] = a0b3 + a1b2 + a2b1 + a3b0 + 
                   a0b2.hi + a1b1.hi + a2b0.hi + 
                   u32(cc2.carry) + u32(cc3.carry) + 
                   u32(cc4.carry) + u32(cc5.carry) + u32(cc6.carry);

    return out;
}

fn uint128_mul_wide(a : uint128, b : uint128) -> uint128_wide {
    var result : array<u32, 8>;
    var carry  : u32;
    for (var b_i : u32 = 0; b_i < 4; b_i++) {
        {
            let mul       = u32_mul_wide(a.limbs[0], b.limbs[b_i]);
            let sum_acc   = u32_add_cc(mul.lo, result[b_i]);
            carry         = mul.hi + u32(sum_acc.carry);
            result[b_i]   = sum_acc.sum;
        }
        for (var a_i : u32 = 1u; a_i < 4; a_i++) {
            let mul       = u32_mul_wide(a.limbs[a_i], b.limbs[b_i]);
            let sum_carry = u32_add_cc(mul.lo, carry);
            let sum_acc   = u32_add_cc(sum_carry.sum, result[a_i + b_i]);
            carry         = mul.hi + u32(sum_carry.carry) + u32(sum_acc.carry);  // not possible to overflow
            result[a_i + b_i] = sum_acc.sum;
        }
        result[b_i + 4] = carry;
    }
    return uint128_wide(uint128(vec4u(result[0], result[1], result[2], result[3])),
                        uint128(vec4u(result[4], result[5], result[6], result[7])));
}

fn bigint_mul_lo(pa : bigint, pb : bigint) -> bigint {
    var a      : bigint = pa;
    var b      : bigint = pb;
    var result : bigint;
    var carry  : uint128;
    var i      : u32;

    for (var j : u32 = 0; j < num_limbs; j++) {
        carry = uint128();
        for (i = 0u; i < (num_limbs - j - 1); i++) {
            let mul       = uint128_mul_wide(a.limbs[i], b.limbs[j]);
            let sum_carry = uint128_add_cc(mul.lo,        carry);
            let sum_acc   = uint128_add_cc(sum_carry.sum, result.limbs[i + j]);
            // mu.hi can be at most 2^128 - 1, impossible to overflow again
            let cc        = uint128_addu32_cc(mul.hi, u32(sum_carry.carry || sum_acc.carry));
            carry         = cc.sum;
            result.limbs[i + j] = sum_acc.sum;
        }
        // Handle the highest part with faster arithmetic
        let mul : uint128    = uint128_mul_lo(a.limbs[i], b.limbs[j]);
        let cc  : uint128    = uint128_add_cc(mul, carry).sum;
        result.limbs[i + j]  = uint128_add_cc(result.limbs[i + j], cc).sum;
    }
    return result;
}

fn bigint_mul_wide(pa : bigint, pb : bigint) -> bigint_wide {
    var a      : bigint = pa;
    var b      : bigint = pb;
    var result : array<uint128, num_wide_limbs>;

    var carry  : uint128;
    for (var j : u32 = 0; j < num_limbs; j++) {
        let mul       = uint128_mul_wide(a.limbs[0], b.limbs[j]);
        let sum_acc   = uint128_add_cc(mul.lo, result[j]);
        carry         = uint128_addu32_cc(mul.hi, u32(sum_acc.carry)).sum;
        result[j]     = sum_acc.sum;

        for (var i : u32 = 1; i < num_limbs; i++) {
            let mul       = uint128_mul_wide(a.limbs[i], b.limbs[j]);
            let sum_carry = uint128_add_cc(mul.lo,        carry);
            let sum_acc   = uint128_add_cc(sum_carry.sum, result[i + j]);
            // mu.hi can be at most 2^128 - 1, impossible to overflow again
            carry         = uint128_addu32_cc(mul.hi, u32(sum_carry.carry || sum_acc.carry)).sum;
            result[i + j] = sum_acc.sum;
        }
        result[j + num_limbs]  = carry;
    }

    var wide : bigint_wide;
    for (var i : u32 = 0; i < num_limbs; i++) {
        wide.lo.limbs[i] = result[i];
        wide.hi.limbs[i] = result[i + num_limbs];
    }
    return wide;
}

fn bigint_mul_hi(a : bigint, b : bigint) -> bigint {
    return bigint_mul_wide(a, b).hi;
}

// ---------- Montgomery Reduction ----------

// Montgomery reduction step.
// Reduces a 2×N-bit product into an N-bit residue in [-p, p).
// Requires input in Montgomery form
fn _montgomery_reduce_helper(wide : bigint_wide, p : bigint, J : bigint) -> bigint_cc {
    let Q = bigint_mul_lo(wide.lo, J);
    let H = bigint_mul_hi(Q, p);
    return bigint_sub_cc(wide.hi, H);
}

// Montgomery reduction.
// Reduces a 2×N-bit product into an N-bit residue in [0, p).
// Requires input in Montgomery form
fn montgomery_reduce_wide(wide : bigint_wide, p : bigint, J : bigint) -> bigint {
    var cc  = _montgomery_reduce_helper(wide, p, J);
    if (cc.carry) {
        cc.sum = bigint_add(cc.sum, p);
    }
    return cc.sum;
}

// Montgomery reduction.
// Reduces a 2×N-bit product into an N-bit residue in [0, 2p).
// Requires input in Montgomery form
fn montgomery_reduce_wide_2p(wide : bigint_wide, p : bigint, J : bigint) -> bigint {
    let t = _montgomery_reduce_helper(wide, p, J).sum;
    return bigint_add(t, p);
}

fn montgomery_mul(a : bigint, b : bigint) -> bigint {
    let U = bigint_mul_wide(a, b);
    return montgomery_reduce_wide(U, Fp_p, Fp_J);
}

fn montgomery_mul_2p(a : bigint, b : bigint) -> bigint {
    let U = bigint_mul_wide(a, b);
    return montgomery_reduce_wide_2p(U, Fp_p, Fp_J);
}


// ---------- Barrett Reduction ----------

fn barrett_reduce_wide(x : bigint_wide) -> bigint {
    let xr_hi  : bigint_wide = bigint_mul_wide(x.hi, Fp_mu);
    let xr_lo  : bigint      = bigint_mul_hi(x.lo, Fp_mu);
    let sum_lo : bigint_cc   = bigint_add_cc(xr_hi.lo, xr_lo);
    let sum_hi : bigint      = bigint_add(xr_hi.hi, bigint_from_u32(u32(sum_lo.carry)));
    let z_hi   : bigint      = bigint_shl(sum_hi, 4u);
    let z_lo   : bigint      = bigint_shr(sum_lo.sum, 252u);
    let z      : bigint      = bigint_add(z_hi, z_lo);
    let q      : bigint      = bigint_mul_lo(z, Fp_p);
    let result : bigint      = bigint_sub(x.lo, q);

    let cc = bigint_sub_cc(result, Fp_p);
    if (!cc.carry) {
        return cc.sum;
    }
    else {
        return result;
    }
}

// ---------- Bit ----------

fn bigint_shl(px : bigint, shift : u32) -> bigint {
    var x      : bigint = px;
    let global : u32    = shift / nail_bits;
    let local  : u32    = shift % nail_bits;

    var result : bigint;
    for (var i : u32 = num_total_nails - 1; i > global; i--) {
        let out_limb_idx = i / num_nails;
        let out_nail_idx = i % num_nails;

        let hi = x.limbs[(i - global) / num_nails].limbs[(i - global) % num_nails] << local;
        let lo = select(0u,
                        x.limbs[(i - global - 1) / num_nails].limbs[(i - global - 1) % num_nails] >> (nail_bits - local),
                        local > 0);
        result.limbs[out_limb_idx].limbs[out_nail_idx] = hi | lo;
    }

    let limb_idx = global / num_nails;
    let nail_idx = global % num_nails;
    result.limbs[limb_idx].limbs[nail_idx] = x.limbs[0].limbs[0] << local;
    return result;
}

fn bigint_shr(px : bigint, shift : u32) -> bigint {
    var x      : bigint = px;
    let global : u32    = shift / nail_bits;
    let local  : u32    = shift % nail_bits;

    var result : bigint;
    for (var i : u32 = 0; i < num_total_nails - global; i++) {
        let r_global_idx  = i / num_nails;
        let r_local_idx   = i % num_nails;
        let lo_global_idx = (i + global) / num_nails;
        let lo_local_idx  = (i + global) % num_nails;
        let hi_global_idx = (i + global + 1) / num_nails;
        let hi_local_idx  = (i + global + 1) % num_nails;
        let lo = x.limbs[lo_global_idx].limbs[lo_local_idx] >> local;
        let hi = select(0u,
                        x.limbs[hi_global_idx].limbs[hi_local_idx] << (nail_bits - local),
                        local > 0 && (i + global + 1) < num_total_nails);
        result.limbs[r_global_idx].limbs[r_local_idx] = hi | lo;
    }

    return result;
}

fn bigint_select_bit(p : ptr<function, bigint>, idx : u32) -> u32 {
    let limb_idx = idx / limb_bits;
    let nail_idx = (idx % limb_bits) / nail_bits;
    let bit_idx  = idx % nail_bits;
    return (((*p).limbs[limb_idx].limbs[nail_idx] >> bit_idx) & 1u);
}

fn bigint_set_bit_u32(p : ptr<function, bigint>, idx : u32, val : u32) {
    let limb_idx = idx / limb_bits;
    let nail_idx = (idx % limb_bits) / nail_bits;
    let bit_idx  = idx % nail_bits;
    (*p).limbs[limb_idx].limbs[nail_idx] |= (val & 1u) << bit_idx;
}

fn bigint_test_bit(p : ptr<function, bigint>, idx : u32) -> bool {
    return bigint_select_bit(p, idx) == 1u;
}

// ---------- Is Zero ----------

fn uint128_is_zero(x : uint128) -> bool {
    return all(x.limbs == vec4u(0u, 0u, 0u, 0u));
}

fn bigint_is_zero(px : bigint) -> bool {
    var x : bigint = px;
    var result = true;
    for (var i = 0u; i < num_limbs; i++) {
        result &= uint128_is_zero(x.limbs[i]);
    }
    return result;
}

// ---------- bigint Division ----------

struct divide_result {
    q : bigint,
    r : bigint
};

fn bigint_divide_qr(x : bigint, d : bigint) -> divide_result {
    var n = x;
    var q : bigint;
    var r : bigint;

    var i = i32(num_limbs * limb_bits - 1);

    for (; i >= 0; i--) {
        if (bigint_test_bit(&n, u32(i))) {
            break;
        }
    }

    for (; i >= 0; i--) {
        r = bigint_shl(r, 1u);
        let bit = bigint_select_bit(&n, u32(i));
        bigint_set_bit_u32(&r, 0u, bit);

        let cc = bigint_sub_cc(r, d);
        if (!cc.carry) {
            r = bigint_sub(r, d);
            bigint_set_bit_u32(&q, u32(i), 1u);
        }
    }

    return divide_result(q, r);
}

// ---------- Mod Inverse ----------

fn modinv(x : bigint, m : bigint) -> bigint {
    var b = x;
    var c = m;

    var u = bigint_from_u32(1u);
    var w = bigint_from_u32(0u);

    while (!bigint_is_zero(c)) {
        let div = bigint_divide_qr(b, c);
        b = c;
        c = div.r;

        var new_w = bigint_sub(u, bigint_mul_lo(div.q, w));
        u = w;
        w = new_w;
    }

    // Important: adjust for negative number
    while (bigint_test_bit(&u, num_limbs * limb_bits - 1)) {
        u = bigint_add(u, m);
    }

    return u;
}

// ---------- Exponent Mod ----------

// Compute 32-bit exponent with a Montgomery precompute table
// Output r ^ exp mod p in Montgomery form
fn powmod(table : ptr<uniform, array<bigint, 32>>, exponent : u32) -> bigint {
    // Initialize out to be 1 * R mod p
    var out = bigint(array<uint128, num_limbs>(
                         uint128(vec4u(0x4FFFFFFB, 0xAC96341C, 0x9F60CD29, 0x36FC7695)),
                         uint128(vec4u(0x7879462E, 0x666EA36F, 0x9A07DF2F, 0x0E0A77C1))));

    for (var i : u32 = 0u; i < 32u; i++) {
        let bi : u32 = (exponent >> i) & 1u;
        
        if (bi == 1u) {
            out = montgomery_mul(out, (*table)[i]);
        }
    }

    return out;
}

// ---------- Bit Reversal ---------

@compute @workgroup_size(thread_block_size)
fn ntt_bit_reverse(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    let N    = ntt_config.params[0];
    let bits = ntt_config.params[1];
    for (var id : u32 = globalIdx.x; id < N; id += workgroups.x * thread_block_size) {
        let reversed_id = reverseBits(id) >> (32 - bits);

        if (id < reversed_id) {
            let val : bigint        = ntt_buffer[id];
            ntt_buffer[id]          = ntt_buffer[reversed_id];
            ntt_buffer[reversed_id] = val;
        }
    }
}


// ---------- Adjust Inverse ----------

@compute @workgroup_size(thread_block_size)
fn ntt_reduce4p(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    let N    = ntt_config.params[0];
    for (var idx : u32 = globalIdx.x; idx < N; idx += workgroups.x * thread_block_size) {
        var val : bigint = ntt_buffer[idx];

        let cc1 = bigint_sub_cc(val, Fp_2p);
        if (!cc1.carry) {
            val = cc1.sum;
        }

        let cc2 = bigint_sub_cc(val, Fp_p);
        if (!cc2.carry) {
            val = cc2.sum;
        }

        ntt_buffer[idx] = val;
    }
}

@compute @workgroup_size(thread_block_size)
fn ntt_adjust_inverse_reduce(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    let N    = ntt_config.params[0];
    for (var idx : u32 = globalIdx.x; idx < N; idx += workgroups.x * thread_block_size) {
        let val : bigint = ntt_buffer[idx];
        ntt_buffer[idx] = montgomery_mul(val, ntt_config.N_inv);
    }
}

@compute @workgroup_size(thread_block_size)
fn ntt_fold(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    let half : u32 = ntt_config.params[0] >> 1;  // assume N = 2k
    for (var idx : u32 = globalIdx.x; idx < half; idx += workgroups.x * thread_block_size) {
        let x : bigint = ntt_buffer[idx];
        let y : bigint = ntt_buffer[idx + half];

        let sum = bigint_add(x, y);
        var cc  = bigint_sub_cc(sum, Fp_p);
        if (cc.carry) {
            cc.sum = sum;
        }

        ntt_buffer[idx] = cc.sum;
    }
}

// ---------- NTT kernels ----------

// ---------- NTT Forward (DIF) Kernels ----------

// Assume Input  X, Y ∈ [0, 2p)
//        Output X, Y ∈ [0, 2p)
@compute @workgroup_size(thread_block_size)
fn ntt_forward_radix2(@builtin(global_invocation_id) globalIdx : vec3u,
                      @builtin(num_workgroups) workgroups : vec3u)
{
    let N = ntt_config.params[0];
    let M = ntt_config.params[2];
    let iter = ntt_config.params[3];
    let M2 = M >> 1;

    var x : bigint;
    var y : bigint;
    for (var instance : u32 = globalIdx.x; instance < (N >> 1); instance += workgroups.x * thread_block_size) {
        let group = instance / M2;
        let index = instance % M2;
        let k = group * M + index;

        x = ntt_buffer[k];
        y = ntt_buffer[k + M2];

        var tmp = bigint_add(x, y);
        let cc = bigint_sub_cc(tmp, Fp_2p);
        if (!cc.carry) {
            tmp = cc.sum;
        }

        ntt_buffer[k] = tmp;

        y   = bigint_add(x, bigint_sub(Fp_2p, y));
        tmp = ntt_omegas[index];
        tmp = montgomery_mul_2p(y, tmp);

        ntt_buffer[k + M2] = tmp;
    }
}

@compute @workgroup_size(thread_block_size)
fn ntt_forward_radix2_shared(
    @builtin(local_invocation_id) threadIdx : vec3u,
    @builtin(workgroup_id) blockIdx : vec3u
) {
    let instance = threadIdx.x;
    let ntt_block_size = thread_block_size << 1;  // one thread handle two places
    let ntt_half_block_size = thread_block_size;
    let global_index = blockIdx.x * ntt_block_size + instance;

    // Load from global memory to shared memory
    ntt_workgroup_cache[instance] = ntt_buffer[global_index];
    ntt_workgroup_cache[instance + ntt_half_block_size] = ntt_buffer[global_index + ntt_half_block_size];

    workgroupBarrier();

    let iterations = u32(log2(f32(ntt_block_size)));

    var u : bigint;
    var v : bigint;
    var w : bigint;
    for (var iter = iterations; iter > 1; iter--) {
        let M  = 1u << iter;
        let M2 = M >> 1;
        let omega_base = M2 - 1;

        let ntt_group = instance / M2;
        let ntt_index = instance % M2;
        let k = ntt_group * M + ntt_index;

        let x = ntt_workgroup_cache[k];
        let y = ntt_workgroup_cache[k + M2];

        u = bigint_add(x, y);
        let ucc = bigint_sub_cc(u, Fp_2p);
        if (!ucc.carry) {
            u = ucc.sum;
        }

        let vcc = bigint_sub_cc(x, y);
        if (vcc.carry) {
            v = bigint_add(vcc.sum, Fp_2p);
        }
        else {
            v = vcc.sum;
        }

        ntt_workgroup_cache[k] = u;

        w = ntt_omegas[omega_base + ntt_index];
        v = montgomery_mul_2p(v, w);
        
        ntt_workgroup_cache[k + M2] = v;

        workgroupBarrier();
    }

    {
        let k = instance * 2;

        let x = ntt_workgroup_cache[k];
        let y = ntt_workgroup_cache[k + 1];

        u = bigint_add(x, y);
        // Reduce to [0, 2p)
        let uc1 = bigint_sub_cc(u, Fp_2p);
        if (!uc1.carry) {
            u = uc1.sum;
        }

        // Reduce to [0, p)
        let uc2 = bigint_sub_cc(u, Fp_p);
        if (!uc2.carry) {
            u = uc2.sum;
        }

        v = bigint_sub(bigint_add(x, Fp_2p), y);
        // Reduce to [0, 2p)
        let vc1 = bigint_sub_cc(v, Fp_2p);
        if (!vc1.carry) {
            v = vc1.sum;
        }

        // Reduce to [0, p)
        let vc2 = bigint_sub_cc(v, Fp_p);
        if (!vc2.carry) {
            v = vc2.sum;
        }

        ntt_workgroup_cache[k]     = u;
        ntt_workgroup_cache[k + 1] = v;

        workgroupBarrier();
    }

    ntt_buffer[global_index] = ntt_workgroup_cache[instance];
    ntt_buffer[global_index + ntt_half_block_size] = ntt_workgroup_cache[instance + ntt_half_block_size];
}

// ---------- NTT Inverse (DIT) Kernels ----------

// Assume Input  X, Y ∈ [0, 4p)
//        Output X, Y ∈ [0, 4p)
@compute @workgroup_size(thread_block_size)
fn ntt_inverse_radix2(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    let N = ntt_config.params[0];
    let M = ntt_config.params[2];
    let M2 = M >> 1;

    var x : bigint;
    var y : bigint;
    var w : bigint;

    for (var instance : u32 = globalIdx.x; instance < (N >> 1); instance += workgroups.x * thread_block_size) {
        let group = instance / M2;
        let index = instance % M2;
        let k = group * M + index;

        x = ntt_buffer[k];
        y = ntt_buffer[k + M2];
        w = ntt_omegas[index];

        y = montgomery_mul_2p(y, w);

        let cc = bigint_sub_cc(x, Fp_2p);
        if (!cc.carry) {
            x = cc.sum;
        }

        // Output X, Y ∈ [0, 4p)
        w = bigint_add(x, y);
        ntt_buffer[k] = w;

        w = bigint_add(x, bigint_sub(Fp_2p, y));
        ntt_buffer[k + M2] = w;
    }
}

@compute @workgroup_size(thread_block_size)
fn ntt_inverse_radix2_shared(
    @builtin(local_invocation_id) threadIdx : vec3u,
    @builtin(workgroup_id) blockIdx : vec3u
) {
    let instance = threadIdx.x;
    let ntt_block_size = thread_block_size * 2;  // one thread handle two places
    let ntt_half_block_size = thread_block_size;
    let global_offset = blockIdx.x * ntt_block_size;

    var x : bigint;
    var y : bigint;
    var w : bigint;

    // Load from global memory to shared memory
    ntt_workgroup_cache[instance] = ntt_buffer[global_offset + instance];
    ntt_workgroup_cache[instance + ntt_half_block_size] = ntt_buffer[global_offset + instance + ntt_half_block_size];

    workgroupBarrier();

    {
        let k = instance * 2;

        x = ntt_workgroup_cache[k];
        y = ntt_workgroup_cache[k + 1];

        let ucc = bigint_sub_cc(x, Fp_2p);
        if (!ucc.carry) {
            x = ucc.sum;
        }

        let vcc = bigint_sub_cc(y, Fp_2p);
        if (!vcc.carry) {
            y = vcc.sum;
        }

        ntt_workgroup_cache[k]     = bigint_add(x, y);
        ntt_workgroup_cache[k + 1] = bigint_add(x, bigint_sub(Fp_2p, y));

        workgroupBarrier();
    }

    let iterations = u32(log2(f32(ntt_block_size)));

    for (var iter : u32 = 2; iter <= iterations; iter++) {
        let M  = 1u << iter;
        let M2 = M >> 1;
        let omega_base = M2 - 1;

        let ntt_group = instance / M2;
        let ntt_index = instance % M2;
        let k = ntt_group * M + ntt_index;

        x = ntt_workgroup_cache[k];
        y = ntt_workgroup_cache[k + M2];

        w = ntt_omegas[omega_base + ntt_index];
        y = montgomery_mul_2p(y, w);

        let cc = bigint_sub_cc(x, Fp_2p);
        if (!cc.carry) {
            x = cc.sum;
        }

        ntt_workgroup_cache[k]      = bigint_add(x, y);
        ntt_workgroup_cache[k + M2] = bigint_add(x, bigint_sub(Fp_2p, y));

        workgroupBarrier();
    }

    // Store result to global memory
    ntt_buffer[global_offset + instance] = ntt_workgroup_cache[instance];
    ntt_buffer[global_offset + instance + ntt_half_block_size] = ntt_workgroup_cache[instance + ntt_half_block_size];
}

@compute @workgroup_size(thread_block_size)
fn EltwiseAddMod(@builtin(global_invocation_id) globalIdx : vec3u, 
                 @builtin(num_workgroups) workgroups : vec3u) 
{
    var out : bigint;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   = vector_x[idx];
        let y   = vector_y[idx];
        out     = bigint_add(x, y);

        // Adjust overflow
        let cc = bigint_sub_cc(out, Fp_p);
        if (!cc.carry) {
            out = cc.sum;
        }

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseAddAssignMod(@builtin(global_invocation_id) globalIdx : vec3u,
                       @builtin(num_workgroups) workgroups : vec3u)
{
    var out : bigint;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   = vector_x[idx];
        let y   = vector_out[idx];
        out     = bigint_add(x, y);

        // Adjust overflow
        let cc = bigint_sub_cc(out, Fp_p);
        if (!cc.carry) {
            out = cc.sum;
        }

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseAddConstantMod(@builtin(global_invocation_id) globalIdx : vec3u,
                         @builtin(num_workgroups) workgroups : vec3u)
{
    var out : bigint;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   = vector_x[idx];
        out     = bigint_add(x, input_scalar);

        // Adjust overflow
        let cc = bigint_sub_cc(out, Fp_p);
        if (!cc.carry) {
            out = cc.sum;
        }

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseSubMod(@builtin(global_invocation_id) globalIdx : vec3u,
                 @builtin(num_workgroups) workgroups : vec3u)
{
    var out : bigint_cc;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   = vector_x[idx];
        let y   = vector_y[idx];
        out     = bigint_sub_cc(x, y);

        if (out.carry) {
            out.sum = bigint_add(out.sum, Fp_p);
        }

        vector_out[idx] = out.sum;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseSubConstantMod(@builtin(global_invocation_id) globalIdx : vec3u,
                         @builtin(num_workgroups) workgroups : vec3u)
{
    var out : bigint_cc;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x = vector_x[idx];
        out   = bigint_sub_cc(x, input_scalar);

        if (out.carry) {
            out.sum = bigint_add(out.sum, Fp_p);
        }

        vector_out[idx] = out.sum;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseConstantSubMod(@builtin(global_invocation_id) globalIdx : vec3u,
                         @builtin(num_workgroups) workgroups : vec3u)
{
    var out : bigint_cc;
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x = vector_x[idx];
        out   = bigint_sub_cc(input_scalar, x);

        if (out.carry) {
            out.sum = bigint_add(out.sum, Fp_p);
        }

        vector_out[idx] = out.sum;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseMultMod(@builtin(global_invocation_id) globalIdx : vec3u,
                  @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x : bigint = vector_x[idx];
        let y : bigint = vector_y[idx];

        let wide        = bigint_mul_wide(x, y);
        vector_out[idx] = barrett_reduce_wide(wide);
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseMultConstantMod(@builtin(global_invocation_id) globalIdx : vec3u,
                          @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x : bigint = vector_x[idx];

        let wide        = bigint_mul_wide(x, input_scalar);
        vector_out[idx] = barrett_reduce_wide(wide);
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseMontMultConstantMod(@builtin(global_invocation_id) globalIdx : vec3u,
                              @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   : bigint = vector_x[idx];
        let out : bigint = montgomery_mul(x, input_scalar);
        vector_out[idx]  = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseDivMod(@builtin(global_invocation_id) globalIdx : vec3u,
                 @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x : bigint = vector_x[idx];
        let y : bigint = vector_y[idx];

        let inv  = modinv(y, Fp_p);
        let wide = bigint_mul_wide(x, inv);
        let out  = barrett_reduce_wide(wide);

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseFMAMod(@builtin(global_invocation_id) globalIdx : vec3u,
                 @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   : bigint = vector_x[idx];
        let y   : bigint = vector_y[idx];
        var out : bigint = vector_out[idx];

        let wide = bigint_mul_wide(x, y);
        let tmp  = barrett_reduce_wide(wide);
        out      = bigint_add(out, tmp);
        let cc   = bigint_sub_cc(out, Fp_p);
        if (!cc.carry) {
            out = cc.sum;
        }

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseFMAConstantMod(@builtin(global_invocation_id) globalIdx : vec3u,
                         @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&vector_x); idx += workgroups.x * thread_block_size) {
        let x   : bigint = vector_x[idx];
        var out : bigint = vector_out[idx];

        let wide = bigint_mul_wide(x, input_scalar);
        let tmp  = barrett_reduce_wide(wide);
        out      = bigint_add(out, tmp);
        let cc   = bigint_sub_cc(out, Fp_p);
        if (!cc.carry) {
            out = cc.sum;
        }

        vector_out[idx] = out;
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwiseBitDecompose(@builtin(global_invocation_id) globalIdx : vec3u) {
    let idx = globalIdx.x;
    var x   : bigint = vector_x[idx];

    let bit_index : u32 = input_scalar.limbs[0].limbs[0];
    let bit       : u32 = bigint_select_bit(&x, bit_index);

    vector_out[idx] = bigint_from_u32(bit);
}

@compute @workgroup_size(thread_block_size)
fn EltwisePowMod(@builtin(global_invocation_id) globalIdx : vec3u,
                   @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&powmod_exp); idx += workgroups.x * thread_block_size) {
        let exp   : u32    = powmod_exp[idx];
        let coeff : bigint = powmod_coeff[idx];

        let pow : bigint = powmod(&powmod_table, exp);
        powmod_out[idx]  = montgomery_mul(coeff, pow);
    }
}

@compute @workgroup_size(thread_block_size)
fn EltwisePowAddMod(@builtin(global_invocation_id) globalIdx : vec3u,
                      @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < arrayLength(&powmod_exp); idx += workgroups.x * thread_block_size) {
        let exp   : u32    = powmod_exp[idx];
        let coeff : bigint = powmod_coeff[idx];
        let pow   : bigint = montgomery_mul(coeff, powmod(&powmod_table, exp));
        let sum   : bigint = bigint_add(pow, powmod_out[idx]);

        let cc = bigint_sub_cc(sum, Fp_p);
        if (cc.carry) {
            powmod_out[idx] = sum;
        }
        else {
            powmod_out[idx] = cc.sum;
        }
    }
}

// ---------- Sampling ----------

@compute @workgroup_size(thread_block_size)
fn sample_gather(@builtin(global_invocation_id) globalIdx : vec3u,
                 @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < num_sampling; idx += workgroups.x * thread_block_size) {
        let gather_index = sample_index[idx][0];
        vector_out[idx] = vector_x[gather_index];
    }
}
