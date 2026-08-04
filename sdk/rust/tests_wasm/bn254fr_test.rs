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

//! The BN254 scalar API: constants, byte and bit conversion, literal assertions, and selection.
//!
//! Every value that stands in for private data goes through `witness_cast_*` first. Without
//! that the operand is a compile-time constant, the backend folds it, and the test passes
//! without exercising a single constraint — so the casts are what make this suite mean
//! anything.
//!
//! Two C++ cases have no counterpart here on purpose. `test_to_bits`/`test_from_bits` cover the
//! *unchecked* `bn254fr_to_bits`/`bn254fr_from_bits`, which this SDK deliberately does not
//! expose: `Bn254Fr::to_bits` is the checked form, and an unbound bit decomposition in the
//! public API would be a footgun with no caller. The checked pair is covered below.

#[path = "common/mod.rs"]
mod common;

use common::check;

use ligetron::api::{witness_cast_u32, witness_cast_u64};
use ligetron::bn254fr::{
    self, assert_equal_bytes, assert_equal_u32, assert_equal_u64, mux, mux2, to_bytes,
    to_bytes_checked, Bn254Fr, ORDER_LITTLE,
};

// ---------------------------------------------------------------- constants

fn test_set_get_u32() {
    let pub_x: u32 = 10;
    let priv_x = witness_cast_u32(0x2231_2231);

    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_u32(pub_x);
    check(pub_bn.get_u64() == 10);

    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_u32(priv_x);
    check(priv_bn.get_u64() == u64::from(priv_x));
}

fn test_set_get_u64() {
    let pub_x: u64 = 20;
    let priv_x = witness_cast_u64(0x0565_99a3_2826_a8b4);

    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_u64(pub_x);
    check(pub_bn.get_u64() == 20);

    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_u64_checked(priv_x);
    check(priv_bn.get_u64() == priv_x);
}

fn test_set_get_u64_checked() {
    let priv_x = witness_cast_u64(0x0565_99a3_2826_a8b4);

    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_u64(20);
    check(pub_bn.get_u64_checked() == 20);

    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_u64_checked(priv_x);
    check(priv_bn.get_u64_checked() == priv_x);

    // set_u32_checked has no C++ test of its own; it pairs with the u64 form.
    let mut small = Bn254Fr::new();
    small.set_u32_checked(witness_cast_u32(0x1234_5678));
    check(small.get_u64_checked() == 0x1234_5678);
}

// ---------------------------------------------------------------- bytes

const X_STR: &str = "0x127788238591756923AF8211934512AABB";

/// The little-endian 32-byte encoding of [`X_STR`], read back as four 64-bit words.
fn check_x_words(bytes: &[u8; 32]) {
    check(u64::from_le_bytes(bytes[0..8].try_into().unwrap()) == 0xAF82_1193_4512_AABB);
    check(u64::from_le_bytes(bytes[8..16].try_into().unwrap()) == 0x7788_2385_9175_6923);
    check(u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == 0x12);
    check(u64::from_le_bytes(bytes[24..32].try_into().unwrap()) == 0x0);
}

fn test_to_bytes() {
    // Pre-filled with a non-zero pattern, so a short write would show up.
    let mut bytes = [1u8; 32];
    to_bytes(&mut bytes, &Bn254Fr::from_str(X_STR), ORDER_LITTLE);
    check_x_words(&bytes);
}

fn test_to_bytes_checked() {
    let mut bytes = [1u8; 32];
    to_bytes_checked(&mut bytes, &Bn254Fr::from_str(X_STR), ORDER_LITTLE);
    check_x_words(&bytes);
}

fn test_set_bytes_checked() {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&0xAF82_1193_4512_AABBu64.to_le_bytes());
    bytes[8..16].copy_from_slice(&0x7788_2385_9175_6923u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&0x12u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0u64.to_le_bytes());

    // The checked import is set_bytes_little followed by assert_equal_bytes; the SDK writes it
    // that way rather than as one call.
    let mut x = Bn254Fr::new();
    x.set_bytes_little(&bytes);
    assert_equal_bytes(&x, &bytes, ORDER_LITTLE);

    Bn254Fr::assert_equal(&x, &Bn254Fr::from_str(X_STR));
}

fn test_to_bytes_round_trip() {
    // Export then re-import must land on the same element, in both byte orders.
    let x = Bn254Fr::from_str(X_STR);

    let mut little = [0u8; 32];
    to_bytes_checked(&mut little, &x, ORDER_LITTLE);
    let mut back = Bn254Fr::new();
    back.set_bytes_little(&little);
    Bn254Fr::assert_equal(&back, &x);

    let mut big = [0u8; 32];
    to_bytes_checked(&mut big, &x, bn254fr::ORDER_BIG);
    let mut back_big = Bn254Fr::new();
    back_big.set_bytes_big(&big);
    Bn254Fr::assert_equal(&back_big, &x);

    // The two encodings must be byte reversals of each other.
    for i in 0..32 {
        check(little[i] == big[31 - i]);
    }
}

// ---------------------------------------------------------------- literal assertions

fn test_assert_equal_u32() {
    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_u32(20);
    assert_equal_u32(&pub_bn, 20);

    let priv_u32 = witness_cast_u32(0x2355_1123);
    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_u32(priv_u32);
    assert_equal_u32(&priv_bn, priv_u32);
}

fn test_assert_equal_u64() {
    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_u64(0xAB_1233_2222);
    assert_equal_u64(&pub_bn, 0xAB_1233_2222);

    let priv_u64 = witness_cast_u64(0x2255_8812_3812_4123);
    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_u64(priv_u64);
    assert_equal_u64(&priv_bn, priv_u64);
}

fn test_assert_equal_bytes() {
    let pub_u64: u64 = 0x00A7_28D8_2287_F823;
    let pub_bytes = pub_u64.to_le_bytes();
    let mut pub_bn = Bn254Fr::new();
    pub_bn.set_bytes_little(&pub_bytes);
    assert_equal_bytes(&pub_bn, &pub_bytes, ORDER_LITTLE);

    let priv_u64 = witness_cast_u64(0x2789_8AF2_2712_3123);
    let priv_bytes = priv_u64.to_le_bytes();
    let mut priv_bn = Bn254Fr::new();
    priv_bn.set_bytes_little(&priv_bytes);
    assert_equal_bytes(&priv_bn, &priv_bytes, ORDER_LITTLE);
}

// ---------------------------------------------------------------- bits

fn do_test_to_bits(val: u64, count: usize) {
    let mut x = Bn254Fr::new();
    x.set_u64(witness_cast_u64(val));

    let bits = x.to_bits(count);
    check(bits.len() == count);

    for i in 0..count {
        assert_equal_u32(&bits[i], ((val >> i) & 1) as u32);
    }
}

fn do_test_from_bits(val: u64, count: usize) {
    let bits: Vec<Bn254Fr> = (0..count)
        .map(|i| Bn254Fr::from_u32(((val >> i) & 1) as u32))
        .collect();

    let res = Bn254Fr::from_bits_checked(&bits);
    assert_equal_u64(&res, val);
}

fn test_to_bits_checked() {
    do_test_to_bits(0x0F83_34AA_820F_1D23, 64);
}

fn test_from_bits_checked() {
    do_test_from_bits(0x0F81_23AA_820F_1D23, 64);
}

fn test_bits_round_trip() {
    let val = witness_cast_u64(0x0F83_34AA_820F_1D23);
    let mut x = Bn254Fr::new();
    x.set_u64(val);
    let back = Bn254Fr::from_bits_checked(&x.to_bits(64));
    Bn254Fr::assert_equal(&back, &x);
}

// ---------------------------------------------------------------- selection

fn test_mux() {
    let a = Bn254Fr::from_str("72177213123123123");
    let b = Bn254Fr::from_str("2819237812312312312738123");
    let cond_0 = Bn254Fr::new(); // 0
    let cond_1 = Bn254Fr::from_u32(1);

    let mut res_0 = Bn254Fr::new();
    let mut res_1 = Bn254Fr::new();
    mux(&mut res_0, &cond_0, &a, &b);
    mux(&mut res_1, &cond_1, &a, &b);

    Bn254Fr::assert_equal(&res_0, &a);
    Bn254Fr::assert_equal(&res_1, &b);
}

fn test_mux2() {
    let a0 = Bn254Fr::from_str("72177213123123123");
    let a1 = Bn254Fr::from_str("2819237812312312312738123");
    let a2 = Bn254Fr::from_str("882381231231");
    let a3 = Bn254Fr::from_str("69912812737727232");

    let zero = Bn254Fr::new();
    let one = Bn254Fr::from_u32(1);

    // Selector order is (s0, s1); the C++ expectations pin the bit ordering.
    let mut r00 = Bn254Fr::new();
    let mut r01 = Bn254Fr::new();
    let mut r10 = Bn254Fr::new();
    let mut r11 = Bn254Fr::new();
    mux2(&mut r00, &zero, &zero, &a0, &a1, &a2, &a3);
    mux2(&mut r01, &zero, &one, &a0, &a1, &a2, &a3);
    mux2(&mut r10, &one, &zero, &a0, &a1, &a2, &a3);
    mux2(&mut r11, &one, &one, &a0, &a1, &a2, &a3);

    Bn254Fr::assert_equal(&r00, &a0);
    Bn254Fr::assert_equal(&r01, &a2);
    Bn254Fr::assert_equal(&r10, &a1);
    Bn254Fr::assert_equal(&r11, &a3);
}

fn main() {
    test_to_bits_checked();
    test_from_bits_checked();
    test_bits_round_trip();

    test_set_get_u32();
    test_set_get_u64();
    test_set_get_u64_checked();

    test_to_bytes();
    test_to_bytes_checked();
    test_set_bytes_checked();
    test_to_bytes_round_trip();

    test_assert_equal_u32();
    test_assert_equal_u64();
    test_assert_equal_bytes();

    test_mux();
    test_mux2();
}
