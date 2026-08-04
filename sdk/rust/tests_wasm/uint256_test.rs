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

//! `Uint256`: construction, conversion, and the checked arithmetic — multiply, divide, mod and
//! invmod.
//!
//! The arithmetic here proves an out-of-circuit oracle's answer, so a passing proof means the
//! multiply-back and range checks actually bind. Every vector is taken from the C++ suites so
//! the two stay comparable.
//!
//! The `Bn254FrBigint` layer these are built on has its own suite in `bn254fr_bigint_test.rs`.
//!
//! `to_bytes_little`/`to_bytes_big` are only tested in their checked form, because that is the
//! only form this SDK exposes — there is no unchecked byte export to pair with the C++
//! `test_to_bytes_little(false)`.

#[path = "common/mod.rs"]
mod common;

use common::check;

use ligetron::bn254fr::{assert_equal_u32, Bn254Fr};
use ligetron::uint256::{self, Uint256, Uint256Wide, UINT256_NLIMBS};

// ---------------------------------------------------------------- helpers

fn u256(s: &str) -> Uint256 {
    Uint256::from_str(s, 10)
}

/// Constrains a value's limbs against decimal literals, most-significant limb last.
fn assert_words_eq(val: &Uint256, expected: [&str; UINT256_NLIMBS]) {
    let words = val.get_words();
    for i in 0..UINT256_NLIMBS {
        let mut exp = Bn254Fr::new();
        exp.set_str(expected[i], 10);
        Bn254Fr::assert_equal(&words[i], &exp);
    }
}

/// Constrains a value's limbs against `u64` literals, avoiding any hand hex-to-decimal step.
fn assert_uint_words_eq(val: &Uint256, expected: [u64; UINT256_NLIMBS]) {
    let words = val.get_words();
    for i in 0..UINT256_NLIMBS {
        Bn254Fr::assert_equal(&words[i], &Bn254Fr::from_u64(expected[i]));
    }
}

/// The decimal string used across the C++ suite, and its limb decomposition.
const REF_STR: &str = "241978572001512527289694654294400568637203164540116421040";
const REF_WORDS: [&str; UINT256_NLIMBS] = [
    "17770160115856198064",
    "10893452603207674376",
    "711111111019555310",
    "0",
];

// ---------------------------------------------------------------- construction

fn test_ctor_dtor() {
    assert_uint_words_eq(&Uint256::new(), [0, 0, 0, 0]);
}

fn test_set_u64_get_u64() {
    let uval: u64 = 0x0352_1787;
    let mut x = Uint256::new();
    x.set_u64(uval);
    check(x.get_u64() == uval);
    assert_uint_words_eq(&x, [uval, 0, 0, 0]);

    // set_u32 shares the path and must zero the upper limbs too.
    let mut y = Uint256::new();
    y.set_u32(0x1234_5678);
    check(y.get_u64() == 0x1234_5678);
    assert_uint_words_eq(&y, [0x1234_5678, 0, 0, 0]);
}

fn test_set_words() {
    let words_u64: [u64; UINT256_NLIMBS] = [0x0012_23EA, 0xF781_A231, 0x2349_871E, 0x2213_4198];
    let words: [Bn254Fr; UINT256_NLIMBS] = std::array::from_fn(|i| Bn254Fr::from_u64(words_u64[i]));

    let mut x = Uint256::new();
    x.set_words_checked(&words);
    assert_uint_words_eq(&x, words_u64);

    // set_words additionally range-checks each limb.
    let mut y = Uint256::new();
    y.set_words(&words);
    assert_uint_words_eq(&y, words_u64);
}

fn test_set_str() {
    assert_words_eq(&u256(REF_STR), REF_WORDS);
}

fn test_print() {
    u256(REF_STR).print();
}

fn test_copy_checked() {
    let x = u256(REF_STR);
    let mut y = Uint256::new();
    y.copy_checked(&x);
    assert_words_eq(&y, REF_WORDS);

    // Clone goes through the same path.
    assert_words_eq(&x.clone(), REF_WORDS);
}

fn test_set_bn254_checked() {
    let uval: u64 = 0x0001_2378_AF62;
    let mut x = Uint256::new();
    x.set_bn254(&Bn254Fr::from_u64(uval));
    assert_uint_words_eq(&x, [uval, 0, 0, 0]);
}

// ---------------------------------------------------------------- byte conversion

const DATA_LITTLE: [u8; 32] = [
    0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6, 0x08, 0x6a, 0xbf, 0x37, 0x6d, 0x51, 0x2d, 0x97,
    0xee, 0x69, 0x27, 0xb0, 0xc9, 0x5f, 0xde, 0x09, 0xaa, 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const DATA_BIG: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69, 0xEE,
    0x97, 0x2D, 0x51, 0x6D, 0x37, 0xBF, 0x6A, 0x08, 0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0,
];

fn test_set_bytes() {
    // 26 bytes: partial top limb, little-endian.
    let mut a = Uint256::new();
    a.set_bytes_little(&DATA_LITTLE[0..26]);
    assert_words_eq(
        &a,
        [
            "17770160115856198064",
            "10893452603207674376",
            "711111111019555310",
            "48042",
        ],
    );
    let mut a_u = Uint256::new();
    a_u.set_bytes_little_unchecked(&DATA_LITTLE[0..26]);
    uint256::assert_equal(&a_u, &a);

    // Full 32 bytes, little-endian.
    let mut b = Uint256::new();
    b.set_bytes_little(&DATA_LITTLE);
    assert_words_eq(
        &b,
        [
            "17770160115856198064",
            "10893452603207674376",
            "711111111019555310",
            "18446744073709534122",
        ],
    );

    // Fewer bytes than one limb.
    let mut c = Uint256::new();
    c.set_bytes_little(&DATA_LITTLE[0..3]);
    assert_words_eq(&c, ["7096752", "0", "0", "0"]);

    // 28 bytes: partial top limb, big-endian — the shape that broke the bigint path.
    let mut d = Uint256::new();
    d.set_bytes_big(&DATA_BIG_28);
    assert_words_eq(
        &d,
        [
            "17770160115856198064",
            "10893452603207674376",
            "711111111019555310",
            "268435456",
        ],
    );
    let mut d_u = Uint256::new();
    d_u.set_bytes_big_unchecked(&DATA_BIG_28);
    uint256::assert_equal(&d_u, &d);

    // Full 32 bytes, big-endian.
    let mut e = Uint256::new();
    e.set_bytes_big(&DATA_BIG);
    assert_words_eq(
        &e,
        [
            "17770160115856198064",
            "10893452603207674376",
            "711111111019555310",
            "1152921508901814271",
        ],
    );

    // Three bytes, big-endian.
    let mut f = Uint256::new();
    f.set_bytes_big(&[0xF6, 0x9C, 0x4A]);
    assert_words_eq(&f, ["16161866", "0", "0", "0"]);
}

const DATA_BIG_28: [u8; 28] = [
    0x10, 0x00, 0x00, 0x00, 0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69, 0xEE, 0x97, 0x2D, 0x51, 0x6D,
    0x37, 0xBF, 0x6A, 0x08, 0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C, 0x49, 0xB0,
];

fn test_to_bytes_little() {
    let expected: [u8; 32] = [
        0xb0, 0x49, 0x6c, 0x9b, 0x79, 0x4a, 0x9c, 0xf6, 0x08, 0x6a, 0xbf, 0x37, 0x6d, 0x51, 0x2d,
        0x97, 0xee, 0x69, 0x27, 0xb0, 0xc9, 0x5f, 0xde, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    let words: [Bn254Fr; UINT256_NLIMBS] = std::array::from_fn(|i| {
        let mut f = Bn254Fr::new();
        f.set_str(REF_WORDS[i], 10);
        f
    });
    let mut val = Uint256::new();
    val.set_words_checked(&words);

    let got = val.to_bytes_little();
    for i in 0..32 {
        check(got[i] == expected[i]);
    }
}

fn test_to_bytes_big() {
    let expected: [u8; 32] = [
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xDE, 0x5F, 0xC9, 0xB0, 0x27, 0x69,
        0xEE, 0x97, 0x2D, 0x51, 0x6D, 0x37, 0xBF, 0x6A, 0x08, 0xF6, 0x9C, 0x4A, 0x79, 0x9B, 0x6C,
        0x49, 0xB0,
    ];

    let top = "1152921504606846976";
    let words: [Bn254Fr; UINT256_NLIMBS] = std::array::from_fn(|i| {
        let mut f = Bn254Fr::new();
        f.set_str(if i == 3 { top } else { REF_WORDS[i] }, 10);
        f
    });
    let mut val = Uint256::new();
    val.set_words_checked(&words);

    let got = val.to_bytes_big();
    for i in 0..32 {
        check(got[i] == expected[i]);
    }
}

fn test_bytes_round_trip() {
    let x = u256(REF_STR);

    let mut back = Uint256::new();
    back.set_bytes_little(&x.to_bytes_little());
    uint256::assert_equal(&back, &x);

    let mut back_big = Uint256::new();
    back_big.set_bytes_big(&x.to_bytes_big());
    uint256::assert_equal(&back_big, &x);
}

// ---------------------------------------------------------------- bits

fn test_to_from_bits() {
    let x = u256("115792089210356248762697446949407573530086143415211086033018482518360559134033");
    let bits = x.to_bits();
    check(bits.len() == 256);
    uint256::assert_equal(&Uint256::from_bits(&bits), &x);
}

// ---------------------------------------------------------------- add / sub with carry

fn do_test_add_cc(a: &str, b: &str, exp: &str, exp_carry: bool) {
    let res = uint256::add_cc(&u256(a), &u256(b));
    uint256::assert_equal(&res.val, &u256(exp));
    assert_equal_u32(&res.carry, u32::from(exp_carry));
}

fn test_add_cc() {
    do_test_add_cc("10", "20", "30", false);

    do_test_add_cc(
        "1234567890123456789012345678901234567890123456789012345678901234",
        "987654321098765432109876543210987654321098765432109876543210987",
        "2222222211222222221122222222112222222211222222221122222222112221",
        false,
    );

    do_test_add_cc(
        "340282366920938463463374607431768211455",
        "999999999999999999999999999999999999",
        "341282366920938463463374607431768211454",
        false,
    );

    do_test_add_cc(
        "11579208923731619542357098500868790785326998466564056403945758400791312963980",
        "1",
        "11579208923731619542357098500868790785326998466564056403945758400791312963981",
        false,
    );

    // Wraps: 2^256 - 1 + 10 == 9 with carry out.
    do_test_add_cc(MAX_256, "10", "9", true);
}

fn do_test_sub_cc(a: &str, b: &str, exp: &str, exp_borrow: bool) {
    let res = uint256::sub_cc(&u256(a), &u256(b));
    uint256::assert_equal(&res.val, &u256(exp));
    assert_equal_u32(&res.carry, u32::from(exp_borrow));
}

fn test_sub_cc() {
    do_test_sub_cc("30", "20", "10", false);

    do_test_sub_cc(
        "2222222211222222221122222222112222222211222222221122222222112221",
        "987654321098765432109876543210987654321098765432109876543210987",
        "1234567890123456789012345678901234567890123456789012345678901234",
        false,
    );

    do_test_sub_cc(
        "341282366920938463463374607431768211454",
        "999999999999999999999999999999999999",
        "340282366920938463463374607431768211455",
        false,
    );

    do_test_sub_cc(
        "11579208923731619542357098500868790785326998466564056403945758400791312963981",
        "1",
        "11579208923731619542357098500868790785326998466564056403945758400791312963980",
        false,
    );

    // Underflows to 2^256 - 1 with the borrow set.
    do_test_sub_cc("9", "10", MAX_256, true);
}

// ---------------------------------------------------------------- predicates and selection

fn do_test_eq(a: &str, b: &str, expected: bool) {
    assert_equal_u32(&uint256::eq(&u256(a), &u256(b)), u32::from(expected));
}

fn test_eq() {
    do_test_eq("1", "1", true);
    do_test_eq("1", "0", false);
    do_test_eq(
        "11579208923731619542357098500868790785326998466564056403945758400791312963994",
        "11579208923731619542357098500868790785326998466564056403945758400791312963994",
        true,
    );
    do_test_eq(
        "11579208923731619542357098500868790785326998466564056403945758400791312963994",
        "11579208923712312312390012380913096564056403945758400791312963994",
        false,
    );
}

fn test_eqz() {
    assert_equal_u32(&uint256::eqz(&Uint256::new()), 1);
    assert_equal_u32(&uint256::eqz(&u256("1")), 0);
    assert_equal_u32(&uint256::eqz(&u256(MAX_256)), 0);
}

fn test_mux() {
    let a = u256("115792089210356248762697446949407573530086143415211086033018482518360559134033");
    let b = u256("21888242871839275222246405745257275088548364400416034343698204186575808495617");

    // The second value is selected when cond is 1.
    uint256::assert_equal(&uint256::mux(&Bn254Fr::from_u32(1), &a, &b), &b);
    uint256::assert_equal(&uint256::mux(&Bn254Fr::new(), &a, &b), &a);
}

// ---------------------------------------------------------------- Uint256 multiply

// ---------------------------------------------------------------- Uint256 multiply

const MAX_128: &str = "340282366920938463463374607431768211455"; // 2^128 - 1
const POW_128: &str = "340282366920938463463374607431768211456"; // 2^128
const MAX_256: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935"; // 2^256 - 1

fn do_test_mul_wide(a: &str, b: &str, exp_low: &str, exp_high: &str) {
    let res = uint256::mul_wide(&u256(a), &u256(b));
    uint256::assert_equal(&res.lo, &u256(exp_low));
    uint256::assert_equal(&res.hi, &u256(exp_high));
}

fn test_mul_wide() {
    do_test_mul_wide("2", "3", "6", "0");

    // Max 128-bit x Max 128-bit = 256-bit result (no high word overflow)
    do_test_mul_wide(
        MAX_128,
        MAX_128,
        "115792089237316195423570985008687907852589419931798687112530834793049593217025",
        "0",
    );

    // Max 256-bit x 1 = same value
    do_test_mul_wide(MAX_256, "1", MAX_256, "0");

    // Max 256-bit x 2 = 2^256 - 2 (low) with carry (high = 1)
    do_test_mul_wide(
        MAX_256,
        "2",
        "115792089237316195423570985008687907853269984665640564039457584007913129639934",
        "1",
    );

    // 2^128 x 2^128 = 2^256 (all zeros in low, high = 1)
    do_test_mul_wide(POW_128, POW_128, "0", "1");

    do_test_mul_wide(
        "115792089237316195423570985008687907853269984665640564039457584007913129638000",
        MAX_128,
        "115792089237316195423570985008687907194483322306703698774364344020009872263056",
        "340282366920938463463374607431768211454",
    );
}

// ---------------------------------------------------------------- 512-bit divide

fn do_test_divide_qr(
    a_low: &str,
    a_high: &str,
    b: &str,
    exp_q_low: &str,
    exp_q_high: &str,
    exp_r: &str,
) {
    let wide = Uint256Wide {
        lo: u256(a_low),
        hi: u256(a_high),
    };

    let (q_low, q_high, r) = wide.divide_qr_normalized(&u256(b));

    uint256::assert_equal(&q_low, &u256(exp_q_low));
    let mut expected_q_high = Bn254Fr::new();
    expected_q_high.set_str(exp_q_high, 10);
    Bn254Fr::assert_equal(&q_high, &expected_q_high);
    uint256::assert_equal(&r, &u256(exp_r));
}

fn test_divide_qr() {
    do_test_divide_qr("100", "0", "10", "10", "0", "0");

    // Boundary: divisor = 2^192, the smallest the 256+64-bit quotient can take. The most
    // significant limb is nonzero but the top bit is clear, and the quotient is exactly
    // 2^320 - 1, so q_high sits at 2^64 - 1. Anything smaller overflows q_high.
    do_test_divide_qr(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "6277101735386680763835789423207666416102355444464034512896",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "18446744073709551615",
        "6277101735386680763835789423207666416102355444464034512895",
    );

    do_test_divide_qr("123456789", "0", "100", "1234567", "0", "89");

    do_test_divide_qr(
        "0",
        "1",
        "2",
        "57896044618658097711785492504343953926634992332820282019728792003956564819968", // 2^255
        "0",
        "0",
    );

    do_test_divide_qr(
        "5",
        "1",
        "10",
        "11579208923731619542357098500868790785326998466564056403945758400791312963994",
        "0",
        "1",
    );

    // The only vector with a non-zero quotient high limb.
    do_test_divide_qr("1", "1", "1", "1", "1", "0");

    do_test_divide_qr(
        "100",
        MAX_256,
        "115792089237316195423570985008687907853269984665640564039457584007913129639926", // 2^256 - 10
        "9",
        "1",
        "190",
    );
}

// ---------------------------------------------------------------- 512-bit mod

/// `uint512_mod` over a 512-bit dividend `hi:lo`.
fn do_test_uint512_mod(lo: &str, hi: &str, m: &str, exp: &str) {
    let wide = Uint256Wide {
        lo: u256(lo),
        hi: u256(hi),
    };
    uint256::assert_equal(&uint256::uint512_mod(&wide, &u256(m)), &u256(exp));
}

fn test_uint512_mod() {
    // The original vector: 100 + MAX_256 * 2^256, reduced by 2^256 - 10.
    let wide = Uint256Wide {
        lo: u256("100"),
        hi: u256(MAX_256),
    };
    let m = u256("115792089237316195423570985008687907853269984665640564039457584007913129639926");
    uint256::assert_equal(&uint256::uint512_mod(&wide, &m), &u256("190"));

    // m = 2^256 - 189. The modulus's most significant limb must be nonzero, i.e. m >= 2^192:
    // `divide_qr_normalized` sizes the quotient at 256 + 64 bits, and a smaller divisor can
    // overflow that. That is the limb condition, NOT the stronger top-bit-set sense of
    // "normalized". Violating it is not silent -- the quotient comes back truncated and the
    // multiply-back assertion `q*b + r == a` fails -- but every vector here stays inside the
    // precondition.
    const M: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639747";

    // 0 mod m
    do_test_uint512_mod("0", "0", M, "0");

    // m-1: below the modulus, so no reduction happens
    do_test_uint512_mod(
        "115792089237316195423570985008687907853269984665640564039457584007913129639746",
        "0",
        M,
        "115792089237316195423570985008687907853269984665640564039457584007913129639746",
    );

    // exactly 2^256, i.e. the low limb group empty and hi = 1
    do_test_uint512_mod("0", "1", M, "189");

    // the widest possible dividend, 2^512 - 1
    do_test_uint512_mod(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
        M,
        "35720",
    );

    // m * 2^256 -- an exact multiple, so the remainder is zero
    do_test_uint512_mod(
        "0",
        "115792089237316195423570985008687907853269984665640564039457584007913129639747",
        M,
        "0",
    );
}

// ---------------------------------------------------------------- modular inverse

fn do_test_inv(a: &str, m: &str, exp: &str) {
    uint256::assert_equal(&uint256::invmod(&u256(a), &u256(m)), &u256(exp));
}

fn test_inv() {
    do_test_inv("3", "11", "4");
    do_test_inv("1", "97", "1");
    do_test_inv("17", "97", "40");

    // inverse of 5 mod the BN254 scalar field modulus
    do_test_inv(
        "5",
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        "8755297148735710088898562298102910035419345760166413737479281674630323398247",
    );

    // inverse of 3 mod the secp256k1 field prime
    do_test_inv(
        "3",
        "115792089237316195423570985008687907852837564279074904382605163141518161494337",
        "77194726158210796949047323339125271901891709519383269588403442094345440996225",
    );

    // m-1 is its own inverse, since (m-1)^2 = m^2 - 2m + 1 === 1 (mod m).
    do_test_inv("96", "97", "96");
    do_test_inv(
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        "21888242871839275222246405745257275088548364400416034343698204186575808495616",
    );

    do_test_inv(
        "92083353579669972405495757776470670379717099030169638017457449866473924951844",
        "115792089210356248762697446949407573530086143415211086033018482518360559134033",
        "107144220426932500591649118614422298517760573469212118502069469584724027903412",
    );
}

fn main() {
    test_ctor_dtor();
    test_set_u64_get_u64();
    test_set_words();
    test_set_str();
    test_print();
    test_copy_checked();
    test_set_bn254_checked();

    test_set_bytes();
    test_to_bytes_little();
    test_to_bytes_big();
    test_bytes_round_trip();
    test_to_from_bits();

    test_add_cc();
    test_sub_cc();
    test_eq();
    test_eqz();
    test_mux();

    test_mul_wide();
    test_divide_qr();
    test_uint512_mod();
    test_inv();
}
