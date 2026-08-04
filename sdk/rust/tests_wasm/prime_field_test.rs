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

//! The `ff` prime field layer: construction, arithmetic, and import/export.
//!
//! This is the layer `ecc` and everything above it is built on, so it is the one place where an
//! under-constrained operation would be invisible in every other suite and still poison them
//! all.
//!
//! The field is declared here through the public [`impl_prime_field!`] macro rather than reusing
//! `P256Base`, which additionally checks that a *user-defined* field works with nothing but the
//! crate's public API.

#[path = "common/mod.rs"]
mod common;

use common::check;

use ligetron::bn254fr::{assert_equal_u32, Bn254Fr};
use ligetron::ff::FieldElement;
use ligetron::impl_prime_field;
use ligetron::uint256::{self, Uint256};

/// The P-256 base field prime, matching the C++ `test_field`.
#[derive(Copy, Clone, Debug)]
pub struct TestField;
impl_prime_field!(
    TestField,
    "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
);

type FE = FieldElement<TestField>;

/// prime - 1, used by the reduction cases.
const PRIME_M1: &str = "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffe";

// ---------------------------------------------------------------- helpers

fn u256(s: &str) -> Uint256 {
    Uint256::from_str(s, 0)
}

fn fe(s: &str) -> FE {
    FE::from_uint256(&u256(s))
}

/// Constrains a field element's canonical value against a `Uint256` literal.
fn assert_fe_eq_str(x: &FE, expected: &str) {
    uint256::assert_equal(&x.to_uint256(), &u256(expected));
}

// ---------------------------------------------------------------- construction

fn test_ctor_dtor() {
    uint256::assert_equal(&FE::default().to_uint256(), &Uint256::new());
}

fn test_set_get_uint256() {
    let x = Uint256::from_u64(5);
    uint256::assert_equal(&FE::from_uint256(&x).to_uint256(), &x);
}

fn test_print() {
    fe("241978572001512527289694654294400568637203164540116421040").print();
}

fn test_ctor_uint256() {
    let x = Uint256::from_u64(12312313123);
    uint256::assert_equal(&FE::from_uint256(&x).to_uint256(), &x);
}

fn test_ctor_int() {
    uint256::assert_equal(&FE::from_u32(1).to_uint256(), &Uint256::from_u64(1));
    uint256::assert_equal(&FE::one().to_uint256(), &Uint256::from_u64(1));
    uint256::assert_equal(&FE::zero().to_uint256(), &Uint256::new());
}

fn test_copy_ctor() {
    let s = "241978572001512527289694654294400568637203164540116421040";
    let fx = fe(s);
    let fy = fx.clone();
    assert_fe_eq_str(&fy, s);
}

fn test_from_str() {
    // The string constructor must agree with going through Uint256.
    assert_fe_eq_str(&FE::from_str("0x1234567890abcdef"), "0x1234567890abcdef");
    assert_fe_eq_str(&FE::from_u64(u64::MAX), "0xffffffffffffffff");
}

// ---------------------------------------------------------------- arithmetic

fn test_add() {
    assert_fe_eq_str(&(&fe("10") + &fe("20")), "30");

    // Wraps the modulus: (prime - 1) + 2 === 1. The C++ has this case commented out.
    assert_fe_eq_str(&(&fe(PRIME_M1) + &fe("2")), "1");

    // Both operands near the modulus: (prime - 1) + (prime - 2) === prime - 3.
    assert_fe_eq_str(
        &(&fe(PRIME_M1)
            + &fe("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd")),
        "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
    );
}

fn test_sub() {
    assert_fe_eq_str(&(&fe("500") - &fe("400")), "100");

    // Underflows the modulus: 9 - 10 === prime - 1. The C++ has this case commented out.
    assert_fe_eq_str(&(&fe("9") - &fe("10")), PRIME_M1);

    assert_fe_eq_str(&(&fe("0") - &fe("0")), "0");
}

fn test_mul() {
    // No reduction needed.
    assert_fe_eq_str(
        &(&fe("34028236692093846346337460743176821145") * &fe("1209371987239812739812731728379123812")),
        "41152796230584246818469977629329928449168694384595558569076337982534604740",
    );

    // Product exceeds the modulus and must reduce. The C++ computes this but has its
    // assertion commented out, so the expected value here is the one its comment records.
    assert_fe_eq_str(
        &(&fe("3402823669209384634633746074317682114521412342222222222222222222222222222222")
            * &fe("1209371987239812739812731728379123812")),
        "58512464492546777013172437578310408470178981375010378539944553533908315921941",
    );

    assert_fe_eq_str(&(&fe("7") * &fe("0")), "0");
    assert_fe_eq_str(&(&fe("7") * &fe("1")), "7");
}

fn test_div() {
    assert_fe_eq_str(
        &(&fe("34028236692093846346337460743176821145")
            / &fe("1209371987239812739812731728379123812123123")),
        "52875600598123785107505835260439024755840630830216046830155940773978164657184",
    );
}

fn test_neg() {
    assert_fe_eq_str(&(-&fe("0")), "0");
    assert_fe_eq_str(
        &(-&fe("100")),
        "0xffffffff00000001000000000000000000000000ffffffffffffffffffffff9b",
    );
    assert_fe_eq_str(&fe("100").negate().negate(), "100");
}

fn test_inv() {
    let mut res = FE::default();
    FE::inv_into(&mut res, &fe("100"));
    assert_fe_eq_str(
        &res,
        "0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14",
    );

    // x * x^-1 === 1, the property the vector above is a witness for.
    assert_fe_eq_str(&(&fe("100") * &res), "1");
    assert_fe_eq_str(&(&fe("12345") * &fe("12345").inv()), "1");
}

fn test_sqr() {
    let mut res = FE::default();
    FE::sqr(
        &mut res,
        &fe("0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14"),
    );
    assert_fe_eq_str(
        &res,
        "0xa5182a988ba5e3549ce703afb7e90ff972474539944d013a92a305532617c1bd",
    );
}

fn test_pow() {
    const BASE: &str = "0x7d70a3d68ccccccd4a3d70a3d70a3d70a3d70a3dee147ae147ae147ae147ae14";

    let mut res = FE::default();

    FE::powm_ui(&mut res, &fe(BASE), 0);
    assert_fe_eq_str(&res, "1");

    FE::powm_ui(&mut res, &fe(BASE), 1);
    assert_fe_eq_str(&res, BASE);

    FE::powm_ui(&mut res, &fe(BASE), 8726568);
    assert_fe_eq_str(
        &res,
        "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4",
    );
}

// ---------------------------------------------------------------- selection and predicates

fn test_mux() {
    let (a, b) = (fe("10"), fe("20"));
    let cond_0 = Bn254Fr::from_u32(0);
    let cond_1 = Bn254Fr::from_u32(1);

    // Polarity matches bn254fr_mux: the second value wins when cond is 1.
    assert_fe_eq_str(&FE::mux(&cond_0, &a, &b), "10");
    assert_fe_eq_str(&FE::mux(&cond_1, &a, &b), "20");
}

fn test_eqz() {
    assert_equal_u32(&FE::eqz(&FE::zero()), 1);
    assert_equal_u32(&FE::eqz(&fe("1231231231123")), 0);
}

fn test_eq() {
    assert_equal_u32(&FE::eq(&fe("42"), &fe("42")), 1);
    assert_equal_u32(&FE::eq(&fe("42"), &fe("43")), 0);
    FE::assert_equal(&fe("42"), &fe("42"));
}

fn test_to_bits() {
    // 5 = 0b101
    let bits = fe("5").to_bits();
    check(bits.len() == FE::NUM_ROUNDED_BITS);

    assert_equal_u32(&bits[0], 1);
    assert_equal_u32(&bits[1], 0);
    assert_equal_u32(&bits[2], 1);
    for bit in bits.iter().skip(3) {
        assert_equal_u32(bit, 0);
    }
}

// ---------------------------------------------------------------- import / export

const LIMBS_8: [u32; 8] = [
    0x2826a8b4, 0x056599a3, 0x77578e37, 0xc3b908a4, 0x8d14e0f8, 0xce09198a, 0x70684f6c, 0xf1bfbae7,
];
const LIMBS_8_STR: &str = "0xf1bfbae770684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4";

fn test_import_u32() {
    let mut x = FE::default();
    x.import_limbs(&LIMBS_8);
    assert_fe_eq_str(&x, LIMBS_8_STR);

    // Seven limbs: the odd trailing limb goes in on its own.
    let limbs7 = &LIMBS_8[0..7];
    let mut x2 = FE::default();
    x2.import_limbs(limbs7);
    assert_fe_eq_str(&x2, "0x70684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4");
}

fn test_export_u32() {
    let mut x = FE::default();
    x.import_limbs(&LIMBS_8);

    let mut limbs = [0u32; 8];
    check(x.export_limbs(&mut limbs) == 8);
    for i in 0..8 {
        check(limbs[i] == LIMBS_8[i]);
    }

    // Round-trip through Uint256 as well, which is the other construction path.
    let mut y = FE::from_uint256(&u256(LIMBS_8_STR));
    let mut limbs_y = [0u32; 8];
    y.export_limbs(&mut limbs_y);
    for i in 0..8 {
        check(limbs_y[i] == LIMBS_8[i]);
    }
    y.import_limbs(&LIMBS_8);
    assert_fe_eq_str(&y, LIMBS_8_STR);
}

const BYTES_32: [u8; 32] = [
    0xb4, 0xa8, 0x26, 0x28, 0xa3, 0x99, 0x65, 0x05, 0x37, 0x8e, 0x57, 0x77, 0xa4, 0x08, 0xb9, 0xc3,
    0xf8, 0xe0, 0x14, 0x8d, 0x8a, 0x19, 0x09, 0xce, 0x6c, 0x4f, 0x68, 0x70, 0xe7, 0xba, 0xbf, 0xf1,
];

fn test_import_bytes() {
    let mut x_little = FE::default();
    x_little.import_bytes_little(&BYTES_32);
    assert_fe_eq_str(&x_little, LIMBS_8_STR);

    let mut x_big = FE::default();
    x_big.import_bytes_big(&BYTES_32);
    assert_fe_eq_str(
        &x_big,
        "0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870e7babff1",
    );

    // 28 bytes: a short import must not read past the end.
    let bytes28 = &BYTES_32[0..28];
    let mut x2_little = FE::default();
    x2_little.import_bytes_little(bytes28);
    assert_fe_eq_str(
        &x2_little,
        "0x70684f6cce09198a8d14e0f8c3b908a477578e37056599a32826a8b4",
    );

    let mut x2_big = FE::default();
    x2_big.import_bytes_big(bytes28);
    assert_fe_eq_str(
        &x2_big,
        "0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870",
    );

    // Values above the modulus must reduce on import.
    let bytes3: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xa3, 0x99, 0x65, 0x05, 0x37, 0x8e, 0x57, 0x77, 0xa4, 0x08, 0xb9,
        0xc3, 0xf8, 0xe0, 0x14, 0x8d, 0x8a, 0x19, 0x09, 0xce, 0x6c, 0x4f, 0x68, 0x70, 0xff, 0xff,
        0xff, 0xff,
    ];

    let mut x3_little = FE::default();
    x3_little.import_bytes_little(&bytes3);
    assert_fe_eq_str(
        &x3_little,
        "0x70684f6bce09198a8d14e0f8c3b908a377578e37056599a400000000",
    );

    let mut x3_big = FE::default();
    x3_big.import_bytes_big(&bytes3);
    assert_fe_eq_str(
        &x3_big,
        "0xa3996504378e5777a408b9c3f8e0148c8a1909ce6c4f687100000000",
    );
}

fn test_export_bytes() {
    let mut bytes_little = [0u8; 32];
    fe(LIMBS_8_STR).export_bytes_little(&mut bytes_little);
    for i in 0..32 {
        check(bytes_little[i] == BYTES_32[i]);
    }

    let mut bytes_big = [0u8; 32];
    fe("0xb4a82628a3996505378e5777a408b9c3f8e0148d8a1909ce6c4f6870e7babff1")
        .export_bytes_big(&mut bytes_big);
    for i in 0..32 {
        check(bytes_big[i] == BYTES_32[i]);
    }
}

fn main() {
    test_ctor_dtor();
    test_set_get_uint256();
    test_print();
    test_ctor_uint256();
    test_ctor_int();
    test_copy_ctor();
    test_from_str();

    test_add();
    test_sub();
    test_mul();
    test_div();
    test_neg();
    test_inv();
    test_sqr();
    test_pow();

    test_mux();
    test_eqz();
    test_eq();
    test_to_bits();

    test_import_u32();
    test_export_u32();
    test_import_bytes();
    test_export_bytes();
}
