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

//! `Bn254FrBigint`: carry-free and carry-propagating arithmetic, division, modular inverse,
//! comparison, and byte import.
//!
//! Two deviations from the C++ suite, both deliberate:
//!
//! * `test_idiv` and `do_test_mul` have their assertions **commented out** in the C++, so those
//!   cases compute a result and check nothing. They are asserted here.
//! * `test_convert_to_proper_signed` calls the array-form
//!   `bn254fr_bigint_convert_to_proper_representation_signed_checked`, which is crate-internal
//!   in this SDK. The same code path is reached publicly via `sub_no_carry(...).to_proper()`,
//!   since `sub_no_carry` produces a signed value; that is what [`test_to_proper_signed`] does.

#[path = "common/mod.rs"]
mod common;

use common::{assert_bigint_eq, bigint_from_limbs, check};

use ligetron::bn254fr::assert_equal_u32;
use ligetron::bn254fr_bigint::Bn254FrBigint;

// ---------------------------------------------------------------- addition

/// `add_no_carry(a, b).to_proper()` — the deferred-carry path `ff` uses.
fn do_test_add(a: &[&str], b: &[&str], exp: &[&str]) {
    let res = Bn254FrBigint::add_no_carry(&bigint_from_limbs(a), &bigint_from_limbs(b)).to_proper();
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_add() {
    do_test_add(
        &["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"],
        &["9c15c81b7b00a5b5", "29f"],
        &["218adc264990aa35", "f2ec973d606bccac", "1806f16e9", "0"],
    );

    do_test_add(
        &["8575140ace900480", "ffffffffffffffff"],
        &["0000000000000001", "ffffffffffffffff"],
        &["8575140ace900481", "fffffffffffffffe", "1"],
    );

    // Operands swapped: the ragged-width path must be symmetric.
    do_test_add(
        &["9c15c81b7b00a5b5", "29f"],
        &["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"],
        &["218adc264990aa35", "f2ec973d606bccac", "1806f16e9", "0"],
    );
}

/// `add_checked` — carries propagated as it goes, one limb wider than the wider operand.
fn do_test_add_checked(a: &[&str], b: &[&str], exp: &[&str]) {
    let res = Bn254FrBigint::add_checked(&bigint_from_limbs(a), &bigint_from_limbs(b));
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_add_checked() {
    // Equal widths, carry into the top limb.
    do_test_add_checked(
        &["ffffffffffffffff", "ffffffffffffffff"],
        &["0000000000000001", "0000000000000000"],
        &["0000000000000000", "0000000000000000", "1"],
    );

    // Ragged widths, carry propagating through the extra limbs.
    do_test_add_checked(
        &["ffffffffffffffff", "ffffffffffffffff", "0000000000000005"],
        &["0000000000000001"],
        &["0000000000000000", "0000000000000000", "0000000000000006", "0"],
    );

    // Same, operands swapped.
    do_test_add_checked(
        &["0000000000000001"],
        &["ffffffffffffffff", "ffffffffffffffff", "0000000000000005"],
        &["0000000000000000", "0000000000000000", "0000000000000006", "0"],
    );

    do_test_add_checked(
        &["8575140ace900480", "f2ec973d606bca0c"],
        &["9c15c81b7b00a5b5", "000000000000029f"],
        &["218adc264990aa35", "f2ec973d606bccac", "0"],
    );
}

// ---------------------------------------------------------------- subtraction

fn do_test_sub(a: &[&str], b: &[&str], exp: &[&str]) {
    let res = Bn254FrBigint::sub_no_carry(&bigint_from_limbs(a), &bigint_from_limbs(b)).to_proper();
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_sub() {
    do_test_sub(
        &["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"],
        &["9c15c81b7b00a5b5", "29f"],
        &["e95f4bef538f5ecb", "f2ec973d606bc76c", "1806f16e9", "0"],
    );
}

/// The signed-to-proper conversion, reached the way a caller can reach it.
///
/// `sub_no_carry` marks its result signed, so `to_proper` takes the signed branch and its
/// `range_check_signed`. Borrowing across limbs is what makes the intermediate genuinely
/// negative per limb rather than merely large.
fn test_to_proper_signed() {
    // 1 - 10 borrows: limb 0 goes negative and limb 1 absorbs it.
    do_test_sub(
        &["0000000000000001", "0000000000000001"],
        &["000000000000000a", "0000000000000000"],
        &["fffffffffffffff7", "0000000000000000", "0", "0"],
    );

    // Multi-limb borrow chain.
    do_test_sub(
        &["0000000000000000", "0000000000000000", "0000000000000001"],
        &["0000000000000001", "0000000000000000", "0000000000000000"],
        &["ffffffffffffffff", "ffffffffffffffff", "0000000000000000", "0"],
    );
}

// ---------------------------------------------------------------- multiplication

fn do_test_mul_checked(a: &[&str], b: &[&str], exp: &[&str]) {
    let res = Bn254FrBigint::mul_checked(&bigint_from_limbs(a), &bigint_from_limbs(b));
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

/// `mul_unchecked` maps to the unconstrained host multiply. Asserting its result binds the
/// output; the C++ leaves this assertion commented out.
fn do_test_mul_unchecked(a: &[&str], b: &[&str], exp: &[&str]) {
    let res = Bn254FrBigint::mul_unchecked(&bigint_from_limbs(a), &bigint_from_limbs(b));
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

const MUL_A: [&str; 3] = ["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"];
const MUL_B: [&str; 2] = ["9c15c81b7b00a5b5", "29f"];
const MUL_EXP: [&str; 5] = [
    "ae25ce705eb9ae80",
    "1f873258dacf3c12",
    "39ae0cc0ce74bf3c",
    "3f08d9176c7",
    "0",
];

fn test_mul() {
    do_test_mul_checked(&MUL_A, &MUL_B, &MUL_EXP);
    do_test_mul_checked(&MUL_B, &MUL_A, &MUL_EXP);
    do_test_mul_checked(
        &["8575140ace900480", "ffffffffffffffff"],
        &["0000000000000001", "ffffffffffffffff"],
        &[
            "8575140ace900480",
            "7a8aebf5316ffb7f",
            "8575140ace900481",
            "fffffffffffffffe",
        ],
    );

    // The unchecked form uses one more limb than the checked one.
    do_test_mul_unchecked(&MUL_A, &MUL_B, &MUL_EXP);
}

// ---------------------------------------------------------------- division

/// The C++ has both assertions here commented out, so its `test_idiv` checks nothing.
fn do_test_idiv(a: &[&str], b: &[&str], exp_q: &[&str], exp_r: &[&str]) {
    check(exp_q.len() == a.len());
    check(exp_r.len() == b.len());

    let (q, r) = Bn254FrBigint::idiv(&bigint_from_limbs(a), &bigint_from_limbs(b));

    assert_bigint_eq(&q, &bigint_from_limbs(exp_q));
    assert_bigint_eq(&r, &bigint_from_limbs(exp_r));
}

fn test_idiv() {
    do_test_idiv(
        &["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"],
        &["9c15c81b7b00a5b5", "29f"],
        &["5c6158f2cc8fcf5", "928940", "0"],
        &["2f12e691e26b4247", "1d0"],
    );

    // Divisor larger than the dividend: quotient zero, remainder the dividend.
    do_test_idiv(
        &["9c15c81b7b00a5b5", "29f"],
        &["8575140ace900480", "f2ec973d606bca0c", "1806f16e9"],
        &["0", "0"],
        &["9c15c81b7b00a5b5", "29f", "0"],
    );

    do_test_idiv(
        &["8575140ace900480", "ffffffffffffffff"],
        &["0000000000000001", "ffffffffffffffff"],
        &["1", "0"],
        &["8575140ace90047f", "0"],
    );
}

// ---------------------------------------------------------------- modular inverse

/// The P-256 prime, as limbs.
const P256_PRIME: [&str; 4] = ["ffffffffffffffff", "ffffffff", "0", "ffffffff00000001"];

fn do_test_invmod(a: &[&str], m: &[&str], exp: &[&str]) {
    check(exp.len() == m.len());
    let res = Bn254FrBigint::invmod(&bigint_from_limbs(a), &bigint_from_limbs(m));
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_invmod() {
    do_test_invmod(
        &["39812738912fffff", "12978e3183798127", "12397"],
        &P256_PRIME,
        &[
            "daebfd9ce697b8c9",
            "4e4d5843bd48b940",
            "c2fabdd80b8b2d48",
            "58088c23544b5272",
        ],
    );

    // Nine-limb operand against a four-limb modulus.
    do_test_invmod(
        &[
            "1870000002222fff",
            "22222222222af273",
            "12738912fffff222",
            "78e3183798127398",
            "2222fff12397129",
            "222af27318700000",
            "fffff22222222222",
            "9812739812738912",
            "1239712978e31837",
        ],
        &P256_PRIME,
        &[
            "9599f26c56c5cad2",
            "f703a003bdb314f0",
            "cc2a16b362a3f894",
            "997572d4925ac539",
        ],
    );
}

// ---------------------------------------------------------------- comparison

fn do_test_eq(a: &[&str], b: &[&str], expected: bool) {
    let res = Bn254FrBigint::eq(&bigint_from_limbs(a), &bigint_from_limbs(b));
    assert_equal_u32(&res, u32::from(expected));
}

const EQ_REF: [&str; 4] = [
    "daebfd9ce697b8c9",
    "4e4d5843bd48b940",
    "c2fabdd80b8b2d48",
    "58088c23544b5272",
];

fn test_eq() {
    do_test_eq(&EQ_REF, &EQ_REF, true);

    do_test_eq(
        &EQ_REF,
        &[
            "daebfd9ce697b8c9",
            "1",
            "c2fabdd80b8b2d48",
            "58088c23544b5272",
        ],
        false,
    );

    // Differing limb counts: unequal when the extra limbs are non-zero...
    do_test_eq(&EQ_REF, &["daebfd9ce697b8c9", "4e4d5843bd48b940"], false);
    do_test_eq(&["daebfd9ce697b8c9", "4e4d5843bd48b940"], &EQ_REF, false);

    // ...and equal when they are zero, in either direction.
    do_test_eq(
        &["daebfd9ce697b8c9", "4e4d5843bd48b940", "0", "0"],
        &["daebfd9ce697b8c9", "4e4d5843bd48b940"],
        true,
    );
    do_test_eq(
        &["daebfd9ce697b8c9", "4e4d5843bd48b940"],
        &["daebfd9ce697b8c9", "4e4d5843bd48b940", "0", "0"],
        true,
    );
}

fn do_test_eqz(a: &[&str], expected: bool) {
    assert_equal_u32(&bigint_from_limbs(a).eqz(), u32::from(expected));
}

fn test_eqz() {
    do_test_eqz(
        &[
            "daebfd9ce697b8c9",
            "0",
            "c2fabdd80b8b2d48",
            "58088c23544b5272",
        ],
        false,
    );
    do_test_eqz(&["0", "0", "0", "0"], true);
}

fn test_lt() {
    let a = bigint_from_limbs(&["0000000000000005", "0000000000000000"]);
    let b = bigint_from_limbs(&["0000000000000006", "0000000000000000"]);
    assert_equal_u32(&Bn254FrBigint::lt(&a, &b), 1);
    assert_equal_u32(&Bn254FrBigint::lt(&b, &a), 0);
    assert_equal_u32(&Bn254FrBigint::lt(&a, &a), 0);

    // Difference only in the most significant limb.
    let c = bigint_from_limbs(&["ffffffffffffffff", "0000000000000001"]);
    let d = bigint_from_limbs(&["0000000000000000", "0000000000000002"]);
    assert_equal_u32(&Bn254FrBigint::lt(&c, &d), 1);
    assert_equal_u32(&Bn254FrBigint::lt(&d, &c), 0);
}

// ---------------------------------------------------------------- byte import

fn do_test_set_bytes_little(bytes: &[u8], exp: &[&str]) {
    let mut res = Bn254FrBigint::new();
    res.set_bytes_little(bytes);
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_set_bytes_little() {
    do_test_set_bytes_little(
        &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        &["0102030405060708"],
    );

    do_test_set_bytes_little(
        &[
            0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
            0x01, 0x00,
        ],
        &["08090a0b0c0d0e0f", "0001020304050607"],
    );

    // Empty input is zero.
    do_test_set_bytes_little(&[], &[]);

    // Fewer bytes than one limb.
    do_test_set_bytes_little(&[0x01, 0x02, 0x03], &["0000000000030201"]);

    // More than one limb with a partial top limb — the shape that caught the `set_bytes_big`
    // defect. Present here for both orders so a regression in either shows up.
    do_test_set_bytes_little(
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ],
        &["0807060504030201", "00000000000b0a09"],
    );
}

fn do_test_set_bytes_big(bytes: &[u8], exp: &[&str]) {
    let mut res = Bn254FrBigint::new();
    res.set_bytes_big(bytes);
    assert_bigint_eq(&res, &bigint_from_limbs(exp));
}

fn test_set_bytes_big() {
    do_test_set_bytes_big(
        &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        &["0102030405060708"],
    );

    do_test_set_bytes_big(
        &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ],
        &["08090a0b0c0d0e0f", "0001020304050607"],
    );

    do_test_set_bytes_big(&[0x01, 0x02, 0x03], &["0000000000010203"]);

    do_test_set_bytes_big(&[], &[]);

    // Regression guard: more than one limb with a partial top limb. The old implementation
    // overwrote the partial limb and left limb 0 at zero, shifting the value up by 64 bits.
    // The C++ cases are all 8, 16, 3 or 0 bytes, none of which reaches that branch.
    do_test_set_bytes_big(
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ],
        &["0405060708090a0b", "0000000000010203"],
    );
}

fn main() {
    test_add();
    test_add_checked();
    test_sub();
    test_to_proper_signed();
    test_mul();
    test_idiv();
    test_invmod();
    test_eq();
    test_eqz();
    test_lt();
    test_set_bytes_little();
    test_set_bytes_big();
}
