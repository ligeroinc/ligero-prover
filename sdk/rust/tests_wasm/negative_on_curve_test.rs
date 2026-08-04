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

//! NEGATIVE test: `assert_on_curve` must reject an off-curve point.
//!
//! **This program is expected to FAIL to prove.** `tests_wasm/run.sh` knows it is a negative
//! suite and treats `Final prove result: false` as a pass, `true` as a failure.
//!
//! Why it exists: every other suite feeds valid values, so it verifies that the constraint
//! system ACCEPTS a correct witness. Nothing verified that it REJECTS an incorrect one, which
//! is what a soundness assertion is for. Comment out the `assert_equal_u32` in
//! `AffineCurve::assert_on_curve` (`src/ecc/curve.rs:90`) and this suite starts proving true —
//! it is the only test in the tree that notices.
//!
//! Note `p256_test::test_on_curve` is NOT the same check. It asserts the *predicate*
//! `on_curve(bad) == 0`, which is a positive test that proves fine. This asserts the
//! *constraint*, which must make the whole proof unsatisfiable.

use ligetron::ecc::coordinates::Affine;
use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{P256Base, P256};
use ligetron::ff::FieldElement;

type FE = FieldElement<P256Base>;

/// 2G on P-256 with the last nibble of y bumped: same x, so it satisfies nothing.
const BAD_X: &str = "0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978";
const BAD_Y: &str = "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D2";

fn main() {
    let curve = P256::new();
    let bad = Affine::new(FE::from_str(BAD_X), FE::from_str(BAD_Y));

    // The single constrained call under test. Nothing follows it: a negative suite must trip
    // exactly one assertion, or a failure cannot be attributed.
    curve.assert_on_curve(&bad);
}
