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

#include <ligetron/bn254fr_bigint.hpp>
#include <ligetron/api.h>
#include <vector>
#include <string>


using namespace ligetron;

using str_vector = std::vector<std::string>;


void bn254fr_bigint_assert_equal(const bn254fr_bigint &a,
                                 const bn254fr_bigint &b) {
    assert_one(a.limbs_count() == b.limbs_count());
    for (size_t i = 0; i < a.limbs_count(); ++i) {
        bn254fr_assert_equal(a.limbs()[i], b.limbs()[i]);
    }
}

bn254fr_bigint bn254fr_bigint_from_str(const str_vector &limbs, uint32_t base) {
    bn254fr_bigint res{limbs.size()};
    for (size_t i = 0, sz = limbs.size(); i < sz; ++i) {
        bn254fr_set_str(res.limbs()[i], limbs[i].c_str(), base);
    }

    return res;
}

void do_test_add(const str_vector &a_str,
                 const str_vector &b_str,
                 const str_vector &exp_str,
                 uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint b = bn254fr_bigint_from_str(b_str, base);
    bn254fr_bigint exp = bn254fr_bigint_from_str(exp_str, base);

    auto res_sz = std::max(a_str.size(), b_str.size()) + 1;

    auto res = bn254fr_bigint::add_no_carry(a, b).to_proper();

    bn254fr_bigint_assert_equal(res, exp);
}

void test_add() {
    do_test_add(
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"9c15c81b7b00a5b5", "29f"},
        {"218adc264990aa35", "f2ec973d606bccac", "1806f16e9", "0"},
        16
    );

    do_test_add(
        {"8575140ace900480", "ffffffffffffffff"},
        {"0000000000000001", "ffffffffffffffff"},
        {"8575140ace900481", "fffffffffffffffe", "1"},
        16
    );

    do_test_add(
        {"9c15c81b7b00a5b5", "29f"},
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"218adc264990aa35", "f2ec973d606bccac", "1806f16e9", "0"},
        16
    );
}

void do_test_sub(const str_vector &a_str,
                 const str_vector &b_str,
                 const str_vector &exp_str,
                 uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint b = bn254fr_bigint_from_str(b_str, base);
    bn254fr_bigint exp = bn254fr_bigint_from_str(exp_str, base);

    auto res = bn254fr_bigint::sub_no_carry(a, b).to_proper();

    bn254fr_bigint_assert_equal(res, exp);
}

void test_sub() {
    do_test_sub(
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"9c15c81b7b00a5b5", "29f"},
        {"e95f4bef538f5ecb", "f2ec973d606bc76c", "1806f16e9", "0"},
        16
    );
}

void do_test_mul(const str_vector &a_str,
                 const str_vector &b_str,
                 const str_vector &exp_str,
                 uint32_t base,
                 bool checked) {

    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint b = bn254fr_bigint_from_str(b_str, base);
    bn254fr_bigint exp = bn254fr_bigint_from_str(exp_str, base);

    auto res_sz = a_str.size() + b_str.size();
    bn254fr_bigint res{res_sz};

    if (checked) {
        bn254fr_bigint_mul_checked(res.limbs().data(),
                                   a.limbs().data(),
                                   b.limbs().data(),
                                   a.limbs_count(),
                                   b.limbs_count(),
                                   64);
    } else {
        bn254fr_bigint_mul(res.limbs().data(),
                           a.limbs().data(),
                           b.limbs().data(),
                           a.limbs_count(),
                           b.limbs_count(),
                           64);
    }

    bn254fr_bigint_assert_equal(res, exp);
}

void test_mul(bool checked) {
    do_test_mul(
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"9c15c81b7b00a5b5", "29f"},
        {"ae25ce705eb9ae80", "1f873258dacf3c12", "39ae0cc0ce74bf3c", "3f08d9176c7", "0"},
        16,
        checked
    );

    do_test_mul(
        {"9c15c81b7b00a5b5", "29f"},
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"ae25ce705eb9ae80", "1f873258dacf3c12", "39ae0cc0ce74bf3c", "3f08d9176c7", "0"},
        16,
        checked
    );

    do_test_mul(
        {"8575140ace900480", "ffffffffffffffff"},
        {"0000000000000001", "ffffffffffffffff"},
        {"8575140ace900480", "7a8aebf5316ffb7f", "8575140ace900481", "fffffffffffffffe"},
        16,
        checked
    );
}

void do_test_idiv(const str_vector &a_str,
                  const str_vector &b_str,
                  const str_vector &exp_q_str,
                  const str_vector &exp_r_str,
                  uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint b = bn254fr_bigint_from_str(b_str, base);
    bn254fr_bigint exp_q = bn254fr_bigint_from_str(exp_q_str, base);
    bn254fr_bigint exp_r = bn254fr_bigint_from_str(exp_r_str, base);

    assert_one(exp_q_str.size() == a_str.size());
    assert_one(exp_r_str.size() == b_str.size());

    auto [q, r] = bn254fr_bigint::idiv(a, b);

    // bn254fr_bigint_assert_equal(q, exp_q, a_str.size());
    // bn254fr_bigint_assert_equal(r, exp_r, b_str.size());
}

void test_idiv() {
    do_test_idiv(
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"9c15c81b7b00a5b5", "29f"},
        {"5c6158f2cc8fcf5", "928940", "0"},
        {"2f12e691e26b4247", "1d0"},
        16
    );

    do_test_idiv(
        {"9c15c81b7b00a5b5", "29f"},
        {"8575140ace900480", "f2ec973d606bca0c", "1806f16e9"},
        {"0", "0"},
        {"9c15c81b7b00a5b5", "29f", "0"},
        16
    );

    do_test_idiv(
        {"8575140ace900480", "ffffffffffffffff"},
        {"0000000000000001", "ffffffffffffffff"},
        {"1", "0"},
        {"8575140ace90047f", "0"},
        16
    );
}

void do_test_invmod(const str_vector &a_str,
                    const str_vector &m_str,
                    const str_vector &exp_str,
                    uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint m = bn254fr_bigint_from_str(m_str, base);
    bn254fr_bigint exp = bn254fr_bigint_from_str(exp_str, base);

    assert_one(exp_str.size() == m_str.size());

    bn254fr_bigint res{m_str.size()};

    bn254fr_bigint_invmod_checked(res.limbs().data(),
                                  a.limbs().data(),
                                  m.limbs().data(),
                                  a.limbs_count(),
                                  m.limbs_count(),
                                  64);
    bn254fr_bigint_assert_equal(res, exp);
}

void test_invmod() {
    do_test_invmod(
        {"39812738912fffff", "12978e3183798127", "12397"},
        {"ffffffffffffffff", "ffffffff", "0", "ffffffff00000001"},      // P256 prime
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        16
    );

    do_test_invmod(
        {"1870000002222fff", "22222222222af273", "12738912fffff222", "78e3183798127398",
         "2222fff12397129", "222af27318700000", "fffff22222222222", "9812739812738912", "1239712978e31837"},
        {"ffffffffffffffff", "ffffffff", "0", "ffffffff00000001"},      // P256 prime
        {"9599f26c56c5cad2", "f703a003bdb314f0", "cc2a16b362a3f894", "997572d4925ac539"},
        16
    );
}

void do_test_eq(const str_vector &a_str,
                const str_vector &b_str,
                bool exp_b,
                uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);
    bn254fr_bigint b = bn254fr_bigint_from_str(b_str, base);

    bn254fr_class exp{exp_b ? 1 : 0};

    auto res = bn254fr_bigint::eq(a, b);
    bn254fr_class::assert_equal(res, exp);
}

void test_eq() {
    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        true,
        16
    );

    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        {"daebfd9ce697b8c9", "1",                "c2fabdd80b8b2d48", "58088c23544b5272"},
        false,
        16
    );

    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        {"daebfd9ce697b8c9", "4e4d5843bd48b940"},
        false,
        16
    );

    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "0", "0"},
        {"daebfd9ce697b8c9", "4e4d5843bd48b940"},
        true,
        16
    );

    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940"},
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "c2fabdd80b8b2d48", "58088c23544b5272"},
        false,
        16
    );

    do_test_eq(
        {"daebfd9ce697b8c9", "4e4d5843bd48b940"},
        {"daebfd9ce697b8c9", "4e4d5843bd48b940", "0", "0"},
        true,
        16
    );
}

void do_test_eqz(const str_vector &a_str,
                 bool exp_b,
                 uint32_t base) {
    bn254fr_bigint a = bn254fr_bigint_from_str(a_str, base);

    bn254fr_class exp;
    exp.set_u32(exp_b ? 1 : 0);

    auto res = a.eqz();
    bn254fr_class::assert_equal(res, exp);
}

void test_eqz() {
    do_test_eqz(
        {"daebfd9ce697b8c9", "0", "c2fabdd80b8b2d48", "58088c23544b5272"},
        false,
        16
    );

    do_test_eqz(
        {"0", "0", "0", "0"},
        true,
        16
    );
}

void do_test_convert_to_proper_signed(const str_vector &in_str,
                                      const str_vector &exp_str,
                                      uint32_t base,
                                      uint32_t in_bits,
                                      uint32_t out_bits) {
    auto in = bn254fr_bigint_from_str(in_str, base);
    bn254fr_bigint out{exp_str.size()};
    auto exp = bn254fr_bigint_from_str(exp_str, base);

    bn254fr_bigint_convert_to_proper_representation_signed_checked(
        out.limbs().data(),
        in.limbs().data(),
        out.limbs_count(),
        in.limbs_count(),
        out_bits,
        in_bits);
    bn254fr_bigint_assert_equal(out, exp);
}

void test_convert_to_proper_signed() {
    do_test_convert_to_proper_signed(
        {
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff7",    //-10
            "1",
            "0"
        },
        {"fffffffffffffff6", "0", "0", "0"},
        16,
        64,
        64
    );

    do_test_convert_to_proper_signed(
        {
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffff7",    //-10
            "1",
            "1"
        },
        {"fffffffffffffff6", "0", "1", "0"},
        16,
        64,
        64
    );

    // in 16 bits
    // out 8 bits
    do_test_convert_to_proper_signed(
        // 192936
        {
            "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593effffda9",  // -600
            "1F4",                                                               // 500
            "1"
        },
        {"A8", "F1", "2", "0"},
        16,
        16,
        8
    );
}

int main(int argc, char * argv[]) {
    test_add();
    test_sub();
    test_mul(false);
    test_mul(true);;
    test_idiv();
    // test_invmod();
    test_eq();
    test_eqz();

    test_convert_to_proper_signed();

    return 0;
}
