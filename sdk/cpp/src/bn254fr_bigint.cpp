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

/*
 * bn254fr_bigint.cpp
 *
 * Big integer implementation on top of bn254fr limbs
 *
 */


#include <ligetron/bn254fr_bigint.hpp>
#include <cassert>


namespace ligetron {


static void print_u32(const std::string &msg, uint32_t x) {
    print_str(msg.c_str(), msg.size());
    bn254fr_t bnx;
    bn254fr_alloc(bnx);
    bn254fr_set_u32(bnx, x);
    bn254fr_print(bnx, 10);
    bn254fr_free(bnx);
}

/// Returns number of limbs in proper representation for
/// overflow representation.
static uint32_t proper_size(uint32_t n_limbs,
                            uint32_t n_bits,
                            uint32_t n_overflow_bits) {
    if (n_overflow_bits == n_bits) {
        return n_limbs;
    }

    uint32_t n_add_limbs = n_overflow_bits / n_bits;

    return n_limbs + n_add_limbs;
}

static constexpr uint32_t log_ceil(uint32_t n) {
    uint32_t n_temp = n;
    for (uint32_t i = 0; i < 254; i++) {
        if (n_temp == 0) {
           return i;
        }
        n_temp = n_temp / 2;
    }
    return 254;
}

// Decomposes bn254 value into bits with constraints and deallocates result.
// This is used for checking that value fits in specified number of bits.
// n_bits must be less or equal than 256
static void check_bits(const bn254fr_t in, uint32_t n_bits) {
    // allocate array if bits
    bn254fr_t bits[256];
    for (size_t i = 0; i < n_bits; ++i) {
        bn254fr_alloc(bits[i]);
    }

    // decompose value into bits and add constraints
    bn254fr_to_bits_checked(bits, in, n_bits);

    // deallocate bits
    for (size_t i = 0; i < n_bits; ++i) {
        bn254fr_free(bits[i]);
    }
}

bn254fr_bigint::bn254fr_bigint(uint32_t n_limbs) {
    alloc(n_limbs);
}

bn254fr_bigint::bn254fr_bigint(uint32_t n_limbs, uint64_t val):
bn254fr_bigint{n_limbs} {
    bn254fr_set_u64(limbs_[0], val);
}

bn254fr_bigint::bn254fr_bigint(bn254fr_t *limbs, uint32_t n_limbs,
                               uint32_t n_bits, bool is_unsign):
limbs_count_{n_limbs}, bits_count_{n_bits}, is_unsigned_{is_unsign} {
    alloc(n_limbs);
    for (uint32_t i = 0, cnt = limbs_count(); i < cnt; ++i) {
        bn254fr_copy(limbs_[i], limbs[i]);
        bn254fr_assert_equal(limbs_[i], limbs[i]);
    }
}

bn254fr_bigint::bn254fr_bigint(const bn254fr_bigint &other) {
    copy(other);
}

bn254fr_bigint::bn254fr_bigint(bn254fr_bigint &&other) {
    move(std::move(other));
}

bn254fr_bigint::~bn254fr_bigint() {
    dealloc();
}

bn254fr_bigint &bn254fr_bigint::operator=(const bn254fr_bigint &other) {
    dealloc();
    copy(other);
    return *this;
}

bn254fr_bigint &bn254fr_bigint::operator=(bn254fr_bigint &&other) {
    dealloc();
    move(std::move(other));
    return *this;
}

uint32_t bn254fr_bigint::limbs_count() const {
    return limbs_count_;
}

uint32_t bn254fr_bigint::bits_count() const {
    return bits_count_;
}

bool bn254fr_bigint::is_unsigned() const {
    return is_unsigned_;
}

bool bn254fr_bigint::is_proper() const {
    return is_unsigned() && bits_count() == base_bits_count;
}

std::span<bn254fr_t> bn254fr_bigint::limbs() const {
    return {limbs_, limbs_count()};
}

void bn254fr_bigint::set(bn254fr_t *limbs,
                         uint32_t n_limbs,
                         uint32_t n_bits,
                         bool is_uns) {
    realloc(n_limbs);

    for (uint32_t i = 0; i < n_limbs; ++i) {
        bn254fr_copy(limbs_[i], limbs[i]);
        bn254fr_assert_equal(limbs_[i], limbs[i]);
    }

    bits_count_ = n_bits;
    is_unsigned_ = is_uns;
}

void bn254fr_bigint::print() const {
    bn254fr_bigint_print(limbs_, limbs_count_, base_bits_count);
}

void bn254fr_bigint::dump() const {
    print();

    print_u32("bits = ", bits_count_);
    print_u32("limbs = ", limbs_count_);
    print_u32("unsigned = ", uint32_t{is_unsigned_});

    for (auto &&limb : limbs()) {
        bn254fr_print(limb);
    }
}

bool bn254fr_bigint::is_zero() const {
    bn254fr_class zero{0};

    for (auto && limb : limbs()) {
        if (!bn254fr_eq(limb, zero.data())) {
            return false;
        }
    }

    return true;
}

bn254fr_class bn254fr_bigint::eqz() const {
    bn254fr_t sum;
    bn254fr_alloc(sum);

    bn254fr_class zero;

    for (auto && limb : limbs()) {
        // eq = a[i] == 0
        bn254fr_t eq;
        bn254fr_alloc(eq);
        bn254fr_eq_checked(eq, limb, zero.data());

        // sum += eq
        bn254fr_t tmp;
        bn254fr_alloc(tmp);
        bn254fr_addmod_checked(tmp, sum, eq);

        bn254fr_free(sum);
        sum[0] = tmp[0];        // move tmp -> sum

        bn254fr_free(eq);
    }

    // res = sum == limbs_count()
    bn254fr_class res;
    bn254fr_t exp_sum;
    bn254fr_alloc(exp_sum);
    bn254fr_set_u32(exp_sum, limbs_count());
    bn254fr_eq_checked(const_cast<__bn254fr*>(res.data()), sum, exp_sum);

    bn254fr_free(sum);
    bn254fr_free(exp_sum);

    return res;
}

bn254fr_class bn254fr_bigint::eq(const bn254fr_bigint &a,
                                 const bn254fr_bigint &b) {
    bn254fr_t sum;
    bn254fr_alloc(sum);

    bn254fr_class zero;

    auto a_count = a.limbs_count();
    auto b_count = b.limbs_count();

    auto common_count = std::min(a_count, b_count);
    for (size_t i = 0; i < common_count; ++i) {
        // eq = a[i] == b[i]
        bn254fr_t eq;
        bn254fr_alloc(eq);
        bn254fr_eq_checked(eq, a.limbs()[i], b.limbs()[i]);

        // sum += eq
        bn254fr_t tmp;
        bn254fr_alloc(tmp);
        bn254fr_addmod_checked(tmp, sum, eq);

        bn254fr_free(sum);
        sum[0] = tmp[0];        // move tmp -> sum

        bn254fr_free(eq);
    }

    if (a_count < b_count) {
        for (size_t i = common_count; i < b_count; ++i) {
            // eq = b[i] == 0
            bn254fr_t eq;
            bn254fr_alloc(eq);
            bn254fr_eq_checked(eq, b.limbs()[i], zero.data());

            // sum += eq
            bn254fr_t tmp;
            bn254fr_alloc(tmp);
            bn254fr_addmod_checked(tmp, sum, eq);

            bn254fr_free(sum);
            sum[0] = tmp[0];        // move tmp -> sum

            bn254fr_free(eq);
        }
    } else if (b_count < a_count) {
        for (size_t i = common_count; i < a_count; ++i) {
            // eq = a[i] == 0
            bn254fr_t eq;
            bn254fr_alloc(eq);
            bn254fr_eq_checked(eq, a.limbs()[i], zero.data());

            // sum += eq
            bn254fr_t tmp;
            bn254fr_alloc(tmp);
            bn254fr_addmod_checked(tmp, sum, eq);

            bn254fr_free(sum);
            sum[0] = tmp[0];        // move tmp -> sum

            bn254fr_free(eq);
        }
    }

    // res = sum == max(a_count, b_count)
    bn254fr_class res;
    bn254fr_t exp_sum;
    bn254fr_alloc(exp_sum);
    bn254fr_set_u32(exp_sum, std::max(a_count, b_count));
    bn254fr_eq_checked(const_cast<__bn254fr*>(res.data()), sum, exp_sum);

    bn254fr_free(sum);
    bn254fr_free(exp_sum);

    return res;
}

bn254fr_class bn254fr_bigint::lt(const bn254fr_bigint &a,
                                 const bn254fr_bigint &b) {

    assert(a.is_proper() && b.is_proper() &&
           "a and b must be in proper representation");
    assert(a.limbs_count() == b.limbs_count() &&
           "limbs count for a and b must be equal");

    uint32_t count = a.limbs_count();

    if (count == 1) {
        bn254fr_class res{1};
        bn254fr_lt_checked(const_cast<__bn254fr*>(res.data()),
                           a.limbs()[0],
                           b.limbs()[0],
                           base_bits_count);
        return res;
    }

    bn254fr_t *lt = new bn254fr_t[count];
    bn254fr_t *eq = new bn254fr_t[count];

    for (size_t i = 0; i < count; ++i) {
        bn254fr_alloc(lt[i]);
        bn254fr_alloc(eq[i]);

        bn254fr_lt_checked(lt[i], a.limbs()[i], b.limbs()[i], base_bits_count);
        bn254fr_eq_checked(eq[i], a.limbs()[i], b.limbs()[i]);
    }

    bn254fr_t *ors = new bn254fr_t[count - 1];
    bn254fr_t *ands = new bn254fr_t[count - 1];
    bn254fr_t *eq_ands = new bn254fr_t[count - 1];

    for (size_t i = 0; i < count - 1; ++i) {
        bn254fr_alloc(ors[i]);
        bn254fr_alloc(ands[i]);
        bn254fr_alloc(eq_ands[i]);
    }

    bn254fr_land_checked(ands[count - 2], eq[count - 1], lt[count - 2]);
    bn254fr_land_checked(eq_ands[count - 2], eq[count - 1], eq[count - 2]);
    bn254fr_lor_checked(ors[count - 2], lt[count - 1], ands[count - 2]);

    for (int i = count - 3; i >= 0; i--) {
        bn254fr_land_checked(ands[i], eq_ands[i + 1], lt[i]);
        bn254fr_land_checked(eq_ands[i], eq_ands[i + 1], eq[i]);
        bn254fr_lor_checked(ors[i], ors[i + 1], ands[i]);
    }

    bn254fr_class res;

    bn254fr_copy(const_cast<__bn254fr*>(res.data()), ors[0]);
    bn254fr_assert_equal(res.data(), ors[0]);

    for (size_t i = 0; i < count; ++i) {
        bn254fr_free(lt[i]);
        bn254fr_free(eq[i]);
    }

    for (size_t i = 0; i < count - 1; ++i) {
        bn254fr_free(ors[i]);
        bn254fr_free(ands[i]);
        bn254fr_free(eq_ands[i]);
    }

    delete [] ors;
    delete [] ands;
    delete [] eq_ands;
    delete [] eq;
    delete [] lt;

    return res;
}

bn254fr_bigint bn254fr_bigint::to_proper() const {
    auto res_size = proper_size(limbs_count_, base_bits_count, bits_count_);
    bn254fr_bigint res{res_size};

    if (is_proper()) {
        return *this;
    }

    uint32_t bcount = is_unsigned() ? bits_count() + 1 : bits_count();
    bn254fr_bigint_convert_to_proper_representation_signed_checked(
        res.limbs().data(),
        limbs_,
        res.limbs_count(),
        limbs_count_,
        base_bits_count,
        bcount);

    return res;
}

bn254fr_bigint bn254fr_bigint::to_proper_unchecked() const {
    auto res_size = proper_size(limbs_count_, base_bits_count, bits_count_);
    bn254fr_bigint res{res_size};

    if (is_proper()) {
        return *this;
    }

    if (is_unsigned()) {
        bn254fr_bigint_convert_to_proper_representation_unsigned(
            res.limbs().data(),
            limbs_,
            res.limbs_count(),
            limbs_count_,
            base_bits_count);
    } else {
        bn254fr_bigint_convert_to_proper_representation_signed(
            res.limbs().data(),
            limbs_,
            res.limbs_count(),
            limbs_count_,
            base_bits_count);
    }

    return res;
}

bn254fr_bigint bn254fr_bigint::to_overflow(uint32_t n_limbs,
                                           uint32_t n_bits) const {
    bn254fr_bigint res{n_limbs};
    res.set_bits_count(n_bits);
    bn254fr_bigint_convert_to_overflow_representation(res.limbs().data(),
                                                      limbs().data(),
                                                      res.limbs_count(),
                                                      limbs_count(),
                                                      base_bits_count,
                                                      n_bits);
    return res;
}

bn254fr_bigint bn254fr_bigint::max(uint32_t n_limbs, uint32_t n_bits) {
    bn254fr_t pow_2, bits;
    bn254fr_alloc(pow_2);
    bn254fr_alloc(bits);
    bn254fr_set_u32(bits, n_bits);
    bn254fr_set_u32(pow_2, 1);
    bn254fr_shlmod(pow_2, pow_2, bits);
    bn254fr_submod(pow_2, pow_2, bn254fr_class{1}.data());

    bn254fr_bigint res{n_limbs};
    res.set_bits_count(n_bits);
    for (auto && limb : res.limbs()) {
        bn254fr_copy(limb, pow_2);
    }

    bn254fr_free(pow_2);
    bn254fr_free(bits);

    return res;
}

bn254fr_bigint bn254fr_bigint::max_proper(uint32_t n_limbs,
                                              uint32_t n_bits) {
    return max(n_limbs, n_bits).to_proper_unchecked();
}

uint32_t bn254fr_bigint::add_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                     const bn254fr_bigint &y) {
    return std::max(x.bits_count(), y.bits_count()) + 1;
}

/// Performs addition of two big integers without carry, adds constraints.
bn254fr_bigint bn254fr_bigint::add_no_carry(const bn254fr_bigint &x,
                                            const bn254fr_bigint &y) {
    auto res_bits_count = add_no_carry_res_bits_count(x, y);
    assert(res_bits_count <= max_bits_count && "bn254fr bigint overflow");

    uint32_t x_count = x.limbs_count();
    uint32_t y_count = y.limbs_count();

    bn254fr_bigint res{std::max(x_count, y_count)};

    uint32_t common_count = std::min(x_count, y_count);

    // calculate sum of common limbs
    for (size_t i = 0; i < common_count; ++i) {
        bn254fr_addmod_checked(res.limbs()[i], x.limbs()[i], y.limbs()[i]);
    }

    // copy extra limbs to output
    if (x_count > y_count) {
        for (size_t i = y_count; i < x_count; ++i) {
            bn254fr_copy(res.limbs()[i], x.limbs()[i]);
            bn254fr_assert_equal(res.limbs()[i], x.limbs()[i]);
        }
    } else if (x_count < y_count) {
        for (size_t i = x_count; i < y_count; ++i) {
            bn254fr_copy(res.limbs()[i], y.limbs()[i]);
            bn254fr_assert_equal(res.limbs()[i], y.limbs()[i]);
        }
    }

    res.set_unsigned(x.is_unsigned() && y.is_unsigned());
    res.set_bits_count(res_bits_count);

    return res;
}

bn254fr_bigint bn254fr_bigint::add_no_carry_unchecked(const bn254fr_bigint &x,
                                                      const bn254fr_bigint &y) {
    auto res_bits_count = add_no_carry_res_bits_count(x, y);
    assert(res_bits_count <= max_bits_count && "bn254fr bigint overflow");

    bn254fr_bigint res{std::max(x.limbs_count(), y.limbs_count())};

    uint32_t x_count = x.limbs_count();
    uint32_t y_count = y.limbs_count();
    uint32_t common_count = std::min(x_count, y_count);

    // calculate sum of common limbs
    for (size_t i = 0; i < common_count; ++i) {
        bn254fr_addmod(res.limbs()[i], x.limbs()[i], y.limbs()[i]);
    }

    // copy extra limbs to output
    if (x_count > y_count) {
        for (size_t i = y_count; i < x_count; ++i) {
            bn254fr_copy(res.limbs()[i], x.limbs()[i]);
        }
    } else if (x_count < y_count) {
        for (size_t i = x_count; i < y_count; ++i) {
            bn254fr_copy(res.limbs()[i], y.limbs()[i]);
        }
    }

    res.set_unsigned(x.is_unsigned() && y.is_unsigned());
    res.set_bits_count(res_bits_count);

    return res;
}

uint32_t bn254fr_bigint::sub_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                     const bn254fr_bigint &y) {
    return std::max(x.bits_count() + 1, y.bits_count()) + 1;
}

bn254fr_bigint bn254fr_bigint::sub_no_carry(const bn254fr_bigint &x,
                                            const bn254fr_bigint &y) {
    uint32_t x_count = x.limbs_count();
    uint32_t y_count = y.limbs_count();

    bn254fr_bigint res{std::max(x.limbs_count(), y.limbs_count())};
    res.set_bits_count(sub_no_carry_res_bits_count(x, y));
    res.set_unsigned(false);

    // calculate difference of common limbs
    uint32_t n_common_limbs = std::min(x_count, y_count);
    for (uint32_t i = 0; i < n_common_limbs; ++i) {
        bn254fr_submod_checked(res.limbs()[i], x.limbs()[i], y.limbs()[i]);
    }

    // calculate difference for extra limbs
    if (x_count >= y_count) {
        for (uint32_t i = y_count; i < x_count; ++i) {
            bn254fr_copy(res.limbs()[i], x.limbs()[i]);
            bn254fr_assert_equal(res.limbs()[i], x.limbs()[i]);
        }
    } else {
        for (uint32_t i = x_count; i < y_count; ++i) {
            bn254fr_negmod_checked(res.limbs()[i], y.limbs()[i]);
        }
    }

    return res;
}

uint32_t bn254fr_bigint::mul_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                     const bn254fr_bigint &y) {
    return x.bits_count() +
           y.bits_count() +
           log_ceil(std::min(x.limbs_count(), y.limbs_count()));
}

bn254fr_bigint bn254fr_bigint::mul_no_carry(const bn254fr_bigint &x,
                                            const bn254fr_bigint &y) {
    auto res_limbs_count = x.limbs_count() + y.limbs_count() - 1;
    bn254fr_bigint res{res_limbs_count};
    res.set_bits_count(mul_no_carry_res_bits_count(x, y));
    bn254fr_bigint_mul_checked_no_carry(res.limbs().data(),
                                        x.limbs().data(),
                                        y.limbs().data(),
                                        x.limbs_count(),
                                        y.limbs_count());
    return res;
}

bn254fr_bigint bn254fr_bigint::mul_unchecked(const bn254fr_bigint &x,
                                             const bn254fr_bigint &y) {
    bn254fr_bigint res{x.limbs_count() + y.limbs_count()};
    bn254fr_bigint_mul(res.limbs().data(),
                       x.limbs().data(),
                       y.limbs().data(),
                       x.limbs_count(),
                       y.limbs_count(),
                       base_bits_count);
    return res;
}

std::tuple<bn254fr_bigint, bn254fr_bigint>
bn254fr_bigint::idiv(const bn254fr_bigint &a, const bn254fr_bigint &b) {
    bn254fr_class zero;
    bn254fr_class one{1};

    // perform big integer division without constraints
    auto [q, r] = idiv_unchecked(a, b);

    // check range for q limbs
    for (auto && limb : q.limbs()) {
        check_bits(limb, base_bits_count);
    }

    // checking range for r limbs
    for (auto && limb : r.limbs()) {
        check_bits(limb, base_bits_count);
    }

    // calculate q * b with constraints
    auto mul_res = bn254fr_bigint::mul_no_carry(q, b);

    // calculate q * b + r with constraints
    auto add_res = bn254fr_bigint::add_no_carry(mul_res, r);

    // converting q * b + r to proper representation
    auto add_res_prop = add_res.to_proper();

    // checking q * b + r === a

    for (uint32_t i = 0, sz = a.limbs_count(); i < sz; ++i) {
        bn254fr_assert_equal(a.limbs()[i], add_res_prop.limbs()[i]);
    }

    for (uint32_t i = a.limbs_count(), sz = add_res_prop.limbs_count();
         i < sz; ++i) {
        bn254fr_assert_equal(add_res_prop.limbs()[i], zero.data());
    }

    // check r < b

    auto lt_res = lt(r, b);
    bn254fr_assert_equal(lt_res.data(), one.data());

    return {q, r};
}

std::tuple<bn254fr_bigint, bn254fr_bigint>
bn254fr_bigint::idiv_unchecked(const bn254fr_bigint &x,
                               const bn254fr_bigint &y) {
    bn254fr_bigint q{x.limbs_count()};
    bn254fr_bigint r{y.limbs_count()};

    bn254fr_bigint_idiv(q.limbs().data(),
                        r.limbs().data(),
                        x.limbs().data(),
                        y.limbs().data(),
                        x.limbs_count(),
                        y.limbs_count(),
                        base_bits_count);

    return {q, r};
}

bn254fr_bigint bn254fr_bigint::rem(const bn254fr_bigint &a,
                                   const bn254fr_bigint &m) {
    bn254fr_class zero;
    bn254fr_class one{1};

    // convert a to proper representation without constraints
    auto a_prop = a.to_proper_unchecked();
    
    // convert m to proper representation without constraints
    auto m_prop = m.to_proper_unchecked();

    // compute (q, out) = idiv(a_proper, m_proper) without constraints
    auto [q, out] = bn254fr_bigint::idiv_unchecked(a_prop, m_prop);

    // check that out < m
    auto lt_res = lt(out, m_prop);
    bn254fr_class::assert_equal(lt_res, one);

    // check q * m + out === a with constraints

    // compute mul_res = q * m without carry, with constraints
    auto mul_res = mul_no_carry(q, m);

    // compute add_res = mul_res + out without carry, with constraints
    auto add_res = add_no_carry(mul_res, out);

    // compute sub_res = a - add_res without carry, with constraints
    auto sub_res = sub_no_carry(a, add_res);

    // convert sub_res to proper representation with constraints
    auto sub_res_proper = sub_res.to_proper();

    // check sub_res proper representation is zero
    for (auto && limb : sub_res_proper.limbs()) {
        bn254fr_assert_equal(limb, zero.data());
    }

    return out;
}

bn254fr_bigint bn254fr_bigint::rem_unchecked(const bn254fr_bigint &a,
                                             const bn254fr_bigint &m) {
    auto [q, r] = idiv_unchecked(a, m);
    return r;
}

bn254fr_bigint bn254fr_bigint::invmod(const bn254fr_bigint &a,
                                      const bn254fr_bigint &m) {
    auto res = invmod_unchecked(a, m);

    bn254fr_t zero;
    bn254fr_t one;

    bn254fr_alloc(zero);
    bn254fr_alloc(one);
    bn254fr_set_u32(one, 1);

    auto mul_res = bn254fr_bigint::mul_no_carry(res, a);
    auto mul_res_rem = bn254fr_bigint::rem(mul_res, m);
    bn254fr_assert_equal(mul_res_rem.limbs()[0], one);
    for (uint32_t i = 1, sz = mul_res_rem.limbs_count(); i < sz; ++i) {
        bn254fr_assert_equal(mul_res_rem.limbs()[i], zero);
    }

    bn254fr_free(zero);
    bn254fr_free(one);

    return res;
}

bn254fr_bigint bn254fr_bigint::invmod_unchecked(const bn254fr_bigint &a,
                                                const bn254fr_bigint &m) {
    bn254fr_bigint res{m.limbs_count()};
    bn254fr_bigint_invmod(res.limbs().data(),
                          a.limbs().data(),
                          m.limbs().data(),
                          a.limbs_count(),
                          m.limbs_count(),
                          base_bits_count);
    return res;
}

void bn254fr_bigint::alloc(uint32_t count) {
    limbs_count_ = count;

    if (limbs_count_ == 0) {
        limbs_ = nullptr;
    } else {
        limbs_ = new bn254fr_t[count];
    }

    for (auto &&limb : limbs()) {
        bn254fr_alloc(limb);
    }
}

void bn254fr_bigint::dealloc() {
    for (auto &&limb : limbs()) {
        bn254fr_free(limb);
    }

    if (limbs_count_ != 0) {
        delete[] limbs_;
    }
}

void bn254fr_bigint::copy(const bn254fr_bigint &other) {
    alloc(other.limbs_count());
    for (uint32_t i = 0; i < limbs_count_; ++i) {
        bn254fr_copy(limbs_[i], other.limbs()[i]);
        bn254fr_assert_equal(limbs_[i], other.limbs()[i]);
    }

    bits_count_ = other.bits_count();
    is_unsigned_ = other.is_unsigned();
}

void bn254fr_bigint::move(bn254fr_bigint &&other) {
    limbs_ = other.limbs_;
    limbs_count_ = other.limbs_count_;
    bits_count_ = other.bits_count_;
    is_unsigned_ = other.is_unsigned_;

    other.limbs_ = nullptr;
    other.limbs_count_ = 0;
    other.bits_count_ = base_bits_count;
    other.is_unsigned_ = true;
}

void bn254fr_bigint::reset() {
    dealloc();

    limbs_count_ = 0;
    bits_count_ = base_bits_count;
    is_unsigned_ = true;
}


} // namespace ligetron
