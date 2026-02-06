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

/*
 * uint256 generic prime field definition
 */

#ifndef __LIGETRON_PRIME_FIELD_UINT256_H__
#define __LIGETRON_PRIME_FIELD_UINT256_H__

#include <ligetron/api.h>
#include <ligetron/uint256_cpp.h>
#include <ligetron/ff/field_element.h>
#include <ligetron/ff/concepts.h>
#include <ligetron/bn254fr_bigint.hpp>
#include <cassert>
#include <span>


namespace ligetron::ff {


/// Storage type for uint256 field arithmetics implementation
template <typename Field>
class prime_field_uint256_storage {
    template <typename Field2>
    friend class prime_field_uint256_storage;

    static constexpr size_t n_bits_base = 64;
    static constexpr size_t n_max_bits = 250;

public:
    /// Constructs storage from limbs
    prime_field_uint256_storage(bn254fr_t *limbs,
                                uint32_t n_limbs,
                                uint32_t n_bits,
                                bool is_unsign,
                                bool reduced):
    value_{limbs, n_limbs, n_bits, is_unsign},
    is_reduced_{reduced} {
    }

    /// Constructs storage from big integer value
    prime_field_uint256_storage(bn254fr_bigint val, bool reduced):
        value_{std::move(val)}, is_reduced_{reduced} {}

    /// Constructs storage initialized with zero value
    prime_field_uint256_storage():
        value_{UINT256_NLIMBS} {}

    /// Deallocates values used for storage
    ~prime_field_uint256_storage() = default;

    /// Constructs storage from uint256 value
    prime_field_uint256_storage(const uint256 &x) {
        set_uint256(x);
    }

    /// Constructs storage from string
    prime_field_uint256_storage(const char *str):
        prime_field_uint256_storage{uint256{str}} {}

    /// Constructs torage from uint64_t value
    prime_field_uint256_storage(uint64_t val):
    value_{UINT256_NLIMBS, val} {
    }

    /// Copy constructor, initializes storage from another storage
    /// with making equality constraints
    prime_field_uint256_storage(const prime_field_uint256_storage &other):
    value_{other.value_}, is_reduced_{other.is_reduced_} {
    }

    /// Constructs storage from another storage for different field
    /// with making equality constraints
    template <typename Field2>
    prime_field_uint256_storage(const prime_field_uint256_storage<Field2> &other):
    prime_field_uint256_storage{other.to_uint256()} {
    }

    /// Copy-assignment operator. Reallocates this value and assigns value
    /// from another storage, adds equality constraints.
    prime_field_uint256_storage
    &operator=(const prime_field_uint256_storage &other) = default;

    /// Move-assignment operator. Deallocates this value and moves value
    /// from other storage. Resets other storage.
    prime_field_uint256_storage
    &operator=(const prime_field_uint256_storage &&other) = default;

    /// Converts storage to uint256 value
    uint256 to_uint256() const {
        reduce();

        assert(value_.limbs_count() == UINT256_NLIMBS &&
               "invalid limbs count after reduce");

        bn254fr_t handles[UINT256_NLIMBS];
        for (uint32_t i = 0, sz = value_.limbs_count(); i < sz; ++i) {
            handles[i][0] = value_.limbs()[i][0];
        }

        uint256 res;
        uint256_set_words_checked(res.data(), handles);
        return res;
    }

    /// Sets storage value from uint256
    void set_uint256(const uint256 &x) {
        bn254fr_t limbs[UINT256_NLIMBS];
        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            bn254fr_alloc(limbs[i]);
        }

        uint256_get_words_checked(limbs, x.data());
        value_.set(limbs, UINT256_NLIMBS, n_bits_base, true);
        is_reduced_ = false;

        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            bn254fr_free(limbs[i]);
        }
    }

    static void add(prime_field_uint256_storage &out,
                    const prime_field_uint256_storage &x,
                    const prime_field_uint256_storage &y) {
        auto max_bits_fn = [](auto &&x, auto &&y) {
            return bn254fr_bigint::add_no_carry_res_bits_count(x.value_,
                                                               y.value_);
        };

        convert_args_to_proper_if_required(max_bits_fn, x, y);
        out.value_ = bn254fr_bigint::add_no_carry(x.value_, y.value_);
        out.is_reduced_ = false;
    }

    static void sub(prime_field_uint256_storage &out,
                    const prime_field_uint256_storage &x,
                    const prime_field_uint256_storage &y) {
        auto max_bits_fn = [](auto &&x, auto &&y) {
            return std::max(x.value_.bits_count() + 1,
                            y.value_.bits_count())
                            + 1;
        };

        convert_args_to_proper_if_required(max_bits_fn, x, y);

        // calculate multiplier for field modulus that should be added to x
        // to be sure result of subtraction is greater or equal to zero
        uint32_t mult_bits_count = y.value_.is_unsigned() ?
                                   y.value_.bits_count() :
                                   y.value_.bits_count() - 1;
        bn254fr_bigint mult =
            calc_overflow_multiplier(y.size(),
                                     mult_bits_count,
                                     Field::modulus().value_);

        // calculate x + mult
        bn254fr_bigint x_plus_mult =
            bn254fr_bigint::add_no_carry(x.value_, mult);

        // calculate x + mult - y
        out.value_ = bn254fr_bigint::sub_no_carry(x_plus_mult, y.value_);
        out.is_reduced_ = false;
    }

    static void mul(prime_field_uint256_storage &out,
                    const prime_field_uint256_storage &x,
                    const prime_field_uint256_storage &y) {
        auto max_bits_fn = [](auto &&x, auto &&y) {
            return bn254fr_bigint::mul_no_carry_res_bits_count(x.value_,
                                                               y.value_);
        };

        convert_args_to_proper_if_required(max_bits_fn, x, y);

        out.value_ = bn254fr_bigint::mul_no_carry(x.value_, y.value_);
        out.is_reduced_ = false;
    }

    static void inv(prime_field_uint256_storage &out,
                    const prime_field_uint256_storage &x) {
        out.value_ = bn254fr_bigint::invmod(x.value_, Field::modulus().value_);
        out.is_reduced_ = true;
    }

    static void div(prime_field_uint256_storage &out,
                    const prime_field_uint256_storage &x,
                    const prime_field_uint256_storage &y) {

        // To perform dividion we do the following:
        // 1. Calculate out = x / y mod prime = x * y^-1 mod prime without
        //    constraints.
        // 2. Calculate x2 = out * y without carry and with constraints.
        // 3. Prove that x2 == x mod Field::modulus()

        auto max_bits_fn = [](auto &&x, auto &&y) {
            // for x/y division, we calculate x2 = y * out,
            // and then compare x and x2 using subtraction
            auto mul_res_bits = bn254fr_bigint_mul_checked_no_carry_bits(
                    y.value_.limbs_count(),
                    y.value_.bits_count(),
                    UINT256_NLIMBS,
                    n_bits_base);

            auto cmp_bits = assert_equal_mod_bits(x.value_.bits_count(),
                                                  mul_res_bits);

            return cmp_bits;
        };

        convert_args_to_proper_if_required(max_bits_fn, x, y);

        // calculate y_inv = y^-1 mod p without constraints
        auto y_inv =
            bn254fr_bigint::invmod_unchecked(y.value_, Field::modulus().value_);

        // convert x to proper representation
        auto x_proper = x.value_.to_proper_unchecked();

        // calculate x_mul_y_inv = x_proper * y_inv without constraints
        auto x_mul_y_inv = bn254fr_bigint::mul_unchecked(x_proper, y_inv);

        // calculate out = x * y_inv mod p without constraints
        out.value_ = bn254fr_bigint::rem_unchecked(x_mul_y_inv,
                                                   Field::modulus().value_);
        out.is_reduced_ = true;

        // calculate x2 = out * y without carry and with constraints
        auto x2 = bn254fr_bigint::mul_no_carry(out.value_, y.value_);

        // check x2 is equal x mod p
        assert_equal_mod(x.value_, x2, Field::modulus().value_);
    }

    static void mux(prime_field_uint256_storage &out,
                    const bn254fr_class &cond,
                    const prime_field_uint256_storage &x,
                    const prime_field_uint256_storage &y) {
        out.value_.realloc(std::max(x.size(), y.size()));

        uint32_t common_size = std::min(x.size(), y.size());
        for (size_t i = 0; i < common_size; ++i) {
            bn254fr_mux(out.value_.limbs().data()[i],
                        cond.data(),
                        x.value_.limbs().data()[i],
                        y.value_.limbs().data()[i]);
        }

        bn254fr_t zero;
        bn254fr_alloc(zero);

        if (x.size() < y.size()) {
            for (size_t i = common_size, sz = y.size(); i < sz; ++i) {
                bn254fr_mux(out.value_.limbs().data()[i],
                            cond.data(),
                            zero, y.value_.limbs().data()[i]);
            }
        } else if (y.size() < x.size()) {
            for (size_t i = common_size, sz = x.size(); i < sz; ++i) {
                bn254fr_mux(out.value_.limbs().data()[i],
                            cond.data(),
                            x.value_.limbs().data()[i],
                            zero);
            }
        }

        bn254fr_free(zero);

        out.is_reduced_ = x.is_reduced_ && y.is_reduced_;
        out.value_.set_unsigned(x.value_.is_unsigned() && y.value_.is_unsigned());

        if (out.value_.is_unsigned()) {
            out.value_.set_bits_count(std::max(x.value_.bits_count(), y.value_.bits_count()));
        } else {
            uint32_t x_bits = x.value_.bits_count();
            if (x.value_.is_unsigned()) {
                ++x_bits;
            }

            uint32_t y_bits = y.value_.bits_count();
            if (y.value_.is_unsigned()) {
                ++y_bits;
            }

            out.value_.set_bits_count(std::max(x_bits, y_bits));
        }
    }

    void eqz(bn254fr_class &out) const {
        out = value_.eqz();
    }

    void reduce() const {
        if (is_reduced_) {
            return;
        }

        // calculate remainder
        bn254fr_bigint res = bn254fr_bigint::rem(value_,
                                                 Field::modulus().value_);

        // replace current value
        value_ = std::move(res);
        is_reduced_ = true;
    }

    size_t size() const {
        return value_.limbs().size();
    }

    size_t import_u32(std::span<const uint32_t> u32_limbs) {
        value_.realloc(UINT256_NLIMBS);

        size_t sz = u32_limbs.size() > 8 ? 8 : u32_limbs.size();
        size_t n_full_limbs = sz / 2;

        for (size_t i = 0; i < n_full_limbs; ++i) {
            uint64_t u64_limb = u32_limbs[i * 2 + 1];
            u64_limb <<= 32;
            u64_limb |= u32_limbs[i * 2];
            bn254fr_set_u64(value_.limbs()[i], u64_limb);
            bn254fr_assert_equal_u64(value_.limbs()[i], u64_limb);
        }

        if (sz % 2 != 0) {
            // adding extra limb
            bn254fr_set_u32(value_.limbs()[n_full_limbs],
                            u32_limbs[n_full_limbs * 2]);
            bn254fr_assert_equal_u32(value_.limbs()[n_full_limbs], u32_limbs[n_full_limbs * 2]);
        }

        return std::min(u32_limbs.size(), size_t{8});
    }

    size_t export_u32(std::span<uint32_t> u32_limbs) const {
        reduce();

        assert(value_.limbs_count() == UINT256_NLIMBS &&
               "invalid limbs count after reduce");

        for (size_t i = 0; i < UINT256_NLIMBS; ++i) {
            uint64_t limb_u64 = witness_cast_u64(bn254fr_get_u64(value_.limbs()[i]));
            bn254fr_assert_equal_u64(value_.limbs()[i], limb_u64);
            u32_limbs[i * 2] = limb_u64 & 0xFFFFFFFFUL;
            u32_limbs[i * 2 + 1] = limb_u64 >> 32;
        }

        return 8;
    }

    void dump() const {
        value_.dump();
    }

private:
    // For given value p calculates c that c * p is greater than any big integer
    // value that can be represented for specified number of bits and limbs.
    // Returns c * p. p must be in proper representation
    static bn254fr_bigint calc_overflow_multiplier(uint32_t n_limbs,
                                                   uint32_t n_overflow_bits,
                                                   const bn254fr_bigint &p) {
        assert(p.is_proper() && "p must be in proper representation");

        // calculate maximum value of big integer in proper representation
        auto max_val = bn254fr_bigint::max_proper(n_limbs, n_overflow_bits);

        // calculate (q, r) = idiv(max_val, p)
        auto [q, r] = bn254fr_bigint::idiv_unchecked(max_val, p);

        // Add one to q if r is not zero
        if (!r.is_zero()) {
            q = bn254fr_bigint::add_no_carry_unchecked(q, bn254fr_bigint{1, 1});
        }

        // calculate q * p
        auto q_mul_p = bn254fr_bigint::mul_unchecked(q, p);

        // Convert q * p to overflow representation with n_overflow_bits + 1
        // bits in each limb. It should fits into n_limbs limbs.
        return q_mul_p.to_overflow(n_limbs, n_overflow_bits + 1);
    }

    // Checks that big integer in signed overflow form is equal to zero mod m
    static void assert_equal_zero_mod(const bn254fr_bigint &x,
                                      const bn254fr_bigint &m) {
        // To prove x == 0 mod m we do the following:
        // 0. Convert x to proper representation without constraints
        // 1. Compute (q, r) = idiv(x_proper, m) without constraints
        // 2. Compute y = q * m without carry and with constraints
        // 3. Compute difference d = x - y without carry and with constraints
        // 4. Convert d to proper representation with constraints
        // 5. Check d_proper == 0
        // 6. Check r == 0

        // 0. Convert x to proper representation
        auto x_proper = x.to_proper_unchecked();

        // 1. Compute (q, r)
        auto [q, r] = bn254fr_bigint::idiv_unchecked(x_proper, m);

        // 2. Compute y = q * m
        auto y = bn254fr_bigint::mul_no_carry(q, m);

        // 3. Compute d = x - y
        auto d = bn254fr_bigint::sub_no_carry(x, y);

        // 4. Convert d to proper representation
        auto d_proper = d.to_proper();

        // 5. Check d_proper == 0
        for (auto && limb : d_proper.limbs()) {
            bn254fr_assert_equal(limb, bn254fr_class{0}.data());
        }

        // 6. Chek r == 0
        for (auto && limb : r.limbs()) {
            bn254fr_assert_equal(limb, bn254fr_class{0}.data());
        }
    }

    // Returns number of bits required for equality comparison
    // of x and y mod m
    static uint32_t assert_equal_mod_bits(uint32_t x_bits,
                                          uint32_t y_bits) {
        return std::max(x_bits, y_bits + 3) + 1;
    }

    // Checks that two big integers in overflow representation are equal mod m
    static void assert_equal_mod(const bn254fr_bigint &x,
                                 const bn254fr_bigint &y,
                                 const bn254fr_bigint &m) {
        assert(assert_equal_mod_bits(x.bits_count(), y.bits_count()) <= 250 &&
               "assert_equal_mod overflow");

        // To prove x === y mod m we do the following:
        // 1. For y, calculate overflow multiplier a*m, so that a*m >= y
        // 2. Calculate x + (a*m - y) without carry and with constraints
        // 2. Check x + (a*m - y) is equal to zero mod m

        // calculate overflow multiplier
        bn254fr_bigint mult = calc_overflow_multiplier(y.limbs_count(),
                                                       y.bits_count(),
                                                       m);

        // sub_res = a*m - y
        bn254fr_bigint sub_res = bn254fr_bigint::sub_no_carry(mult, y);

        // add_res = x + (a*m - y)
        bn254fr_bigint add_res = bn254fr_bigint::add_no_carry(x, sub_res);

        // check add_res == 0 mod m
        assert_equal_zero_mod(add_res, m);
    }

    static void convert_args_to_proper_if_required(
            const auto calc_max_bits_fn,
            const prime_field_uint256_storage &x,
            const prime_field_uint256_storage &y) {

        if (calc_max_bits_fn(x, y) > n_max_bits) {
            if (x.value_.bits_count() > y.value_.bits_count()) {
                x.reduce();
                if (calc_max_bits_fn(x, y) > n_max_bits) {
                    y.reduce();
                }
            } else {
                y.reduce();
                if (calc_max_bits_fn(x, y) > n_max_bits) {
                    x.reduce();
                }
            }
        }
    }

private:
    mutable bn254fr_bigint value_;
    mutable bool is_reduced_ = true;
};


/// Generic prime field implemented on top of bn254fr big integers
template <typename Derived>
struct prime_field_uint256 {
    using storage_type = prime_field_uint256_storage<Derived>;
    using boolean_type = bn254fr_class;

    static constexpr size_t num_bytes = 32;
    static constexpr size_t num_rounded_bits = 8 * num_bytes;

    virtual ~prime_field_uint256() = default;

    static void set_zero(storage_type &x) {
        x.set_u32(0);
    }

    static void set_one(storage_type &x) {
        x.set_u32(1);
    }
    
    static void add(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        prime_field_uint256_storage<Derived>::add(out, x, y);
    }

    static void sub(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        prime_field_uint256_storage<Derived>::sub(out, x, y);
    }

    static void mul(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        prime_field_uint256_storage<Derived>::mul(out, x, y);
    }

    static void div(storage_type &out,
                    const storage_type &x,
                    const storage_type &y) {
        prime_field_uint256_storage<Derived>::div(out, x, y);
    }

    static void neg(storage_type &out, const storage_type &x) {
        storage_type sub_res;
        bn254fr_class eqz_res;
        x.eqz(eqz_res);
        prime_field_uint256_storage<Derived>::sub(sub_res, Derived::modulus(), x);
        prime_field_uint256_storage<Derived>::mux(out, eqz_res, sub_res, x);
    }

    static void inv(storage_type &out, const storage_type &x) {
        prime_field_uint256_storage<Derived>::inv(out, x);
    }

    static void sqr(storage_type &out, const storage_type &x) {
        mul(out, x, x);
    }

    static void powm_ui(storage_type &out,
                        const storage_type &base,
                        uint32_t exp) {
        storage_type res{1};
        storage_type cur_pow = base;

        while (exp != 0) {
            if (exp & 0x1) {
                storage_type tmp;
                mul(tmp, res, cur_pow);
                res = tmp;
            }

            exp >>= 1;
            storage_type tmp2;
            mul(tmp2, cur_pow, cur_pow);
            cur_pow = tmp2;
        }

        out = res;
    }

    static void mux(storage_type &res,
                    const boolean_type &cond,
                    const storage_type &a,
                    const storage_type &b) {
        prime_field_uint256_storage<Derived>::mux(res, cond, a, b);
    }

    static void eqz(boolean_type &res, const storage_type &a) {
        a.eqz(res);
    }

    static void reduce(storage_type &x) {
        x.reduce();
    }

    static void to_bits(boolean_type *bits, const storage_type &a) {
        a.to_uint256().to_bits(bits);
    }

    static size_t import_u32(storage_type &x, std::span<const uint32_t> limbs) {
        return x.import_u32(limbs);
    }

    static size_t export_u32(const storage_type &x, std::span<uint32_t> limbs) {
        return x.export_u32(limbs);
    }

    static size_t import_bytes_little(storage_type &x,
                                      std::span<const unsigned char> bytes) {
        uint256 ui;
        ui.set_bytes_little(bytes.data(), bytes.size());
        x.set_uint256(ui);
        reduce(x);
        return std::min(bytes.size(), size_t{32});
    }

    static size_t import_bytes_big(storage_type &x,
                                   std::span<const unsigned char> bytes) {
        uint256 ui;
        ui.set_bytes_big(bytes.data(), bytes.size());
        x.set_uint256(ui);
        reduce(x);
        return std::min(bytes.size(), size_t{32});
    }

    static size_t import_bytes(storage_type &x,
                               std::span<const unsigned char> bytes,
                               int byte_order) {
        if (byte_order == -1) {
            return import_bytes_little(x, bytes);
        } else {
            return import_bytes_big(x, bytes);
        }

        return 0;
    }

    static size_t export_bytes_little(const storage_type &x,
                                      std::span<unsigned char> bytes) {
        assert(bytes.size() == 32 && "invalid number of bytes to export");
        x.to_uint256().to_bytes_little(bytes.data());
        return 32;
    }

    static size_t export_bytes_big(const storage_type &x,
                                   std::span<unsigned char> bytes) {
        assert(bytes.size() == 32 && "invalid number of bytes to export");
        x.to_uint256().to_bytes_big(bytes.data());
        return 32;
    }

    static size_t export_bytes(const storage_type &x,
                               std::span<unsigned char> bytes,
                               int byte_order) {
        if (byte_order == -1) {
            return export_bytes_little(x, bytes);
        } else {
            return export_bytes_big(x, bytes);
        }
    }

    static void import_u256(storage_type &x, const uint256 &u) {
        x.set_uint256(u);
    }

    static void export_u256(const storage_type &x, uint256 &u) {
        u = x.to_uint256();
    }

    static void print(const storage_type &x) {
        x.to_uint256().print();
    }

    static void assert_equal(const storage_type &x, const storage_type &y) {
        uint256::assert_equal(x.to_uint256(), y.to_uint256());
    }
};


template <typename F>
concept HasImportU256 = requires(typename F::storage_type &x,
                                 const uint256 &u) {
    { F::import_u256(x, u) };
};

template <typename F>
concept HasExportU256 = requires(const typename F::storage_type &x,
                                 uint256 &u) {
    { F::export_u256(x, u) };
};

/// Sets p256 field element from uin256 value.
/// The uint256 value must be within the field.
template <HasImportU256 F>
inline void set_uint256(field_element<F> &out, const uint256 &x) {
    F::import_u256(out.data(), x);
}

/// Converts p256 field element to uint256 value
template <HasExportU256 F>
inline const uint256 to_uint256(const field_element<F> &x) {
    uint256 res;
    F::export_u256(x.data(), res);
    return res;
}


}


#endif // __LIGETRON_PRIME_FIELD_UINT256_H__
