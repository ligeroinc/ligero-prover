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
 * bn254fr_bigint.h
 *
 * Big integer implementation on top of bn254fr limbs
 *
 */

#ifndef __LIGETRON_BN254FR_BIGINT_HPP__
#define __LIGETRON_BN254FR_BIGINT_HPP__

#include <ligetron/api.h>
#include <ligetron/bn254fr_class.h>
#include <span>


namespace ligetron {


/// Big integer with infinite precision based on bn254fr limbs
class bn254fr_bigint {
public:
    static constexpr size_t base_bits_count = 64;
    static constexpr size_t max_bits_count = 250;

    /// Default constructor. Creates zero big integer with no limbs.
    bn254fr_bigint() = default;

    /// Constructs zero big integer with specified number of allocated limbs.
    bn254fr_bigint(uint32_t n_limbs);

    /// Constructs big integer with specified number of allocated limbs
    /// from u64 value.
    bn254fr_bigint(uint32_t n_limbs, uint64_t val);

    /// Constructs big integer from bn254fr limbs, adds equality constraints.
    bn254fr_bigint(bn254fr_t *limbs,
                   uint32_t n_limbs,
                   uint32_t n_bits,
                   bool is_unsign);

    /// Copy constructor. Allocates new big integer and copies another
    /// big integer into this value. Adds equality constraints
    bn254fr_bigint(const bn254fr_bigint &other);

    /// Move constructor. Moves other big integer to this instance
    /// and sets other value to zero without allocated limbs.
    bn254fr_bigint(bn254fr_bigint &&other);

    /// Destructs big integer value and deallocates all limbs
    ~bn254fr_bigint();

    /// Copy-assignment operator. Reallocates this big integer value
    /// and copies another value into it. Adds equality constraints.
    bn254fr_bigint &operator=(const bn254fr_bigint &other);

    /// Move-assignment operator. Deallocates this big integer value
    /// and moves other value into it. Resets other value to zero.
    bn254fr_bigint &operator=(bn254fr_bigint &&other);

    /// Returns number of limbs in big integer
    uint32_t limbs_count() const;

    /// Return maximum number of bits in each limb
    uint32_t bits_count() const;

    /// Sets maximum number of bits in each limb
    void set_bits_count(uint32_t cnt) {
        bits_count_ = cnt;
    }

    /// Returns true if big integer has unsigned limbs
    bool is_unsigned() const;

    /// Sets whether big integer has unsigned limbs
    void set_unsigned(bool u) {
        is_unsigned_ = u;
    }

    /// Returns true if this big integer is in proper representation, i.e.
    /// is_unsigned() is true and bits_count() == base_bits_count.
    bool is_proper() const;

    /// Returns range of big integer limbs
    std::span<bn254fr_t> limbs() const;

    /// Sets big integer value from limbs, adds equality constraints.
    void set(bn254fr_t *limbs, uint32_t n_limbs, uint32_t n_bits, bool is_uns);

    /// Prints big integer value to stdout
    void print() const;

    /// Dumps value and big integer contents to stdout
    void dump() const;

    /// Returns true if big integer value is zero, without adding constraints.
    bool is_zero() const;

    /// Converts big integer value to proper representation,
    /// adds constraints.
    bn254fr_bigint to_proper() const;

    /// Converts big integer value to proper representation without
    /// adding constraints.
    bn254fr_bigint to_proper_unchecked() const;

    /// Converts big integer value to overflow representation with
    /// specified number of limbs n_bits bits each.
    bn254fr_bigint to_overflow(uint32_t n_limbs, uint32_t n_bits) const;

    /// Returns bn254 one value if this value is zero,
    /// zero bn254 value otherwise. Adds constraints.
    bn254fr_class eqz() const;

    /// Compares a with b. Returns one if a == b, zero otherwise.
    /// a and b must be in proper representation.
    static bn254fr_class eq(const bn254fr_bigint &a, const bn254fr_bigint &b);

    /// Comapres a with b. Returns one if a < b, zero otherwise.
    /// a and b must be in proper representation.
    static bn254fr_class lt(const bn254fr_bigint &a, const bn254fr_bigint &b);

    /// Returns maximum big integer value for specified number of limbs
    /// and number of bits in overflow representation.
    static bn254fr_bigint max(uint32_t n_limbs, uint32_t n_bits);

    /// Returns maximum big integer value for specified number of limbs
    /// and number of bits in proper representation.
    static bn254fr_bigint max_proper(uint32_t n_limbs, uint32_t n_bits);

    /// Returns number of bits for result of addition without carry.
    static uint32_t add_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                const bn254fr_bigint &y);

    /// Performs addition of two big integers without carry, adds constraints.
    static bn254fr_bigint add_no_carry(const bn254fr_bigint &x,
                                       const bn254fr_bigint &y);

    /// Performs addition of two big integers without carry and constraints
    static bn254fr_bigint add_no_carry_unchecked(const bn254fr_bigint &x,
                                                 const bn254fr_bigint &y);

    /// Returns number of bits for result of subtraction without carry.
    static uint32_t sub_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                const bn254fr_bigint &y);

    /// Performs subtraction of two big integers without carry, adds
    /// constraints. The x value must be greater or equal to y value.
    static bn254fr_bigint sub_no_carry(const bn254fr_bigint &x,
                                       const bn254fr_bigint &y);

    /// Returns number of bits for result of multiplication without carry
    static uint32_t mul_no_carry_res_bits_count(const bn254fr_bigint &x,
                                                const bn254fr_bigint &y);

    /// Performs multiplication of two big integers without carry,
    /// adds constraints.
    static bn254fr_bigint mul_no_carry(const bn254fr_bigint &x,
                                       const bn254fr_bigint &y);

    /// Performs multiplication of two big integers without adding constraints
    static bn254fr_bigint mul_unchecked(const bn254fr_bigint &x,
                                        const bn254fr_bigint &y);

    /// Performs integer division, adds constraints.
    /// Returns quotient and remainder.
    static std::tuple<bn254fr_bigint, bn254fr_bigint>
    idiv(const bn254fr_bigint &x, const bn254fr_bigint &y);

    /// Performs integer division without adding constraints.
    /// Returns quotient and remainder.
    static std::tuple<bn254fr_bigint, bn254fr_bigint>
    idiv_unchecked(const bn254fr_bigint &x, const bn254fr_bigint &y);

    /// Calculates remainder of division of two big integers, adds cosntraints.
    static bn254fr_bigint rem(const bn254fr_bigint &a, const bn254fr_bigint &m);

    /// Calculates remainder of division of two big integers
    /// without constraints. 
    static bn254fr_bigint rem_unchecked(const bn254fr_bigint &a,
                                        const bn254fr_bigint &m);

    /// Performs big integer modulus inversion with constraints.
    static bn254fr_bigint invmod(const bn254fr_bigint &a,
                                 const bn254fr_bigint &m);

    /// Performs big integer modulus inversion without constraints.
    static bn254fr_bigint invmod_unchecked(const bn254fr_bigint &a,
                                           const bn254fr_bigint &m);

    /// Reallocates limbs in big integer
    void realloc(uint32_t count) {
        dealloc();
        alloc(count);
    }

private:
    /// Allocate big integer limbs of specified size
    void alloc(uint32_t count);

    /// Deallocate big integer limbs
    void dealloc();

    /// Copies another value into this value, adds constraints
    void copy(const bn254fr_bigint &other);

    /// Moves another value into this value. Resets another value.
    void move(bn254fr_bigint &&other);

    /// Resets this value to zero value without allocated limbs.
    void reset();


    bn254fr_t *limbs_ = nullptr;
    uint32_t limbs_count_ = 0;
    uint32_t bits_count_ = base_bits_count;
    bool is_unsigned_ = true;
};


}


#endif // __LIGETRON_BN254FR_BIGINT_HPP__
