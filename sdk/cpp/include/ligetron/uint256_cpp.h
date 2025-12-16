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
 * uint256_cpp.h
 *
 * C++ API for uint256 operations.
 *
 * Refer to "ligetron/uint256.h" for the C API.
 *
 */

#ifndef __LIGETRON_UINT256_CPP_H__
#define __LIGETRON_UINT256_CPP_H__

#include <ligetron/uint256.h>
#include <ligetron/bn254fr_class.h>
#include <array>
#include <tuple>


namespace ligetron {


/// C++ wrapper for uint256 value. Manages uint256 value lifetime
/// and provides functions for value conversion and arithmetic operations
/// with automatic constraints.
/// Does not automatically track whether the value was constrained or not.
/// The value can't be modified after it has been constrained in another
/// operation until realloc is called.
class uint256 {
public:
    /// Allocates new uint256 value and initializes it with zero
    uint256();

    /// Allocates new uint256 value and initializes it from bn254 value,
    /// adds constraints
    explicit uint256(const bn254fr_t val);

    /// Allocates new uint256 value and initializes it from bn254 value,
    /// adds constraints
    explicit uint256(const bn254fr_class &val);

    /// Allocates new uint256 value and initializes it from uint64_t,
    /// adds constraints
    explicit uint256(uint64_t val);

    /// Allocates new uint256 value and initializes it
    /// from null terminated string
    explicit uint256(const char *str, int base = 0);

    /// Allocates new uint256 value and initializes it from byte buffer,
    /// without adding constraints
    /// "order" value:
    ///   -1: use little-endian byte order,
    ///    1: use big-endian byte order
    explicit uint256(const unsigned char *bytes, uint32_t len, int order);

    /// Deallocates uint256 value
    ~uint256();

    /// Copy constructor. Allocates new uint256 value and initializes it
    /// with existing value, adds constraints
    uint256(const uint256 &other);

    /// Moves another uint256 value to this
    uint256(uint256 &&other);

    /// Allocates new uint256 value and initializes it
    /// with existing value, adds constraints
    uint256(const uint256_t &ui);

    /// Reallocates this value and copies another value to this,
    /// adds constraints.
    uint256 &operator=(const uint256 &other);

    /// Deallocates this value and moves another value to this instance,
    /// without adding constraints
    uint256 &operator=(uint256 &&other);

    /// Reallocates this value.
    void realloc();

    /// Copies another uint256 value to this, adds constraints.
    void copy(const uint256 &other);

    /// Deallocates this value and moves another value to this instance,
    /// without adding constraints
    void move(uint256 &&other);

    /// Swaps two uint256 values without adding constraints
    friend void swap(uint256 &first, uint256 &second);

    /// Adds equality constraints for two uint256 values
    friend void assert_equal(const uint256 &x, const uint256 &y);

    /// Prints value to output stream
    void print() const;

    /// Returns uint256 handle
    __uint256 *data();

    /// Returns uint256 handle
    const __uint256 *data() const;

    ////////////////////////////////////////////////////////////
    // Conversions to and from uint256

    /// Sets uint256 words with adding equality constraints.
    /// words must point to array of size UINT256_NLIBS.
    void set_words(const bn254fr_class *words);

    /// Gets uint256 words with adding equality constraints.
    /// words must point to array of size UINT256_NLIBS.
    void get_words(bn254fr_class *words) const;

    /// Sets uint256 value from bytes in little endian, adds constraints
    void set_bytes_little(const unsigned char *bytes, uint32_t sz);

    /// Sets uint256 value from bytes in big endian, adds constraints
    void set_bytes_big(const unsigned char *bytes, uint32_t sz);

    /// Sets uint256 value from bytes in little endian
    /// without adding constraints
    void set_bytes_little_unchecked(const unsigned char *bytes, uint32_t sz);

    /// Sets uint256 value from bytes in big endian
    /// without adding constraints
    void set_bytes_big_unchecked(const unsigned char *bytes, uint32_t sz);

    /// Converts uint256 value to bytes in little endian, adds constraints
    void to_bytes_little(unsigned char *bytes) const;

    /// Converts uint256 value to bytes in big endian, adds constraints
    void to_bytes_big(unsigned char *bytes) const;

    /// Converts uint256 value to bytes in little endian
    /// without adding constraints
    void to_bytes_little_unchecked(unsigned char *bytes) const;

    /// Converts uint256 value to bytes in big endian
    /// without adding constraints
    void to_bytes_big_unchecked(unsigned char *bytes) const;
    
    /// Sets uint256 value from string
    void set_str(const char *str, int base = 0);

    /// Sets uint256 value from bn254 value, adds constraints
    void set_bn254(const bn254fr_class &bn254);

    /// Sets uint256 value from u64, adds constraints
    void set_u64(uint64_t x);

    /// Sets uint256 value from u64 without adding constraints
    void set_u64_unchecked(uint64_t x);

    /// Converts uint256 value to u64, adds constraints
    uint64_t get_u64() const;

    /// Converts uint256 value to u64 without adding constraints
    uint64_t get_u64_unchecked() const;

    /// Sets uint256 value from u32, adds constraints
    void set_u32(uint32_t x);

    /// Composes uint256 value from bits, adds constraints.
    /// bits must point to an array of size 256.
    void from_bits(const bn254fr_class *bits);

    /// Decomposes uint256 value into bits, adds constraints.
    /// out must point to an array of size 256.
    void to_bits(bn254fr_class *out) const;

private:
    uint256_t handle_;
};


/// Represents uint256 value with additional carry flag.
struct uint256_cc {
    uint256 val;
    bn254fr_class carry;

    uint256_cc() = default;
    uint256_cc(const uint256_cc &) = default;
    uint256_cc(uint256_cc &&) = default;
};


/// Represents 512-bit value as pair of low and high uint256 parts
struct uint256_wide {
    uint256 lo;
    uint256 hi;

    uint256_wide() = default;
    uint256_wide(const uint256_wide &) = default;
    uint256_wide(uint256_wide &&) = default;

    /// Performs uint512 integer division by large value, adds constraints.
    /// Writes low part of quotient in q_low and high part of quotient in
    /// q_high.
    /// The most significant limb of divisor `d` must not be zero so quotient
    /// fits into pair of uint256 and bn254 values.
    void divide_qr_normalized(uint256 &q_low,
                              bn254fr_class &q_high,
                              uint256 &r,
                              const uint256 &d);

    /// Performs uint512 mod operation, adds constraints.
    /// The m value should be large enough so result of modular operation
    /// fits into single uint256 value.
    void mod(uint256 &out, const uint256 &m);

    /// Performs uint512 mod operation, adds constraints.
    /// The m value should be large enough so result of modular operation
    /// fits into single uint256 value.
    /// Returns result of mod operation.
    uint256 operator%(const uint256 &m);
};


////////////////////////////////////////////////////////////
// Arithmetic operations

/// Performs uint256 addition, adds constraints.
void add_cc(uint256_cc &out, const uint256 &a, const uint256 &b);

/// Performs uint256 addition, adds constraints.
/// Returns result of addition with carry flag.
uint256_cc add_cc(const uint256 &a, const uint256 &b);

/// Performs uint256 addition, adds constraints.
/// Drops the carry flag calculated during addition without checking.
uint256 operator+(const uint256 &a, const uint256 &b);

/// Performs uint256 subtraction, adds constraints
void sub_cc(uint256_cc &out, const uint256 &a, const uint256 &b);

/// Performs uint256 subtraction, adds constraints.
/// Returns result of substraction with carry flag.
uint256_cc sub_cc(const uint256 &a, const uint256 &b);

/// Performs uint256 subtraction, adds constraints.
/// Drops the carry flag calculated during addition without checking.
uint256 operator-(const uint256 &a, const uint256 &b);

/// Performs uint256 multiplication, adds constraints
void mul_wide(uint256_wide &out, const uint256 &a, const uint256 &b);

/// Performs uint256 multiplication, adds constraints.
/// Returns low and high parts of the result.
uint256_wide mul_wide(const uint256 &a, const uint256 &b);

/// Performs uint256 multiplication, adds constraints.
/// Returns low part of 512-bit result and drops high part without checking.
uint256 mul_lo(const uint256 &a, const uint256 &b);

/// Performs uint256 multiplication, adds constraints.
/// Returns high part of 512-bit result and drops low part without checking.
uint256 mul_hi(const uint256 &a, const uint256 &b);

/// Performs uint256 multiplication, adds constraints.
/// Returns low part of 512-bit result and drops high part without checking.
uint256 operator*(const uint256 &a, const uint256 &b);

/// Performs uint256 modular inversion, adds constraints.
void invmod(uint256 &out, const uint256 &x, const uint256 &m);

/// Performs uint256 modular inversion, adds constraints.
/// Returns inverted value.
uint256 invmod(const uint256 &x, const uint256 &m);


////////////////////////////////////////////////////////////
// Comparison operations

/// Performs comparison of two uint256 values.
/// Puts 1 to out if values are equal, 0 otherwise.
/// Adds constraints.
void eq(bn254fr_class &out, const uint256 &x, const uint256 &y);

/// Performs comparison of two uint256 values.
/// Returns 1 if values are equal, 0 otherwise.
/// Adds constraints.
bn254fr_class operator==(const uint256 &x, const uint256 &y);

/// Checks if x value is zero. Puts 1 in out if x is zero, 0 otherwise.
/// Adds constraints.
void eqz(bn254fr_class &out, const uint256 &x);

/// Checks if x value is zero. Returns 1 if x is zero, 0 otherwise.
/// Adds constraints.
/// Checks if x value is zero. Puts 1 in out if x is zero, 0 otherwise.
/// Adds constraints.
bn254fr_class eqz(const uint256 &x);


////////////////////////////////////////////////////////////
// Other operations

/// Performs mux operation for of uint256 values, adds constraints.
/// out = (cond == 1) ? a : b.
/// cond value must be either zero or one
void mux(uint256 &out,
         const bn254fr_class &cond,
         const uint256 &a,
         const uint256 &b);

/// Performs mux operation for of uint256 values, adds constraints.
/// out = (cond == 1) ? a : b.
/// cond value must be ither zero or one.
/// Returns result of mux operation.
uint256 mux(const bn254fr_class &cond, const uint256 &a, const uint256 &b);


}


#endif // __LIGETRON_UINT256_VALUE_H__
