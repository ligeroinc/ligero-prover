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
 * bn254fr_class.h
 *
 * C++ wrapper for bn254fr field operations.
 *
 * Refer to "ligetron/bn254fr.h" for the C API.
 *
 */

#ifndef LIGETRON_BN254FR_CLASS_H_
#define LIGETRON_BN254FR_CLASS_H_

#include <ligetron/bn254fr.h>

namespace ligetron {

struct bn254fr_class {
    bn254fr_class();
    bn254fr_class(int i); // Sets field value to (uint64_t)i
    bn254fr_class(const char *str, int base = 0); // Base 0 sets the base depending on the value prefix (0x for hex, etc...)
    bn254fr_class(const bn254fr_t o);
    bn254fr_class(const bn254fr_class& o);

    bn254fr_class& operator=(const bn254fr_t o);
    bn254fr_class& operator=(const bn254fr_class& o);
    ~bn254fr_class();

    __bn254fr* data() { return data_; }
    const __bn254fr* data() const { return data_; }

    bool is_constrained() const {
        return constrained_;
    }

    /** Resets the field element value and removes the constraints. */
    void clear();

    /* --------------- Misc --------------- */
    /** Get field element in a uint64_t constant. */
    uint64_t get_u64() const;

    /**
     * Debug print a field element - value printed with base 10.
    */
    void print_dec();

    /**
     * Debug print a field element - value printed with base 16.
    */
    void print_hex();

    /* --------------- Setters --------------- */
    /** Set field element to a uint32_t constant. */
    void set_u32(uint32_t x);

    /** Set field element to a uint64_t constant. */
    void set_u64(uint64_t x);

    /**
     * Set field element from byte buffer.
     * Read "len" bytes from buffer (up to 32 bytes mod p)).
     * Set bytes in little-endian order.
     */
    void set_bytes_little(const unsigned char *bytes, uint32_t len);

    /**
     * Set field element from byte buffer.
     * Read "len" bytes from buffer (up to 32 bytes mod p)).
     * Set bytes in little-endian order.
     */
    void set_bytes_big(const unsigned char *bytes, uint32_t len);

    /** Set field element from decimal (base=10) or hex (base=16) string. */
    void set_str(const char* str, uint32_t base);

    /* ---- Scalar Comparisons ---- */

    friend bool operator == (const bn254fr_class& obj1, const bn254fr_class& obj2);

    friend bool operator < (const bn254fr_class& obj1, const bn254fr_class& obj2);

    friend bool operator <= (const bn254fr_class& obj1, const bn254fr_class& obj2);

    friend bool operator > (const bn254fr_class& obj1, const bn254fr_class& obj2);

    friend bool operator >= (const bn254fr_class& obj1, const bn254fr_class& obj2);

    /** Return true if a == 0 */ 
    bool eqz() const;

    /* --------------- Logical Operations --------------- */
    friend bool operator && (const bn254fr_class& obj1, const bn254fr_class& obj2);

    friend bool operator || (const bn254fr_class& obj1, const bn254fr_class& obj2);

    /* --------------- Bitwise Operations --------------- */

    /** Decompose a into `count` bits, stored in count-sized 'bn254fr_class' array (outs) as 0 or 1 field values. */
    void to_bits(bn254fr_class* outs, uint32_t count) const;

    /* --------------- Helper functions --------------- */

    /** out = cond ? a1 : a0 */
    void static mux(bn254fr_class& out, bn254fr_class& cond, bn254fr_class& a0, bn254fr_class& a1);

    void static mux2(bn254fr_class& out,
                    bn254fr_class& s0, bn254fr_class& s1,
                    bn254fr_class& a0, bn254fr_class& a1,
                    bn254fr_class& a2, bn254fr_class& a3);

    /* --------------- Friend function list --------------- */

    friend void assert_equal(bn254fr_class& a, bn254fr_class& b);
    friend void addmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);
    friend void submod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);
    friend void mulmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);
    friend void mulmod(bn254fr_class& out, bn254fr_class& a, const uint64_t k);
    friend void divmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);
    friend void divmod(bn254fr_class& out, bn254fr_class& a, const uint64_t k);
    friend void negmod(bn254fr_class& out, bn254fr_class& a);
    friend void invmod(bn254fr_class& out, bn254fr_class& a);
    friend void oblivious_if(bn254fr_class& out, bn254fr_class& cond, bn254fr_class& t, bn254fr_class& f);

protected:
    bn254fr_t data_;
    bool constrained_ = false; // Track if this instance has been constrained
};


/* --------------- Zero Knowledge --------------- */
/** Assert a == b in the field (constraint only). */
void assert_equal(bn254fr_class& a, bn254fr_class& b);

/* --------------- Scalar Arithmetic --------------- */

/** out = a + b mod p */
void addmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);

/** out = a - b mod p */
void submod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);

/** out = a * b mod p */
void mulmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);

void mulmod(bn254fr_class& out, bn254fr_class& a, const uint64_t k);

/** out = a * b^{-1} mod p */
void divmod(bn254fr_class& out, bn254fr_class& a, bn254fr_class& b);

void divmod(bn254fr_class& out, bn254fr_class& a, const uint64_t k);

/** a = -a mod p */
void negmod(bn254fr_class& out, bn254fr_class& a);

/** out = a^{-1} mod p */
void invmod(bn254fr_class& out, bn254fr_class& a);

/** A rename of "mux" operation */
void oblivious_if(bn254fr_class& out, bn254fr_class& cond, bn254fr_class& t, bn254fr_class& f);

} // namespace ligetron

#endif // LIGETRON_BN254FR_CLASS_H_