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
 * bn254fr.h
 *
 * SIMD-style intrinsics for scalar operations over the BN254 scalar field.
 * Supports scalar and immediate (compile-time constant) operands.
 * Inspired by RVV and AVX, adapted for finite field arithmetic and zero-knowledge circuits.
 *
 * Types:
 *   - bn254fr_t:   Runtime scalar field element (opaque handle)
 *
 * --------------------------------------------------------------
 *                 Constraint Semantics and Safety
 * --------------------------------------------------------------
 *
 * `bn254fr_t` behaves like a normal mutable variable when used for **pure computation**.
 * However, once you apply any constraint (e.g., via `bn254fr_assert_add`, `assert_equal`),
 * the value becomes **semantically frozen**: it is part of the constraint system.
 *
 * After constraint assertion:
 *   - You must treat the value as **read-only**.
 *   - Reassigning or modifying the handle without freeing it may silently break
 *     circuit correctness and produce invalid proofs.
 *
 * ⚠️ Constraints are **lazy** and only enforced upon `bn254fr_free()`:
 *     the system accumulates assertions and processes them on deallocation.
 *
 * ----------------------- Correct Usage ------------------------
 *
 *   bn254fr_t a, b, sum;
 *   bn254fr_alloc(a);
 *   bn254fr_alloc(b);
 *   bn254fr_alloc(sum);
 *
 *   bn254fr_set_u64(a, 10);
 *   bn254fr_set_u64(b, 20);
 *
 *   bn254fr_addmod(sum, a, b);            // sum = a + b mod p
 *   bn254fr_assert_add(sum, a, b);        // enforce: sum == a + b
 *
 *   // ❌ INCORRECT: modifies a constrained value
 *   // bn254fr_set_u64(sum, 42);          // breaks constraint semantics since 42 != a + b
 *
 *   // ✅ CORRECT: free before reuse
 *   bn254fr_free(sum);
 *   bn254fr_alloc(sum);
 *   bn254fr_set_u64(sum, 42);             // safe
 *
 * ----------------------- Mental Model -------------------------
 *
 *   - Unconstrained `bn254fr_t` → behaves like a normal variable.
 *   - Constrained `bn254fr_t`   → becomes an immutable wire.
 *
 * Always free before reuse if a value has participated in any constraint.
 *
 * --------------------------------------------------------------
 */

#ifndef LIGETRON_BN254FR_H_
#define LIGETRON_BN254FR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <ligetron/apidef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------- Type Definitions --------------- */

struct __bn254fr {
    uint64_t __handle;
};

typedef __bn254fr bn254fr_t[1];

/* --------------- Zero Knowledge --------------- */
/** Assert a == b in the field (constraint only). */
LIGETRON_API(bn254fr, bn254fr_assert_equal)
void bn254fr_assert_equal(const bn254fr_t a, const bn254fr_t b);

/** Assert out == a + b (enforces a linear constraint). */
LIGETRON_API(bn254fr, bn254fr_assert_add)
void bn254fr_assert_add(const bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** Assert out == a * b (enforces a quadratic constraint). */
LIGETRON_API(bn254fr, bn254fr_assert_mul)
void bn254fr_assert_mul(const bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** Assert out == a * k (enforces a multiply-by-constant constraint). */
LIGETRON_API(bn254fr, bn254fr_assert_mulc)
void bn254fr_assert_mulc(const bn254fr_t out, const bn254fr_t a, const bn254fr_t k);

/* --------------- Memory Management --------------- */
/** Allocate a new field element (host sets handle). */
LIGETRON_API(bn254fr, bn254fr_alloc)
void bn254fr_alloc(bn254fr_t fr);

/** Free a previously allocated field element. */
LIGETRON_API(bn254fr, bn254fr_free)
void bn254fr_free(bn254fr_t fr);

/* --------------- Scalar Initialization --------------- */
/** Set field element to a uint32_t constant. */
LIGETRON_API(bn254fr, bn254fr_set_u32)
void bn254fr_set_u32(bn254fr_t out, uint32_t x);

/** Set field element to a uint64_t constant. */
LIGETRON_API(bn254fr, bn254fr_set_u64)
void bn254fr_set_u64(bn254fr_t out, uint64_t x);

/** Set field element from decimal (base=10) or hex (base=16) string. */
LIGETRON_API(bn254fr, bn254fr_set_str)
void bn254fr_set_str(bn254fr_t out, const char* str, uint32_t base);

/**
 * Set field element from byte buffer.
 * Read "len" bytes from buffer (up to 32 bytes mod p)).
 * "order" value:
 *   -1: use little-endian byte order,
 *    1: use big-endian byte order
 */
LIGETRON_API(bn254fr, bn254fr_set_bytes)
void bn254fr_set_bytes(bn254fr_t out, const unsigned char *bytes, uint32_t len, int32_t order);

/* --------------- Misc --------------- */
/** Get field element in a uint64_t constant. */
LIGETRON_API(bn254fr, bn254fr_get_u64)
uint64_t bn254fr_get_u64(const bn254fr_t x);

/** Copy field value from src to dest. */
LIGETRON_API(bn254fr, bn254fr_copy)
void bn254fr_copy(bn254fr_t dest, const bn254fr_t src);

/**
 * Debug print a field element.
 *  Valid "base" values are 10 or 16.
*/
LIGETRON_API(bn254fr, bn254fr_print)
void bn254fr_print(const bn254fr_t a, uint32_t base = 16);

/* --------------- Scalar Arithmetic --------------- */
/** out = a + b mod p */
LIGETRON_API(bn254fr, bn254fr_addmod)
void bn254fr_addmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a - b mod p */
LIGETRON_API(bn254fr, bn254fr_submod)
void bn254fr_submod(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a * b mod p */
LIGETRON_API(bn254fr, bn254fr_mulmod)
void bn254fr_mulmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a * b^{-1} mod p */
LIGETRON_API(bn254fr, bn254fr_divmod)
void bn254fr_divmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a^{-1} mod p */
LIGETRON_API(bn254fr, bn254fr_invmod)
void bn254fr_invmod(bn254fr_t out, const bn254fr_t a);

/** a = -a mod p */
LIGETRON_API(bn254fr, bn254fr_negmod)
void bn254fr_negmod(bn254fr_t out, const bn254fr_t a);

/** out = a^b mod p */
LIGETRON_API(bn254fr, bn254fr_powmod)
void bn254fr_powmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a / b (integer division) */
LIGETRON_API(bn254fr, bn254fr_idiv)
void bn254fr_idiv(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a % b (integer remainder) */
LIGETRON_API(bn254fr, bn254fr_irem)
void bn254fr_irem(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/* ---- Scalar Comparisons ---- */
/** Return true if a == b */
LIGETRON_API(bn254fr, bn254fr_eq)
bool bn254fr_eq(const bn254fr_t a, const bn254fr_t b);

/** Return true if a < b */
LIGETRON_API(bn254fr, bn254fr_lt)
bool bn254fr_lt(const bn254fr_t a, const bn254fr_t b);

/** Return true if a <= b */
LIGETRON_API(bn254fr, bn254fr_lte)
bool bn254fr_lte(const bn254fr_t a, const bn254fr_t b);

/** Return true if a > b */
LIGETRON_API(bn254fr, bn254fr_gt)
bool bn254fr_gt(const bn254fr_t a, const bn254fr_t b);

/** Return true if a >= b */
LIGETRON_API(bn254fr, bn254fr_gte)
bool bn254fr_gte(const bn254fr_t a, const bn254fr_t b);

/** Return true if a == 0 */
LIGETRON_API(bn254fr, bn254fr_eqz)
bool bn254fr_eqz(const bn254fr_t a);

/* --------------- Logical Operations --------------- */
/** Return true if both a and b are nonzero. */
LIGETRON_API(bn254fr, bn254fr_land)
bool bn254fr_land(const bn254fr_t a, const bn254fr_t b);

/** Return true if either a or b is nonzero. */
LIGETRON_API(bn254fr, bn254fr_lor)
bool bn254fr_lor(const bn254fr_t a, const bn254fr_t b);

/* --------------- Bitwise Operations --------------- */
/** out = a & b */
LIGETRON_API(bn254fr, bn254fr_band)
void bn254fr_band(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a | b */
LIGETRON_API(bn254fr, bn254fr_bor)
void bn254fr_bor (bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = a ^ b */
LIGETRON_API(bn254fr, bn254fr_bxor)
void bn254fr_bxor(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

/** out = ~a */
LIGETRON_API(bn254fr, bn254fr_bnot)
void bn254fr_bnot(bn254fr_t out, const bn254fr_t a);

/** Decompose a into `count` bits, stored in outs[0..count] as 0 or 1 field values. */
LIGETRON_API(bn254fr, bn254fr_to_bits)
void bn254fr_to_bits(bn254fr_t *outs, const bn254fr_t a, uint32_t count);

/* ---- Shift Operations ---- */
/**
 * out = a >> k (field shift right).
 * For 0 <= k <= p/2:  out = a / (2^k) mod p.
 * For p/2 < k < p:    out = a << (p - k).
 */
LIGETRON_API(bn254fr, bn254fr_shrmod)
void bn254fr_shrmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t k);

/**
 * out = a << k (field shift left).
 * For 0 <= k <= p/2: out = (a * 2^k & (2^b - 1)) mod p, where b = bit length of p.
 * For p/2 < k < p:    out = a >> (p - k).
 */
LIGETRON_API(bn254fr, bn254fr_shlmod)
void bn254fr_shlmod(bn254fr_t out, const bn254fr_t a, const bn254fr_t k);

/* --------------- Helper functions --------------- */

/**
 * Set field element from byte buffer.
 * Read "len" bytes from buffer (up to 32 bytes mod p)).
 * Set bytes in little-endian order.
 */
void bn254fr_set_bytes_little(bn254fr_t out, const unsigned char *bytes, uint32_t len);

/**
 * Set field element from byte buffer.
 * Read "len" bytes from buffer (up to 32 bytes mod p)).
 * Set bytes in big-endian order.
 */
void bn254fr_set_bytes_big(bn254fr_t out, const unsigned char *bytes, uint32_t len);

/**
 * "bn254fr_<operation>_checked" funtions execute corresponding "bn254fr_<operation>" function
 *  and set the appropriate constraint on operands
 * */
void bn254fr_addmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

void bn254fr_submod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

void bn254fr_negmod_checked(bn254fr_t out, const bn254fr_t a);

void bn254fr_mulmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

void bn254fr_mulmod_constant_checked(bn254fr_t out, const bn254fr_t a, const uint64_t k);

void bn254fr_divmod_checked(bn254fr_t out, const bn254fr_t a, const bn254fr_t b);

void bn254fr_divmod_constant_checked(bn254fr_t out, const bn254fr_t a, const uint64_t k);

void bn254fr_invmod_checked(bn254fr_t out, const bn254fr_t a);

/** out = cond ? a1 : a0
 * sets appropriate constraints
 */
void bn254fr_mux(bn254fr_t out, const bn254fr_t cond, const bn254fr_t a0, const bn254fr_t a1);

/**
 * t1 = mux(s0, a0, a1)
 * t2 = mux(s0, a2, a3)
 * out = mux(t1, t2)
 * sets appropriate constraints
 */
void bn254fr_mux2(bn254fr_t out,
                const bn254fr_t s0, const bn254fr_t s1,
                const bn254fr_t a0, const bn254fr_t a1,
                const bn254fr_t a2, const bn254fr_t a3);

/** A rename of bn254fr_mux */
void bn254fr_oblivious_if(bn254fr_t out, const bn254fr_t cond, const bn254fr_t t, const bn254fr_t f);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIGETRON_BN254FR_H_
