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
 * vbn254fr.h
 *
 * SIMD-style intrinsics for scalar and vector operations over the BN254 scalar field.
 * Supports scalar, vector, and immediate (compile-time constant) operands.
 * Inspired by RVV and AVX, adapted for finite field arithmetic.
 *
 * Types:
 *   - vbn254fr_t:   vector of scalar field elements (dynamic-length, opaque)
 */

#ifndef LIGETRON_VBN254FR_H_
#define LIGETRON_VBN254FR_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <ligetron/apidef.h>


#ifdef __cplusplus
extern "C" {
#endif

/* --------------- Type Definitions --------------- */

struct __vbn254fr {
    uint32_t __vhandle;
};

typedef __vbn254fr vbn254fr_t[1];

struct vbn254fr_constant {
    uint32_t data[8];
};

/* --------------- Memory Management --------------- */

LIGETRON_API(vbn254fr, vbn254fr_get_size)
uint64_t vbn254fr_get_size();

LIGETRON_API(vbn254fr, vbn254fr_alloc)
void vbn254fr_alloc(vbn254fr_t v);

LIGETRON_API(vbn254fr, vbn254fr_free)
void vbn254fr_free(vbn254fr_t v);

/* --------------- Vector Initialization --------------- */

LIGETRON_API(vbn254fr, vbn254fr_constant_set_str)
int vbn254fr_constant_set_str(const vbn254fr_constant *k, const char *str, int base = 0);

LIGETRON_API(vbn254fr, vbn254fr_set_ui)
void vbn254fr_set_ui(vbn254fr_t v, uint32_t* num, uint64_t len);

LIGETRON_API(vbn254fr, vbn254fr_set_ui_scalar)
void vbn254fr_set_ui_scalar(vbn254fr_t v, uint32_t num);

LIGETRON_API(vbn254fr, vbn254fr_set_str)
int  vbn254fr_set_str(vbn254fr_t v, const char *str[], uint64_t len, int base = 0);

LIGETRON_API(vbn254fr, vbn254fr_set_str_scalar)
int  vbn254fr_set_str_scalar(vbn254fr_t v, const char *str, int base = 0);

LIGETRON_API(vbn254fr, vbn254fr_set_bytes)
void vbn254fr_set_bytes(vbn254fr_t v, const unsigned char *bytes, uint64_t num_bytes, uint64_t count);

LIGETRON_API(vbn254fr, vbn254fr_set_bytes_scalar)
void vbn254fr_set_bytes_scalar(vbn254fr_t v, const unsigned char *bytes, uint64_t num_bytes);

/* --------------- Vector Arithmetic --------------- */

LIGETRON_API(vbn254fr, vbn254fr_addmod)
void vbn254fr_addmod(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

LIGETRON_API(vbn254fr, vbn254fr_addmod_constant)
void vbn254fr_addmod_constant(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_constant k);

LIGETRON_API(vbn254fr, vbn254fr_submod)
void vbn254fr_submod(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

LIGETRON_API(vbn254fr, vbn254fr_submod_constant)
void vbn254fr_submod_constant(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_constant k);

LIGETRON_API(vbn254fr, vbn254fr_constant_submod)
void vbn254fr_constant_submod(vbn254fr_t out, const vbn254fr_constant k, const vbn254fr_t x);

LIGETRON_API(vbn254fr, vbn254fr_mulmod)
void vbn254fr_mulmod(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

LIGETRON_API(vbn254fr, vbn254fr_mulmod_constant)
void vbn254fr_mulmod_constant(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_constant k);

LIGETRON_API(vbn254fr, vbn254fr_mont_mul_constant)
void vbn254fr_mont_mul_constant(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_constant k);

LIGETRON_API(vbn254fr, vbn254fr_divmod)
void vbn254fr_divmod(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

/* --------------- Misc --------------- */

LIGETRON_API(vbn254fr, vbn254fr_copy)
void vbn254fr_copy(vbn254fr_t out, const vbn254fr_t in);

LIGETRON_API(vbn254fr, vbn254fr_print)
void vbn254fr_print(const vbn254fr_t v, uint32_t base);

LIGETRON_API(vbn254fr, vbn254fr_bit_decompose)
void vbn254fr_bit_decompose(vbn254fr_t arr[], const vbn254fr_t x);

LIGETRON_API(vbn254fr, vbn254fr_assert_equal)
void vbn254fr_assert_equal(const vbn254fr_t x, const vbn254fr_t y);

/* --------------- Helper functions --------------- */

vbn254fr_constant vbn254fr_constant_from_str(const char *str, int base = 0);

void vbn254fr_bxor(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

void vbn254fr_neq(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y);

void vbn254fr_gte(vbn254fr_t out, const vbn254fr_t x, const vbn254fr_t y, size_t Bit);

void vbn254fr_mux(vbn254fr_t out, const vbn254fr_t s0,
                   const vbn254fr_t a0, const vbn254fr_t a1);

void vbn254fr_mux2(vbn254fr_t out,
                   const vbn254fr_t s0, const vbn254fr_t s1,
                   const vbn254fr_t a0, const vbn254fr_t a1,
                   const vbn254fr_t a2, const vbn254fr_t a3);

void vbn254fr_oblivious_if(vbn254fr_t out,
                           const vbn254fr_t cond, const vbn254fr_t t, const vbn254fr_t f);

#ifdef __cplusplus
} // extern "C"
#endif


#endif // LIGETRON_VBN254FR_H_
