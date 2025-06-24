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

#ifndef __LIGETRON_FP256__
#define __LIGETRON_FP256__

#include <stdint.h>
#include <stddef.h>
#include <ligetron/apidef.h>

// 256bit Field Operations
// ------------------------------------------------------------

struct  __fp256_backend { void *_handle; };
typedef __fp256_backend fp256_t[1];

struct fp256_class {
    fp256_class();
    fp256_class(int i);
    fp256_class(uint32_t i);
    fp256_class(const char *str, int base = 0);
    fp256_class(const fp256_t o);
    fp256_class(const fp256_class& o);

    fp256_class& operator=(const fp256_t o);
    fp256_class& operator=(const fp256_class& o);
    ~fp256_class();

    __fp256_backend* data() { return data_; }
    const __fp256_backend* data() const { return data_; }

protected:
    fp256_t data_;
};


// Constant
// ------------------------------------------------------------

struct fp256_constant {
    static fp256_constant one;
    static fp256_constant two;
    static fp256_constant three;

    fp256_constant();
    fp256_constant(const char *str, int base = 0);
    
    fp256_constant& operator=(const char *str);

protected:
    uint32_t data[8];
};

LIGETRON_API(ligetron-batch, fp256_constant_set_str)
int fp256_constant_set_str(fp256_constant *k, const char *str, int base = 0);

// Initialization
// ------------------------------------------------------------

LIGETRON_API(ligetron, fp256_init)
void fp256_init(fp256_t n);

LIGETRON_API(ligetron, fp256_clear)
void fp256_clear(fp256_t n);

LIGETRON_API(ligetron, fp256_set_ui)
void fp256_set_ui(fp256_t n, uint32_t num);

// Import from hex string. MSB first.
LIGETRON_API(ligetron, fp256_set_bytes)
void fp256_set_bytes(fp256_t n, const unsigned char *data, uint64_t len);

LIGETRON_API(ligetron, fp256_set_str)
int  fp256_set_str(fp256_t n, const char *str, int base = 0);

LIGETRON_API(ligetron, fp256_copy)
void fp256_copy(fp256_t out, const fp256_t in);

LIGETRON_API(ligetron, fp256_print)
void fp256_print(const fp256_t n);


// Arithmetic
// ------------------------------------------------------------
LIGETRON_API(ligetron, fp256_addmod)
void fp256_addmod(fp256_t out, const fp256_t x, const fp256_t y);

LIGETRON_API(ligetron, fp256_submod)
void fp256_submod(fp256_t out, const fp256_t x, const fp256_t y);

LIGETRON_API(ligetron, fp256_mulmod)
void fp256_mulmod(fp256_t out, const fp256_t x, const fp256_t y);

LIGETRON_API(ligetron, fp256_divmod)
void fp256_divmod(fp256_t out, const fp256_t x, const fp256_t y);

LIGETRON_API(ligetron, fp256_invmod)
void fp256_invmod(fp256_t out, const fp256_t x);

LIGETRON_API(ligetron, fp256_assert_equal)
void fp256_assert_equal(const fp256_t x, const fp256_t y);

LIGETRON_API(ligetron, fp256_bit_decompose)
void fp256_bit_decompose(fp256_t arr[], const fp256_t x);

LIGETRON_API(ligetron, fp256_mux)
void fp256_mux(fp256_t out, const fp256_t cond, const fp256_t a0, const fp256_t a1);

/*
LIGETRON_API(ligetron, fp256_addmod_ui)
void fp256_addmod(fp256_t out, const fp256_t x, uint64_t c);

LIGETRON_API(ligetron, fp256_mulmod_ui)
void fp256_mulmod(fp256_t out, const fp256_t x, uint64_t c);
*/

// Helper Functions
// ------------------------------------------------------------
extern "C" void fp256_mux2(fp256_t out,
                const fp256_t s0, const fp256_t s1,
                const fp256_t a0, const fp256_t a1,
                const fp256_t a2, const fp256_t a3);
extern "C" void fp256_oblivious_if(fp256_t out, const fp256_t cond, const fp256_t t, const fp256_t f);


// 256bit Field Operations (Vector)
// ------------------------------------------------------------

struct  __fp256vec_backend { void *_handle; };
typedef __fp256vec_backend fp256vec_t[1];

struct fp256vec_class {    
    fp256vec_class();
    fp256vec_class(int i);
    fp256vec_class(uint32_t i);
    fp256vec_class(const char *str, int base = 0);
    fp256vec_class(const fp256vec_t o);
    fp256vec_class(const fp256vec_class& o);

    fp256vec_class& operator=(const fp256vec_t o);
    fp256vec_class& operator=(const fp256vec_class& o);
    
    ~fp256vec_class();

    __fp256vec_backend* data() { return data_; }
    const __fp256vec_backend* data() const { return data_; }

protected:
    fp256vec_t data_;
};

// Vector Initialization
// ------------------------------------------------------------
LIGETRON_API(ligetron-batch, fp256vec_get_size)
uint64_t fp256vec_get_size();

LIGETRON_API(ligetron-batch, fp256vec_init)
void fp256vec_init(fp256vec_t v);

LIGETRON_API(ligetron-batch, fp256vec_clear)
void fp256vec_clear(fp256vec_t v);

LIGETRON_API(ligetron-batch, fp256vec_set_ui)
void fp256vec_set_ui(fp256vec_t v, uint32_t* num, uint64_t len);

LIGETRON_API(ligetron-batch, fp256vec_set_ui_scalar)
void fp256vec_set_ui(fp256vec_t v, uint32_t num);

LIGETRON_API(ligetron-batch, fp256vec_set_str)
int  fp256vec_set_str(fp256vec_t v, const char *str[], uint64_t len, int base = 0);

LIGETRON_API(ligetron-batch, fp256vec_set_str_scalar)
int  fp256vec_set_str(fp256vec_t v, const char *str, int base = 0);

LIGETRON_API(ligetron-batch, fp256vec_set_bytes)
void fp256vec_set_bytes(fp256vec_t v, const unsigned char *bytes, uint64_t num_bytes, uint64_t count);

LIGETRON_API(ligetron-batch, fp256vec_set_bytes_scalar)
void fp256vec_set_bytes(fp256vec_t v, const unsigned char *bytes, uint64_t num_bytes);

LIGETRON_API(ligetron-batch, fp256vec_copy)
void fp256vec_copy(fp256vec_t out, const fp256vec_t in);

LIGETRON_API(ligetron-batch, fp256vec_print)
void fp256vec_print(const fp256vec_t v);


// Vector Arithmetic
// ------------------------------------------------------------

LIGETRON_API(ligetron-batch, fp256vec_addmod)
void fp256vec_addmod(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

LIGETRON_API(ligetron-batch, fp256vec_addmod_constant)
void fp256vec_addmod_constant(fp256vec_t out, const fp256vec_t x, const fp256_constant k);

LIGETRON_API(ligetron-batch, fp256vec_submod)
void fp256vec_submod(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

LIGETRON_API(ligetron-batch, fp256vec_submod_constant)
void fp256vec_submod_constant(fp256vec_t out, const fp256vec_t x, const fp256_constant k);

LIGETRON_API(ligetron-batch, fp256vec_constant_submod)
void fp256vec_constant_submod(fp256vec_t out, const fp256_constant k, const fp256vec_t x);

LIGETRON_API(ligetron-batch, fp256vec_mulmod)
void fp256vec_mulmod(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

LIGETRON_API(ligetron-batch, fp256vec_mulmod_constant)
void fp256vec_mulmod_constant(fp256vec_t out, const fp256vec_t x, const fp256_constant k);

LIGETRON_API(ligetron-batch, fp256vec_mont_mul_constant)
void fp256vec_mont_mul_constant(fp256vec_t out, const fp256vec_t x, const fp256_constant k);

LIGETRON_API(ligetron-batch, fp256vec_divmod)
void fp256vec_divmod(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

LIGETRON_API(ligetron-batch, fp256vec_assert_equal)
void fp256vec_assert_equal(const fp256vec_t x, const fp256vec_t y);

LIGETRON_API(ligetron-batch, fp256vec_assert_equal_constant)
void fp256vec_assert_equal(const fp256vec_t x, const fp256_constant& y);

LIGETRON_API(ligetron-batch, fp256vec_bit_decompose)
void fp256vec_bit_decompose(fp256vec_t arr[], const fp256vec_t x);


// Helper Functions
// ------------------------------------------------------------

extern "C" void fp256vec_mux(fp256vec_t out,
                  const fp256vec_t s0,
                  const fp256vec_t a0,
                  const fp256vec_t a1);

extern "C" void fp256vec_mux2(fp256vec_t out,
                   const fp256vec_t s0, const fp256vec_t s1,
                   const fp256vec_t a0, const fp256vec_t a1,
                   const fp256vec_t a2, const fp256vec_t a3);

extern "C" void fp256vec_oblivious_if(fp256vec_t out,
                           const fp256vec_t cond, const fp256vec_t t, const fp256vec_t f);

extern "C" void fp256vec_bit_xor(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

extern "C" void fp256vec_neq(fp256vec_t out, const fp256vec_t x, const fp256vec_t y);

extern "C" void fp256vec_ge(fp256vec_t out, const fp256vec_t x, const fp256vec_t y, size_t Bit);

#endif
