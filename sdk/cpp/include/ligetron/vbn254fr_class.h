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
 * vbn254fr_class.h
 *
 * C++ wrapper for bn254fr vector field operations.
 *
 * Refer to "ligetron/vbn254fr.h" for the C API.
 *
 */


#ifndef LIGETRON_VBN254FR_CLASS_H_
#define LIGETRON_VBN254FR_CLASS_H_

#include <ligetron/vbn254fr.h>

namespace ligetron {

struct vbn254fr_class {
    vbn254fr_class();
    vbn254fr_class(int i);
    vbn254fr_class(uint32_t i);
    vbn254fr_class(uint32_t* num, uint64_t len);
    vbn254fr_class(const char *str[], uint64_t len, int base = 0);
    vbn254fr_class(const char *str, int base = 0);
    vbn254fr_class(const unsigned char *bytes, uint64_t num_bytes, uint64_t count);
    vbn254fr_class(const unsigned char *bytes, uint64_t num_bytes);
    vbn254fr_class(const vbn254fr_t o);
    vbn254fr_class(const vbn254fr_class& o);

    vbn254fr_class& operator=(const vbn254fr_t o);
    vbn254fr_class& operator=(const vbn254fr_class& o);

    ~vbn254fr_class();

    __vbn254fr* data() { return data_; }
    const __vbn254fr* data() const { return data_; }

    /* --------------- Setters --------------- */

    void set_ui(uint32_t* num, uint64_t len);

    void set_ui_scalar(uint32_t x);

    void set_str(const char *str[], uint64_t len, int base = 0);

    void set_str_scalar(const char* str, uint32_t base = 0);

    void set_bytes(const unsigned char *bytes, uint64_t num_bytes, uint64_t count);

    void set_bytes_scalar(const unsigned char *bytes, uint64_t num_bytes);

    /* --------------- Zero Knowledge --------------- */

    static void assert_equal(const vbn254fr_class& a, const vbn254fr_class& b);

    /* --------------- Misc --------------- */

    uint64_t static get_size();

    void print_dec() const;

    void print_hex() const;

    void bit_decompose(vbn254fr_class* out_arr) const;

protected:
    vbn254fr_t data_;
};


/* --------------- Vector Arithmetic --------------- */

void addmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b);

void addmod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k);

void submod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b);

void submod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k);

void constant_submod(vbn254fr_class& out, const vbn254fr_constant& k, const vbn254fr_class& a);

void mulmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b);

void mulmod_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k);

void mont_mul_constant(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_constant& k);

void divmod(vbn254fr_class& out, const vbn254fr_class& a, const vbn254fr_class& b);

/* --------------- Misc --------------- */

void mux(vbn254fr_class& out, const vbn254fr_class& cond, const vbn254fr_class& a0, const vbn254fr_class& a1);

void mux2(vbn254fr_class& out,
                const vbn254fr_class& s0, const vbn254fr_class& s1,
                const vbn254fr_class& a0, const vbn254fr_class& a1,
                const vbn254fr_class& a2, const vbn254fr_class& a3);

void oblivious_if(vbn254fr_class& out, bool cond, const vbn254fr_class& t, const vbn254fr_class& f);

} // namespace ligetron

#endif // LIGETRON_VBN254FR_CLASS_H_
