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

#include <ligetron/fp256.h>

// ------------------------------------------------------------

fp256_constant fp256_constant::one   = "1";
fp256_constant fp256_constant::two   = "2";
fp256_constant fp256_constant::three = "3";

fp256_constant::fp256_constant() : data{} { }

fp256_constant::fp256_constant(const char *str, int base) {
    fp256_constant_set_str(this, str, base);
}

fp256_constant& fp256_constant::operator=(const char *str) {
    fp256_constant_set_str(this, str);
    return *this;
}

// ------------------------------------------------------------

fp256_class::fp256_class() {
    fp256_init(data_);
}

fp256_class::fp256_class(int i) {
    fp256_init(data_);
    fp256_set_ui(data_, i);
}

fp256_class::fp256_class(uint32_t i) {
    fp256_init(data_);
    fp256_set_ui(data_, i);
}

fp256_class::fp256_class(const char *str, int base) {
    fp256_init(data_);
    fp256_set_str(data_, str, base);
}

fp256_class::fp256_class(const fp256_t o) {
    fp256_init(data_);
    fp256_copy(data_, o);
}

fp256_class::fp256_class(const fp256_class& o) {
    fp256_init(data_);
    fp256_copy(data_, o.data_);
}

fp256_class& fp256_class::operator=(const fp256_t o) {
    fp256_copy(data_, o);
    return *this;
}

fp256_class& fp256_class::operator=(const fp256_class& o) {
    fp256_copy(data_, o.data_);
    return *this;
}
    
fp256_class::~fp256_class() { fp256_clear(data_); }


// ------------------------------------------------------------

void fp256_mux2(fp256_t out,
                const fp256_t s0, const fp256_t s1,
                const fp256_t a0, const fp256_t a1,
                const fp256_t a2, const fp256_t a3)
{
    fp256_t tmp1, tmp2;
    fp256_init(tmp1);
    fp256_init(tmp2);

    fp256_mux(tmp1, s0, a0, a1);
    fp256_mux(tmp2, s0, a2, a3);
    fp256_mux(out, s1, tmp1, tmp2);

    fp256_clear(tmp1);
    fp256_clear(tmp2);
}

void fp256_oblivious_if(fp256_t out, const fp256_t cond, const fp256_t t, const fp256_t f) {
    fp256_mux(out, cond, f, t);
}

// ------------------------------------------------------------

fp256vec_class::fp256vec_class() {
    fp256vec_init(data_);
}

fp256vec_class::fp256vec_class(int i) {
    fp256vec_init(data_);
    fp256vec_set_ui(data_, i);
}

fp256vec_class::fp256vec_class(uint32_t i) {
    fp256vec_init(data_);
    fp256vec_set_ui(data_, i);
}

fp256vec_class::fp256vec_class(const char *str, int base) {
    fp256vec_init(data_);
    fp256vec_set_str(data_, str, base);
}

fp256vec_class::fp256vec_class(const fp256vec_t o) {
    fp256vec_init(data_);
    fp256vec_copy(data_, o);
}

fp256vec_class::fp256vec_class(const fp256vec_class& o) {
    fp256vec_init(data_);
    fp256vec_copy(data_, o.data_);
}

fp256vec_class& fp256vec_class::operator=(const fp256vec_t o) {
    fp256vec_copy(data_, o);
    return *this;
}

fp256vec_class& fp256vec_class::operator=(const fp256vec_class& o) {
    fp256vec_copy(data_, o.data_);
    return *this;
}
    
fp256vec_class::~fp256vec_class() { fp256vec_clear(data_); }


// ------------------------------------------------------------

void fp256vec_mux(fp256vec_t out,
                  const fp256vec_t s0,
                  const fp256vec_t a0,
                  const fp256vec_t a1)
{
    // out = s0 * a1 + a0 - s0 * a0
    fp256vec_t tmp;
    fp256vec_init(tmp);

    fp256vec_mulmod(tmp, s0, a0);
    fp256vec_submod(tmp, a0, tmp);
    fp256vec_mulmod(out, s0, a1);
    fp256vec_addmod(out, out, tmp);

    fp256vec_clear(tmp);
}


void fp256vec_mux2(fp256vec_t out,
                   const fp256vec_t s0, const fp256vec_t s1,
                   const fp256vec_t a0, const fp256vec_t a1,
                   const fp256vec_t a2, const fp256vec_t a3)
{
    fp256vec_t tmp1, tmp2;
    fp256vec_init(tmp1);
    fp256vec_init(tmp2);

    fp256vec_mux(tmp1, s0, a0, a1);
    fp256vec_mux(tmp2, s0, a2, a3);
    fp256vec_mux(out, s1, tmp1, tmp2);

    fp256vec_clear(tmp1);
    fp256vec_clear(tmp2);
}

void fp256vec_oblivious_if(fp256vec_t out,
                           const fp256vec_t cond, const fp256vec_t t, const fp256vec_t f)
{
    fp256vec_mux(out, cond, f, t);
}

void fp256vec_bit_xor(fp256vec_t out, const fp256vec_t x, const fp256vec_t y) {
    fp256vec_class tmp;

    fp256vec_mulmod(tmp.data(), x, y);
    fp256vec_mulmod_constant(tmp.data(), tmp.data(), fp256_constant::two);
    fp256vec_submod(tmp.data(), y, tmp.data());
    fp256vec_addmod(out, x, tmp.data());
}

void fp256vec_neq(fp256vec_t out, const fp256vec_t x, const fp256vec_t y) {
    fp256vec_bit_xor(out, x, y);
    fp256vec_constant_submod(out, fp256_constant::one, out);
}

void fp256vec_ge(fp256vec_t out, const fp256vec_t x, const fp256vec_t y, size_t Bit) {

    const size_t MSB = Bit - 1;
    
    fp256vec_t x_bits[Bit], y_bits[Bit];

    for (int i = 0; i < Bit; i++) {
        fp256vec_init(x_bits[i]);
        fp256vec_init(y_bits[i]);
    }

    fp256vec_bit_decompose(x_bits, x);
    fp256vec_bit_decompose(y_bits, y);

    fp256vec_class acc, iacc;
    fp256vec_constant_submod(acc.data(), fp256_constant::one, y_bits[MSB]);
    fp256vec_mulmod(acc.data(), x_bits[MSB], acc.data());

    fp256vec_neq(iacc.data(), x_bits[MSB], y_bits[MSB]);

    fp256vec_class tmp;
    for (int i = MSB - 1; i >= 0; --i) {
        // update acc
        fp256vec_constant_submod(tmp.data(), fp256_constant::one, y_bits[i]);
        fp256vec_mulmod(tmp.data(), tmp.data(), x_bits[i]);
        fp256vec_mulmod(tmp.data(), tmp.data(), iacc.data());
        fp256vec_addmod(acc.data(), acc.data(), tmp.data());

        // update iacc
        fp256vec_neq(tmp.data(), x_bits[i], y_bits[i]);
        fp256vec_mulmod(iacc.data(), iacc.data(), tmp.data());
    }

    fp256vec_addmod(out, acc.data(), iacc.data());

    for (int i = 0; i < Bit; i++) {
        fp256vec_clear(x_bits[i]);
        fp256vec_clear(y_bits[i]);
    }
}

