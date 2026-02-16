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

#pragma once

#include <util/timer.hpp>
#include <params.hpp>
#include <algorithm>
#include <iomanip>

#include <gmpxx.h>

template <typename T>
mpz_class mpz_promote(const T& num) {
    if constexpr (std::is_constructible_v<mpz_class, T>) {
        return num;
    }
    else {
        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), 1, -1, sizeof(T), 0, 0, &num);
        return tmp;
    }
}

namespace ligero::vm::zkp {

template <typename Number>
constexpr Number modulo(const Number& x, const Number& m) {
    // auto t = make_timer(__func__);
    return (x >= m) ? (x % m) : x;
}

template <typename Number>
constexpr Number modulo_neg(const Number& x, const Number& m) {
    // auto t = make_timer(__func__);
    return (x < 0) ? ((x < -m) ? (x % m + m) : (x + m)) : modulo(x, m);
}

void show_hash(const typename params::hasher::digest& d) {
    std::cout << std::hex;
    for (size_t i = 0; i < params::hasher::digest_size; i++)
        std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(d.data[i]);
    std::cout << std::endl << std::dec << std::setfill(' ');
}

bool validate(const mpz_vector& p) {
    bool eq = true;
    for (size_t i = 0; i < p.size(); i++) {
        // std::cout << p[i] << " ";
        eq &= p[i] == 0u;
    }
    return eq;
}

template <typename Field>
bool validate_sum(const mpz_vector& p, const mpz_class& sum) {
    mpz_class acc = 0;
    for (size_t i = 0; i < p.size(); i++) {
        // std::cout << p[i] << " ";
        Field::addmod(acc, acc, p[i]);
    }
    // std::cout << "acc: " << acc << ", running sum: " << sum;
    Field::addmod(acc, acc, sum);
    // std::cout << ", actual: " << acc << std::endl;
    return acc == 0U;
}

}
