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

#pragma once

#include <cstdint>
#include <concepts>
#include <type_traits>
#include <gmpxx.h>

namespace ligero {

template <typename T>
inline typename std::enable_if_t<std::is_integral_v<T>>
mpz_assign(mpz_class& out, T value) {
    if constexpr (std::signed_integral<T>) {
        if constexpr (sizeof(T) <= sizeof(long)) {
            out = static_cast<long>(value);
        } else {
            int64_t tmp = value;
            mpz_import(out.get_mpz_t(), 1, -1, sizeof(tmp), 0, 0, &tmp);
            if (tmp < 0)
                mpz_neg(out.get_mpz_t(), out.get_mpz_t());
        }
    } else {
        if constexpr (sizeof(T) <= sizeof(unsigned long)) {
            out = static_cast<unsigned long>(value);
        } else {
            uint64_t tmp = value;
            mpz_import(out.get_mpz_t(), 1, -1, sizeof(tmp), 0, 0, &tmp);
        }
    }
}

// `mpz_class`
inline void mpz_assign(mpz_class& out, const mpz_class& value) {
    out = value;
}

}  // namespace ligero
