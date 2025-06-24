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

#include <tuple>
#include <zkp/hash.hpp>

namespace ligero::vm::params {

constexpr size_t num_code_test      = 1;
constexpr size_t num_linear_test    = 1;
constexpr size_t num_quadratic_test = 1;
constexpr size_t sample_size        = 192;
constexpr size_t hash_cache_size    = 8;  // 16 * 64bit

constexpr size_t default_row_size      = 8192;
constexpr size_t default_packing_size  = default_row_size - sample_size;
constexpr size_t default_encoding_size = default_row_size * 4;

using hasher = zkp::sha256;

// Since we are using AES counter mode, the value of IV is not important
constexpr unsigned char iv[16]     = { 0 };
constexpr unsigned char ivc[16]    = { 1 };
constexpr unsigned char ivl[16]    = { 2 };
constexpr unsigned char ivq[16]    = { 3 };
constexpr unsigned char RAM_iv[16] = { 82, 65, 77 };  // "RAM"
constexpr unsigned char any_iv[16] = { 0 };

}  // namespace ligero::vm::params

