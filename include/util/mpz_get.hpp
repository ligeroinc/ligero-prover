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

#include <cstdint>
#include <gmpxx.h>

/// @file mpz_get.hpp
/// @brief Platform-safe extraction of fixed-width integers from GMP values

namespace ligero
{
inline uint64_t mpz_get_u64_low(mpz_srcptr val)
{
  // mpz_export writes every significant word and cannot truncate into a single
  // uint64_t. Read only the limbs intersecting the low 64 bits instead. GMP's
  // limb accessor, like mpz_export, reads the magnitude of negative values.
  uint64_t result = static_cast<uint64_t>(mpz_getlimbn(val, 0));
  if constexpr (GMP_NUMB_BITS < 64) {
    for (unsigned bit = GMP_NUMB_BITS, limb = 1; bit < 64; bit += GMP_NUMB_BITS, ++limb)
      result |= static_cast<uint64_t>(mpz_getlimbn(val, limb)) << bit;
  }
  return result;
}

/// Safely extract a uint64_t from an mpz_class
///
/// Unlike mpz_get_ui() which returns unsigned long (platform-dependent size),
/// this function always returns a full 64-bit value regardless of platform.
///
/// @param val The GMP integer to convert
/// @return uint64_t The value as a 64-bit unsigned integer (lower 64 bits if larger)
inline uint64_t mpz_get_u64(const mpz_class& val)
{
  return mpz_get_u64_low(val.get_mpz_t());
}

/// Safely extract a uint64_t from an mpz_t
///
/// This is the C API variant for use with raw mpz_t types.
///
/// @param val The GMP integer to convert
/// @return uint64_t The value as a 64-bit unsigned integer (lower 64 bits if larger)
inline uint64_t mpz_get_u64(const mpz_t val)
{
  return mpz_get_u64_low(val);
}

/// Extract a uint32_t from an mpz_class
///
/// This is just a wrapper around mpz_get_ui() for clarity.
/// Safe on all platforms since we're explicitly requesting 32 bits.
///
/// @param val The GMP integer to convert
/// @return The value as a 32-bit unsigned integer (lower 32 bits if larger)
inline uint32_t mpz_get_u32(const mpz_class& val)
{
  return static_cast<uint32_t>(mpz_get_ui(val.get_mpz_t()));
}
}
