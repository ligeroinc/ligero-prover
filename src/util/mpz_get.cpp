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

#include <cstddef>

#include <util/mpz_get.hpp>

namespace ligero
{
uint64_t mpz_get_u64(const mpz_class& val)
{
  uint64_t result = 0;
  std::size_t count;
  mpz_export(&result, &count, -1, sizeof(uint64_t), 0, 0, val.get_mpz_t());
  return result;
}

uint64_t mpz_get_u64(const mpz_t val)
{
  uint64_t result = 0;
  std::size_t count;
  mpz_export(&result, &count, -1, sizeof(uint64_t), 0, 0, val);
  return result;
}

uint32_t mpz_get_u32(const mpz_class& val)
{
  return static_cast<uint32_t>(mpz_get_ui(val.get_mpz_t()));
}
}
