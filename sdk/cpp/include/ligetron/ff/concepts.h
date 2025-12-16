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

#ifndef __LIGETRON_FF_CONCEPTS_H__
#define __LIGETRON_FF_CONCEPTS_H__

#include <cstdint>
#include <span>
#include <concepts>

namespace ligetron::ff {

template <typename P>
concept FiniteFieldPolicy =
requires(typename P::storage_type& r,
         const typename P::storage_type& a,
         const typename P::storage_type& b,
         uint32_t k)
{
    typename P::storage_type;

    { P::modulus() } -> std::convertible_to<const typename P::storage_type&>;

    { P::set_zero(r) };
    { P::set_one(r)  };

    // Add: r = a + b (mod p)
    { P::add(r, a, b) };

    // Sub: r = a - b (mod p)
    { P::sub(r, a, b) };

    // Mul: r = a * b (mod p)
    { P::mul(r, a, b) };

    // Div: r = a * b^-1 (mod p)
    { P::div(r, a, b) };

    // Neg: r = -a (mod p)
    { P::neg(r, a) };

    // Inv: r = a^-1 (mod p)
    { P::inv(r, a) };

    // Square: r = a^2 (mod p)
    { P::sqr(r, a) };

    // Pow: r = a ^ b (mod p)
    { P::powm_ui(r, a, k) };

    // Montgomery / canonical normalization, etc.
    { P::reduce(r) };
};

template<typename P>
concept HasImportU32 = requires(typename P::storage_type& x,
                                std::span<const uint32_t> limbs) {
    { P::import_u32(x, limbs) } -> std::convertible_to<size_t>;
};

template<typename P>
concept HasExportU32 = requires(const typename P::storage_type& x,
                                std::span<uint32_t> limbs) {
    { P::export_u32(x, limbs) } -> std::convertible_to<size_t>;
};

template <typename F>
concept HasBarrettFactor = requires {
    { F::barrett_factor() } -> std::convertible_to<const typename F::storage_type&>;
};

template <typename F>
concept HasMontgomeryFactor = requires {
    { F::montgomery_factor() } -> std::convertible_to<const typename F::storage_type&>;
};

template <typename F>
concept HasBarrettReduction =
    requires(typename F::storage_type& r,
             const typename F::storage_type& a)
{
    { F::barrett_reduce(r, a) };
};
 

template <typename F>
concept HasMontgomeryReduction =
    requires(typename F::storage_type& r,
             const typename F::storage_type& a)
{
    { F::mont_reduce(r, a) };
};

template <typename F>
concept IsNTTFriendly = requires {
    { F::num_bits  } -> std::convertible_to<size_t>;
    { F::num_bytes } -> std::convertible_to<size_t>;
    { F::modulus_2x() } -> std::convertible_to<const typename F::storage_type&>;
};

template <typename F>
concept HasPrint = requires(const typename F::storage_type& x) {
    F::print(x);
};

template <typename F>
concept HasBoolean = requires {
    typename F::boolean_type;
};

template <typename F>
concept HasMux = HasBoolean<F> &&
                 requires(typename F::storage_type& out,
                          const typename F::boolean_type& c,
                          const typename F::storage_type& a,
                          const typename F::storage_type& b) {
    F::mux(out, c, a, b);
};

template <typename F>
concept HasEqz = HasBoolean<F> &&
                 requires(typename F::boolean_type& out,
                          const typename F::storage_type& a) {
    F::eqz(out, a);
};

template <typename F>
concept HasToBits = HasBoolean<F> &&
                    requires(typename F::boolean_type* bits,
                             const typename F::storage_type& a) {
    { F::num_rounded_bits } -> std::convertible_to<size_t>;
    F::to_bits(bits, a);
};

}  // namespace ligetron

#endif // __LIGETRON_FF_CONCEPTS_H__
