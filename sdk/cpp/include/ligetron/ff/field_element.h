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

#ifndef __LIGETRON_FF_FIELD_ELEMENT_H__
#define __LIGETRON_FF_FIELD_ELEMENT_H__

#include <iostream>
#include <concepts>

#include <ligetron/ff/concepts.h>

namespace ligetron::ff {

template <FiniteFieldPolicy Policy>
struct field_element {
    using storage_type = typename Policy::storage_type;

    field_element() requires std::default_initializable<storage_type> = default;

    explicit field_element(storage_type v, bool reduce_modulus = true)
        : data_(std::move(v))
    {
        if (reduce_modulus)
            reduce();
    }

    template <std::integral I>
    requires std::constructible_from<storage_type, I>
    explicit field_element(I i) : data_(i) { }

    explicit field_element(const char * str)
    requires std::constructible_from<storage_type, const char*>
    : data_(str) { }
    
    field_element& operator=(storage_type v) {
        data_ = std::move(v);
        return *this;
    }

    template <std::integral I>
    requires std::assignable_from<storage_type, I>
    field_element& operator=(I i) {
        data_ = i;
        reduce();
        return *this;
    }

    field_element& operator=(const char *str)
    requires std::assignable_from<storage_type, const char*>
    {
        data_ = str;
        reduce();
        return *this;
    }

    storage_type&       data()       { return data_; }
    const storage_type& data() const { return data_; }
    
    void import_limbs(std::span<const uint32_t> limbs)
    requires HasImportU32<Policy>
    {
        Policy::import_u32(data_, limbs);
    }

    size_t export_limbs(std::span<uint32_t> limbs) const
    requires HasExportU32<Policy>
    {
        return Policy::export_u32(data_, limbs);
    }

    void set_zero() { Policy::set_zero(data_); }
    void set_one()  { Policy::set_one(data_);  }

    static const storage_type& modulus() {
        return Policy::modulus();
    }

    static void add(field_element& out,
                    const field_element& x,
                    const field_element& y)
    {
        Policy::add(out.data_, x.data_, y.data_);
    }

    static void sub(field_element& out,
                    const field_element& x,
                    const field_element& y)
    {
        Policy::sub(out.data_, x.data_, y.data_);
    }

    static void mul(field_element& out,
                    const field_element& x,
                    const field_element& y)
    {
        Policy::mul(out.data_, x.data_, y.data_);
    }

    static void div(field_element& out,
                    const field_element& x,
                    const field_element& y)
    {
        Policy::div(out.data_, x.data_, y.data_);
    }

    static void neg(field_element& out,
                    const field_element& x)
    {
        Policy::neg(out.data_, x.data_);
    }

    static void inv(field_element& out,
                    const field_element& x)
    {
        Policy::inv(out.data_, x.data_);
    }

    static void sqr(field_element& out,
                    const field_element& x)
    {
        Policy::sqr(out.data_, x.data_);
    }

    static void powm_ui(field_element& out,
                         const field_element& base,
                         uint32_t exp)
    {
        Policy::powm_ui(out.data_, base.data_, exp);
    }

    static void mux(field_element& out,
                    const typename Policy::boolean_type& cond,
                    const field_element& a,
                    const field_element& b)
    requires HasMux<Policy> {
        Policy::mux(out.data_, cond, a.data_, b.data_);
    }

    static field_element mux(const typename Policy::boolean_type& cond,
                             const field_element& a,
                             const field_element& b)
    requires HasMux<Policy> {
        field_element res;
        mux(res, cond, a, b);
        return res;
    }

    static void eqz(Policy::boolean_type& out, const field_element& a)
    requires HasEqz<Policy> {
        Policy::eqz(out, a.data_);
    }

    static typename Policy::boolean_type eqz(const field_element& a)
    requires HasEqz<Policy> {
        typename Policy::boolean_type res;
        eqz(res, a);
        return res;
    }

    void reduce() {
        Policy::reduce(data_);
    }

    void to_bits(typename Policy::boolean_type *bits) const
    requires HasToBits<Policy> {
        Policy::to_bits(bits, data_);
    }

    void barrett_reduce()
    requires HasBarrettFactor<Policy>
    {
        Policy::barrett_reduce(data_);
    }

    void to_montgomery()
    requires HasMontgomeryFactor<Policy>
    {
        Policy::to_montgomery(data_);
    }

    void from_montgomery()
    requires HasMontgomeryFactor<Policy>
    {
        Policy::from_montgomery(data_);
    }    

    void montgomery_mul(field_element& out,
                        const field_element& x,
                        const field_element& y)
    requires HasMontgomeryFactor<Policy>
    {
        Policy::montgomery_mul(out.data_, x.data_, y.data_);
    }

    void print() const
    requires HasPrint<Policy>
    {
        Policy::print(data_);
    }

private:
    storage_type data_;
};

template <FiniteFieldPolicy P>
std::ostream& operator<<(std::ostream& os, const field_element<P>& f)
    requires requires(std::ostream& os, const typename P::storage_type& s) {
        os << s;
    }
{
    return os << f.data(); 
}

template <typename P>
field_element<P> operator+(const field_element<P>& x, const field_element<P>& y) {
    field_element<P> out;
    field_element<P>::add(out, x, y);
    return out;
}

template <typename P>
field_element<P> operator-(const field_element<P>& x, const field_element<P>& y) {
    field_element<P> out;
    field_element<P>::sub(out, x, y);
    return out;
}

template <typename P>
field_element<P> operator*(const field_element<P>& x, const field_element<P>& y) {
    field_element<P> out;
    field_element<P>::mul(out, x, y);
    return out;
}

template <typename P>
field_element<P> operator/(const field_element<P>& x, const field_element<P>& y) {
    field_element<P> out;
    field_element<P>::div(out, x, y);
    return out;
}

template <typename P>
field_element<P> operator-(const field_element<P>& x) {
    field_element<P> out;
    field_element<P>::neg(out, x);
    return out;
}


}  // namespace ligetron

#endif // __LIGETRON_FF_FIELD_ELEMENT_H__
