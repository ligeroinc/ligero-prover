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

#include <cassert>
#include <cstdint>
#include <iterator>
#include <memory>
#include <vector>

#include <gmp.h>
#include <gmpxx.h>

#include <boost/serialization/serialization.hpp>
#include <boost/serialization/split_free.hpp>
#include <boost/serialization/split_member.hpp>

namespace ligero::vm::zkp {

struct bn254_gmp {
    using value_type = mpz_class;

    constexpr static size_t num_bits          = 254;
    constexpr static size_t num_rounded_bits  = 256;
    constexpr static size_t num_bytes         = num_rounded_bits / 8;
    constexpr static size_t num_u32_limbs     = 8;
    constexpr static size_t num_u64_limbs     = 4;
    constexpr static size_t num_native_limbs  = num_bytes / sizeof(void*);

    static value_type modulus;
    static value_type modulus_2x;
    static value_type modulus_4x;
    static value_type modulus_middle;
    static value_type root1;
    static value_type root2;
    static value_type montgomery_factor;
    static value_type barrett_factor;
    static size_t     root1_pow2_degree;
    static size_t     root2_pow2_degree;

    static std::tuple<value_type, value_type, value_type>
    generate_omegas(size_t k, size_t n);

    static void reduce(value_type& out, const value_type& x);
    static void reduce_u256(value_type& out, const value_type& x);
    static void negate(value_type& out, const value_type& x);
    static void invmod(value_type& out, const value_type& x);
    static void addmod(value_type& out, const value_type& a, const value_type& b);
    static void submod(value_type& out, const value_type& a, const value_type& b);
    static void mulmod(value_type& out, const value_type& a, const value_type& b);
    static void mont_mulmod(value_type& out, const value_type& a, const value_type& b);
    static void divmod(value_type& out, const value_type& a, const value_type& b);
    static void powmod(value_type& out, const value_type& x, const value_type& exp);
    static void powmod_ui(value_type& out, const value_type& x, uint32_t exp);

    template <typename RandomEngine>
    requires requires(RandomEngine& e,value_type& out,  size_t n) {
        { e(out, n) };
    }
    static void generate_random(value_type& out, RandomEngine& eng) {
        eng(out, num_bytes);

        out >>= 2;
        if (out >= modulus) {
            out -= modulus;
        }
        assert(out >= 0 && out < modulus);
    }
    
    bn254_gmp() : data_(0) { }
    bn254_gmp(int num) : data_(num) {
        if (num < 0) {
            data_ += modulus;
        }
    }
    bn254_gmp(uint32_t num) : data_(num) { }
    bn254_gmp(uint64_t num) : data_(0) {
        mpz_import(data_.get_mpz_t(), 1, -1, sizeof(num), 0, 0, &num);
    }
    bn254_gmp(const mpz_class& num) : data_(num) {
        normalize();
    }
    template <typename... Args>
    bn254_gmp(const __gmp_expr<Args...>& expr) : data_(expr) { normalize(); }

    bn254_gmp& operator=(int num) {
        data_ = num;
        if (data_ < 0) {
            data_ += modulus;
        }
        return *this;
    }
    
    bn254_gmp& operator=(uint32_t num) {
        data_ = num;
        return *this;
    }
    
    bn254_gmp& operator=(uint64_t num)  {
        mpz_import(data_.get_mpz_t(), 1, -1, sizeof(num), 0, 0, &num);
        return *this;
    }
    
    bn254_gmp& operator=(const mpz_class& num) {
        data_ = num;
        normalize();
        return *this;
    }

    template <typename... Args>
    bn254_gmp& operator=(const __gmp_expr<Args...>& expr) {
        data_ = expr;
        return *this;
    }

    void swap(mpz_class& other) {
        data_.swap(other);
        normalize();
    }

    void swap(bn254_gmp& other) {
        data_.swap(other.data_);
        normalize();
    }
    
    bool operator==(const bn254_gmp& other) const {
        return data_ == other.data_;
    }

    auto& data() { return data_; }
    const auto& data() const { return data_; }

    void reset() { data_ = 0; }

    explicit operator unsigned long() const {
        return mpz_get_ui(data_.get_mpz_t());
    }

    bn254_gmp& operator+=(const bn254_gmp& other) {
        addmod(data_, data_, other.data_);
        return *this;
    }

    bn254_gmp& operator-=(const bn254_gmp& other) {
        submod(data_, data_, other.data_);
        return *this;
    }

    bn254_gmp& operator*=(const bn254_gmp& other) {
        mulmod(data_, data_, other.data_);
        return *this;
    }

    bn254_gmp& operator/=(const bn254_gmp& other) {
        divmod(data_, data_, other.data_);
        return *this;
    }

    bn254_gmp operator-() const {
        bn254_gmp r{};
        r.data_ = modulus - data_;
        return r;
    }

    bn254_gmp& normalize() {
        reduce(data_, data_);
        return *this;
    }
    
    bn254_gmp inv() const {
        bn254_gmp ret;
        invmod(ret.data(), data_);
        return ret;
    }

    void from_limbs(const uint32_t *buf) {
        mpz_import(data_.get_mpz_t(), num_u32_limbs, -1, sizeof(uint32_t), 0, 0, buf);
    }

    void from_limbs(const uint64_t *buf) {
        mpz_import(data_.get_mpz_t(), num_u64_limbs, -1, sizeof(uint64_t), 0, 0, buf);
    }

    void to_limbs(uint32_t *buf) const {
        mpz_export(buf, nullptr, -1, sizeof(uint32_t), 0, 0, data_.get_mpz_t());
    }

    void to_limbs(uint64_t *buf) const {
        mpz_export(buf, nullptr, -1, sizeof(uint64_t), 0, 0, data_.get_mpz_t());
    }

    template <typename Archive>
    void save(Archive& ar, const unsigned int) const {
        uint64_t buf[num_u64_limbs]{};

        to_limbs(buf);
        
        ar & buf;
    }

    template <typename Archive>
    void load(Archive& ar, const unsigned int) {
        uint64_t buf[num_u64_limbs]{};

        ar & buf;

        from_limbs(buf);
    }

    BOOST_SERIALIZATION_SPLIT_MEMBER()

protected:
    mpz_class data_;
};

bn254_gmp operator+(const bn254_gmp& x, const bn254_gmp& y);
bn254_gmp operator-(const bn254_gmp& x, const bn254_gmp& y);
bn254_gmp operator*(const bn254_gmp& x, const bn254_gmp& y);
bn254_gmp operator/(const bn254_gmp& x, const bn254_gmp& y);
bn254_gmp operator<<(const bn254_gmp& x, size_t i);
bn254_gmp operator>>(const bn254_gmp& x, size_t i);
bn254_gmp operator&(const bn254_gmp& x, int i);
std::ostream& operator<<(std::ostream& os, const bn254_gmp& f);

// Polynomial over Finite Field in GMP
// ------------------------------------------------------------
struct field_poly_base { };

template <typename Poly>
concept IsFieldPolyExpr = std::derived_from<Poly, field_poly_base>;

template <typename Fp>
struct field_poly {
    using value_type = Fp;
    static constexpr bool is_leaf = true;
    
    field_poly()                       : capacity_(0), size_(0), data_(nullptr)  { }
    field_poly(size_t n)               : capacity_(n), size_(n), data_(new Fp[n]{}) { }
    
    // field_poly(size_t n, uint32_t val) : capacity_(n), size_(n), data_(new Fp[n]{}) {
    //     fill_n(n, val);
    // }
    
    // field_poly(size_t n, uint64_t val) : capacity_(n), size_(n), data_(new Fp[n]{}) {
    //     fill_n(n, val);
    // }
    
    // field_poly(size_t n, const mpz_class& val) : capacity_(n), size_(n), data_(new Fp[n]{}) {
    //     fill_n(n, val);
    // }

    // template <typename Expr>
    // requires (IsFieldPolyExpr<Expr> && !std::is_same_v<Expr, field_poly>)
    // field_poly(Expr&& expr) {
    //     resize(expr.size());
    //     expr.expression_eval(*this);
    // }

    bool operator==(const field_poly& o) const = default;

    size_t size()  const { return size_; }
    bool   empty() const { return !size_; }

    auto& operator[](size_t index) {
        assert(index < size_);
        return data_[index];
    }
    
    const auto& operator[](size_t index) const {
        assert(index < size_);
        return data_[index];
    }

    auto begin()       { return data_.get(); }
    auto begin() const { return data_.get(); }
    auto end()         { return data_.get() + size_; }
    auto end()   const { return data_.get() + size_; }

    void reset() {
        size_ = 0;
        std::for_each(data_.get(), data_.get() + capacity_, [](Fp& x) { x.reset(); });
    }

    template <typename T>
    void fill_n(size_t len, const T& val) {
        std::fill_n(data_.get(), len, val);
    }

    int set_str(const char *str, unsigned int base) {
        mpz_class tmp;
        int err = tmp.set_str(str, base);
        fill_n(size_, tmp);
        return err;
    }

    template <typename T>
    field_poly& push_back(const T& val) {
        assert(size_ + 1 <= capacity_);

        data_[size_] = val;
        ++size_;
        return *this;
    }

    field_poly& push_back_consume(mpz_class& val) {
        assert(size_ + 1 <= capacity_);
        
        data_[size_++].swap(val);
        return *this;
    }

    field_poly& resize(size_t n) {
        assert(n <= capacity_);
        size_ = n;
        return *this;
    }
    
    field_poly& allocate(size_t n) {
        data_ = std::make_unique<Fp[]>(n);
        size_ = 0;
        capacity_ = n;
        return *this;
    }

    field_poly& pad_zeros_until(size_t n) {
        assert(n <= capacity_);

        if (n > size_) size_ = n;
        return *this;
    }

    template <typename RandDist>
    field_poly& pad_randoms_until(size_t n, RandDist& dist) {
        assert(n <= capacity_);

        for (size_t i = size_; i < n; i++) {
            data_[i].swap(dist());
            ++size_;
        }
        return *this;
    }

    std::vector<uint32_t> to_limbs(size_t num_limbs) {
        std::vector<uint32_t> limbs(size_ * num_limbs, 0);

        for (size_t i = 0; i < size_; i++) {
            mpz_export(limbs.data() + i * num_limbs,
                       nullptr,
                       -1,             // Least significant first
                       sizeof(void*),  // Use native word size
                       -1,             // Little endian
                       0,              // Skip 0
                       data_[i].data().get_mpz_t());
        }
        return limbs;
    }

    void from_limbs(const uint32_t *limbs, size_t num_limbs, size_t N) {
        if (capacity_ < N) {
            allocate(N);
        }

        const size_t num_import_words = num_limbs * sizeof(uint32_t) / sizeof(void*);

        for (size_t i = 0; i < N; i++) {
            mpz_import(data_[i].data().get_mpz_t(),
                       num_import_words,
                       -1,
                       sizeof(void*),
                       0,
                       0,
                       limbs + i * num_limbs);
        }
        
        size_ = N;
    }

    void EltwiseAddMod(const field_poly& x, const field_poly& y) {
        assert(size_ == x.size());
        assert(size_ == y.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].addmod(x.data_[i], y.data_[i]);
        }
    }

    void EltwiseAddMod(const field_poly& x, const uint32_t *k) {
        assert(size_ == x.size());
        
        Fp q;
        q.from_limbs(k);

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].addmod(x.data_[i], q);
        }
    }

    void EltwiseSubMod(const field_poly& x, const field_poly& y) {
        assert(size_ == x.size());
        assert(size_ == y.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].submod(x.data_[i], y.data_[i]);
        }
    }

    void EltwiseSubMod(const field_poly& x, const uint32_t *k) {
        assert(size_ == x.size());

        Fp q;
        q.from_limbs(k);

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].submod(x.data_[i], q);
        }
    }

    void EltwiseSubMod(const uint32_t *k, const field_poly& x) {
        assert(size_ == x.size());

        Fp q;
        q.from_limbs(k);

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].submod(q, x.data_[i]);
        }
    }

    void EltwiseMultMod(const field_poly& x, const field_poly& y) {
        assert(size_ == x.size());
        assert(size_ == y.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].mulmod(x.data_[i], y.data_[i]);
        }
    }

    void EltwiseMultMod(const field_poly& x, const uint32_t *k) {
        assert(size_ == x.size());

        Fp q;
        q.from_limbs(k);

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].mulmod(x.data_[i], q);
        }
    }

    void EltwiseMontMultMod(const field_poly& x, const uint32_t *k) {
        assert(size_ == x.size());

        Fp q;
        q.from_limbs(k);

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].montgomery_mulmod(x[i], q);
        }
    }

    void EltwiseDivMod(const field_poly& x, const field_poly& y) {
        assert(size_ == x.size());
        assert(size_ == y.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].divmod(x.data_[i], y.data_[i]);
        }
    }

    // Compute *this = poly * scalar + *this over the finite ring
    void EltwiseFMAMod(const field_poly& x, const field_poly& y) {
        assert(size_ == x.size());
        assert(size_ == y.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].fmamod(x.data_[i], y.data_[i]);
        }
    }

    void EltwiseFMAMod(const field_poly& x, const Fp& k) {
        assert(size_ == x.size());

        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].fmamod(x.data_[i], k);
        }
    }

    void EltwiseBitDecompose(const field_poly& x, size_t index) {
        #pragma omp parallel for
        for (size_t i = 0; i < size_; i++) {
            data_[i].data() = (x[i].data() >> index) & 1;
        }
    }

    inline const auto* data() const { return data_.get(); }
    inline auto* data() { return data_.get(); }

    template <typename Archive>
    void save(Archive& ar, const unsigned int) const {
        ar & size_;

        for (size_t i = 0; i < size_; i++) {
            ar & data_[i];
        }
    }

    template <typename Archive>
    void load(Archive& ar, const unsigned int) {
        size_t len;
        ar & len;

        allocate(len);
        size_ = len;
        for (size_t i = 0; i < size_; i++) {
            ar & data_[i];
        }
    }

    BOOST_SERIALIZATION_SPLIT_MEMBER()

protected:
    size_t capacity_;
    size_t size_;
    std::unique_ptr<Fp[]> data_;
};

}  // namespace ligero::vm::zkp
