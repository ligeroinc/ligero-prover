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

#include <concepts>
#include <memory>

#include <util/mpz_get.hpp>
#include <util/mpz_assign.hpp>
#include <zkp/backend/witness_manager.hpp>

namespace ligero::vm::zkp {

namespace ops {
struct backend_ops { };
struct constant : backend_ops { };
struct addmod   : backend_ops { };
struct submod   : backend_ops { };
struct mulmod   : backend_ops { };
/** Bitwise operations */
struct bitwise_and : backend_ops { };
struct bitwise_not : backend_ops { };
}  // namespace ops


struct zkexpr_base { };

template <typename Op>
concept IsBackendOp = std::derived_from<std::remove_cvref_t<Op>, ops::backend_ops>;

template <typename T>
concept IsZKExpr = std::derived_from<std::remove_cvref_t<T>, zkexpr_base>;

template<typename T>
concept IsZKExprConstant =
     std::integral<std::remove_cvref_t<T>>          // all built-in ints
  || std::same_as<std::remove_cvref_t<T>, mpz_class>;

template <IsBackendOp op, typename... Args> struct zkexpr;

struct managed_witness : zkexpr_base {
    managed_witness() = default;

    explicit managed_witness(std::shared_ptr<lazy_witness> p)
        : data_(std::move(p)) {}

    lazy_witness&       operator*()        { return *data_; }
    const lazy_witness& operator*()  const { return *data_; }

    lazy_witness*       operator->()       { return data_.get(); }
    const lazy_witness* operator->() const { return data_.get(); }

    lazy_witness*       get()       { return data_.get(); }
    const lazy_witness* get() const { return data_.get(); }

    auto&       data()       { return data_; }
    const auto& data() const { return data_; }

    template <typename T>
    void val(const T& v) { mpz_assign(*data_->value_ptr(), v); }
    const mpz_class& val() const { return *data_->value_ptr(); }

    uint32_t as_u32() const { return mpz_get_u32(val()); }
    uint64_t as_u64() const { return mpz_get_u64(val()); }

    template <typename Ctx>
    managed_witness eval(Ctx& ctx) const {
        return *this;
    }

    template <typename Ctx>
    void eval(Ctx& ctx, mpz_class& result, const mpz_class& rand) const {
        ctx.manager().witness_add_random(*data_, rand);
        result = *data_->value_ptr();
    }

private:
    std::shared_ptr<lazy_witness> data_;
};

struct decomposed_bits {
    decomposed_bits() = default;
    decomposed_bits(std::vector<managed_witness> bits) : bits_(std::move(bits)) { }

    ~decomposed_bits() {
        // Enforce reverse-order destruction of elements
        while (!bits_.empty()) {
            bits_.pop_back();
        }
    }

    size_t size() const { return bits_.size(); }

    const managed_witness& operator[](size_t i) const { return bits_[i]; }
          managed_witness& operator[](size_t i)       { return bits_[i]; }

    const auto& data() const { return bits_; }
    auto&       data()       { return bits_; }

    void push_back(managed_witness w) {
        bits_.push_back(std::move(w));
    }

    void push_lsb(managed_witness w, size_t n) {
        bits_.insert(bits_.begin(), n, w);
    }

    void drop_lsb(size_t n) {
        assert(n <= size());

        // Enforce reverse-order destruction by manually calling `reset()`
        for (int i = n - 1; i >= 0; --i) {
            bits_[i].data().reset();
        }
        bits_.erase(bits_.begin(), bits_.begin() + n);
    }

    void push_msb(managed_witness w, size_t n) {
        bits_.insert(bits_.end(), n, w);
    }

    void drop_msb(size_t n) {
        assert(n <= size());

        // Enforce reverse-order destruction by manually calling `pop_back()`
        for (size_t i = 0; i < n; i++) {
            bits_.pop_back();
        }
    }

private:
    std::vector<managed_witness> bits_;
};

template <IsBackendOp Op, typename... Args>
struct zkexpr : zkexpr_base {
    zkexpr(Op op, Args... args) : args_(std::move(args)...) { }

    template <typename Ctx>
    managed_witness eval(Ctx& ctx) const {
        return std::apply([&ctx, op=op_](const auto&... args) {
            return ctx.eval_impl(op, args...);
        }, args_);
    }

    template <typename Ctx>
    void eval(Ctx& ctx, mpz_class& result, const mpz_class& rand) const {
        return std::apply([&ctx, &result, &rand, op=op_](const auto&... args) {
            ctx.eval_impl(result, rand, op, args...);
        }, args_);
    }

protected:
    Op op_;
    std::tuple<Args...> args_;
};

template<IsBackendOp Op, typename... Args>
zkexpr(Op, Args&&...) -> zkexpr<Op, std::decay_t<Args>...>;

template <typename T>
struct zkexpr<ops::constant, T> : zkexpr_base {
    zkexpr(T v) : data(std::move(v)) { }

    template <typename Ctx>
    managed_witness eval(Ctx& ctx) const {
        auto *wit = ctx.manager().acquire_witness(data);
        ctx.manager().constrain_constant(*wit);
        return ctx.make_managed(wit);
    }

    // template <typename Ctx>
    // void eval(Ctx& ctx, mpz_class& result, const mpz_class& rand) const {
    //     mpz_class *tmp = ctx.acquire_mpz();
    //     typename Ctx::field_type::mulmod(*tmp, rand, k);
    //     ctx.manager().constsum_add(*tmp);
    //     ctx.recycle_mpz(tmp);
    // }

    T data;
};

template <IsZKExpr T, IsZKExpr V>
auto operator+(T&& t, V&& v) {
    return zkexpr{ ops::addmod{}, std::forward<T>(t), std::forward<V>(v) };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator+(T&& t, K k) {
    return zkexpr{
        ops::addmod{},
        std::forward<T>(t),
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) }
    };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator+(K k, T&& t) {
    return zkexpr{
        ops::addmod{},
        std::forward<T>(t),
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) }
    };
}

template <IsZKExpr T, IsZKExpr V>
auto operator-(T&& t, V&& v) {
    return zkexpr{ ops::submod{}, std::forward<T>(t), std::forward<V>(v) };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator-(T&& t, K k) {
    return zkexpr{
        ops::submod{},
        std::forward<T>(t),
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) }
    };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator-(K k, T&& t) {
    return zkexpr{
        ops::submod{},
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) },
        std::forward<T>(t)
    };
}

template <IsZKExpr T, IsZKExpr V>
auto operator*(T&& t, V&& v) {
    return zkexpr{ ops::mulmod{}, std::forward<T>(t), std::forward<V>(v) };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator*(T&& t, K k) {
    return zkexpr{
        ops::mulmod{},
        std::forward<T>(t),
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) }
    };
}

template <IsZKExpr T, IsZKExprConstant K>
auto operator*(K k, T&& t) {
    return zkexpr{
        ops::mulmod{},
        std::forward<T>(t),
        zkexpr<ops::constant, std::decay_t<K>>{ std::move(k) }
    };
}

template <IsZKExpr T>
auto operator~(T&& t) {
    return zkexpr{ ops::bitwise_not{}, std::forward<T>(t) };
}

template <IsZKExpr T, IsZKExpr V>
auto operator&(T&& t, V&& v) {
    return zkexpr{ ops::bitwise_and{}, std::forward<T>(t), std::forward<V>(v) };
}


template <typename Field, typename RandomPolicy>
struct ligetron_backend {
    using field_type       = Field;
    using random_policy    = RandomPolicy;
    using witness_row_type = typename witness_manager<Field, RandomPolicy>::witness_row_type;

    struct witness_deleter {
        witness_deleter(ligetron_backend *p) : self(p) { }

        void operator()(lazy_witness *wit) {
            self->manager().commit_release_witness(wit);
        }
    private:
        ligetron_backend *self;
    };

    ligetron_backend(size_t packing_size, size_t padded_size)
        : packing_size_(packing_size),
          padded_size_(padded_size),
          manager_(packing_size, padded_size)
        {  }

    auto&       manager()       { return manager_; }
    const auto& manager() const { return manager_; }

    managed_witness acquire_witness() {
        return make_managed(manager_.acquire_witness());
    }

    managed_witness make_managed(lazy_witness *wit) {
        return managed_witness { std::shared_ptr<lazy_witness>(wit, witness_deleter{ this }) };
    }

    template <IsZKExpr Expr>
    managed_witness eval(const Expr& expr) {
        return expr.eval(*this);
    }

    template <IsZKExprConstant K>
    managed_witness eval(const K& k) {
        return zkexpr<ops::constant, std::decay_t<K>>{ k }.eval(*this);
    }

    /** ------------------------------------------------------------ *
     * For addition, compute result and set randomness:
     *   Z   =   X    +    Y
     *  -r      +r        +r
     * ------------------------------------------------------------- */
    template <IsZKExpr T, IsZKExpr V>
    managed_witness eval_impl(ops::addmod op, const T& expr_x, const V& expr_y) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x, expr_y);
        manager_.recycle_mpz(r);

        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExpr V>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::addmod op, const T& expr_x, const V& expr_y)
    {
        auto *x = manager_.acquire_mpz();
        auto *y = manager_.acquire_mpz();

        expr_x.eval(*this, *x, r);
        expr_y.eval(*this, *y, r);

        Field::addmod(out, *x, *y);

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(y);
    }

    /** ------------------------------------------------------------ *
     * For addition with constant, compute result and set randomness:
     *   Z   =   X    +    K;    this.constant_sum_
     *  -r      +r                   +(k * r)
     * ------------------------------------------------------------- */
    template <IsZKExpr T, IsZKExprConstant K>
    managed_witness
    eval_impl(ops::addmod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x, k_val);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExprConstant K>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::addmod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val)
    {
        auto *x = manager_.acquire_mpz();
        auto *k = manager_.acquire_mpz();

        expr_x.eval(*this, *x, r);

        *k = k_val.data;
        Field::addmod(out, *x, *k);

        if constexpr (RandomPolicy::enable_linear_check) {
            // Now k = k * r
            Field::mulmod(*k, *k, r);
            manager_.constsum_add(*k);
        }

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(k);
    }

    /** ------------------------------------------------------------ *
     * IMPORTANT: For subtract, It has to be in such form:
     *   Z   =   X    -    Y
     *  -r      +r        -r
     * Otherwise the randomness's sign won't be correct in nested expression
     * e.g. (a - (b - c))
     * ------------------------------------------------------------ */
    template<IsZKExpr T, IsZKExpr V>
    managed_witness eval_impl(ops::submod op, const T& expr_x, const V& expr_y) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x, expr_y);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExpr V>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::submod op, const T& expr_x, const V& expr_y)
    {
        auto *x       = manager_.acquire_mpz();
        auto *y       = manager_.acquire_mpz();
        auto *minus_r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            Field::negate(*minus_r, r);
        }

        expr_x.eval(*this, *x, r);
        expr_y.eval(*this, *y, *minus_r);

        Field::submod(out, *x, *y);

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(y);
        manager_.recycle_mpz(minus_r);
    }

    /** ------------------------------------------------------------ *
     * For subtract with constant, compute result and set randomness:
     *   Z   =   X    -    K;    this.constant_sum_
     *  -r      +r                   -(k * r)
     * ------------------------------------------------------------- */
    template <IsZKExpr T, IsZKExprConstant K>
    managed_witness
    eval_impl(ops::submod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x, k_val);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExprConstant K>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::submod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val)
    {
        auto *x = manager_.acquire_mpz();
        auto *k = manager_.acquire_mpz();

        expr_x.eval(*this, *x, r);

        *k = k_val.data;
        Field::submod(out, *x, *k);

        if constexpr (RandomPolicy::enable_linear_check) {
            // Now k = k * r
            Field::mulmod(*k, *k, r);
            manager_.constsum_sub(*k);
        }

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(k);
    }

    /** ------------------------------------------------------------ *
     * For subtract with constant, compute result and set randomness:
     *   Z   =   K    -    X;    this.constant_sum_
     *  -r                -r          +(k * r)
     * ------------------------------------------------------------- */
    template <IsZKExpr T, IsZKExprConstant K>
    managed_witness
    eval_impl(ops::submod op, const zkexpr<ops::constant, K>& k_val, const T& expr_x) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, k_val, expr_x);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExprConstant K>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::submod op, const zkexpr<ops::constant, K>& k_val, const T& expr_x)
    {
        auto *x = manager_.acquire_mpz();
        auto *k = manager_.acquire_mpz();
        auto *minus_r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            Field::negate(*minus_r, r);
        }
        expr_x.eval(*this, *x, *minus_r);

        mpz_assign(*k, k_val.data);
        Field::submod(out, *k, *x);

        if constexpr (RandomPolicy::enable_linear_check) {
            // Now k = k * r
            Field::mulmod(*k, *k, r);
            manager_.constsum_add(*k);
        }

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(k);
        manager_.recycle_mpz(minus_r);
    }


    /** ------------------------------------------------------------ *
     * Multiplication
     * ------------------------------------------------------------- */
    template<IsZKExpr T, IsZKExpr V>
    managed_witness eval_impl(ops::mulmod op, const T& expr_x, const V& expr_y) {
        managed_witness x = expr_x.eval(*this);
        managed_witness y = expr_y.eval(*this);

        auto *z = manager_.acquire_witness();
        Field::mulmod(*z->value_ptr(), *x->value_ptr(), *y->value_ptr());

        manager_.constrain_quadratic(z, x.get(), y.get());

        return make_managed(z);
    }

    template <IsZKExpr T, IsZKExpr V>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::mulmod op, const T& expr_x, const V& expr_y)
    {
        managed_witness z = eval_impl(op, expr_x, expr_y);
        out = z.val();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.witness_add_random(*z, r);
        }
    }

    /** ------------------------------------------------------------ *
     * Multipy by constant
     *   Z   =     X    *    K;
     *  -r     +(K * r)
     * ------------------------------------------------------------- */
    template <IsZKExpr T, IsZKExprConstant K>
    managed_witness
    eval_impl(ops::mulmod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x, k_val);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T, IsZKExprConstant K>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::mulmod op, const T& expr_x, const zkexpr<ops::constant, K>& k_val)
    {
        auto *x  = manager_.acquire_mpz();
        auto *k  = manager_.acquire_mpz();
        auto *kr = manager_.acquire_mpz();

        *k = k_val.data;

        if constexpr (RandomPolicy::enable_linear_check) {
            Field::mulmod(*kr, *k, r);
        }
        expr_x.eval(*this, *x, *kr);

        Field::mulmod(out, *x, *k);

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(k);
        manager_.recycle_mpz(kr);
    }

    /** ------------------------------------------------------------ *
     * For bitwise not, compute result and set randomness:
     *   Z   =   1    -    X;    this.constant_sum_
     *  -r                -r          +r
     * ------------------------------------------------------------- */
    template <IsZKExpr T>
    managed_witness
    eval_impl(ops::bitwise_not op, const T& expr_x) {
        auto *wit = manager_.acquire_witness();
        auto *r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.generate_linear_random(*r);
            manager_.witness_sub_random(*wit, *r);
        }
        eval_impl(*wit->value_ptr(), *r, op, expr_x);

        manager_.recycle_mpz(r);
        return make_managed(wit);
    }

    template <IsZKExpr T>
    void eval_impl(mpz_class& out, const mpz_class& r, ops::bitwise_not, const T& expr_x) {
        auto *x = manager_.acquire_mpz();
        auto *minus_r = manager_.acquire_mpz();

        if constexpr (RandomPolicy::enable_linear_check) {
            Field::negate(*minus_r, r);
        }
        expr_x.eval(*this, *x, *minus_r);

        assert(*x == 0 || *x == 1);
        out = 1u - x->get_ui();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.constsum_add(r);
        }

        manager_.recycle_mpz(x);
        manager_.recycle_mpz(minus_r);
    }

    /** ------------------------------------------------------------ *
     * Bitwise AND
     * ------------------------------------------------------------- */
    template<IsZKExpr T, IsZKExpr V>
    managed_witness eval_impl(ops::bitwise_and op, const T& expr_x, const V& expr_y) {
        managed_witness x = expr_x.eval(*this);
        managed_witness y = expr_y.eval(*this);

        auto *z = manager_.acquire_witness();
        *z->value_ptr() = x.val().get_ui() & y.val().get_ui();

        assert(x.val() == 0 || x.val() == 1);
        assert(y.val() == 0 || y.val() == 1);

        manager_.constrain_quadratic(z, x.get(), y.get());

        return make_managed(z);
    }

    template <IsZKExpr T, IsZKExpr V>
    void eval_impl(mpz_class& out, const mpz_class& r,
                   ops::bitwise_and op, const T& expr_x, const V& expr_y)
    {
        managed_witness z = eval_impl(op, expr_x, expr_y);
        out = z.val();

        if constexpr (RandomPolicy::enable_linear_check) {
            manager_.witness_add_random(*z, r);
        }
    }

    managed_witness duplicate(managed_witness& wit) {
        return make_managed(manager_.clone_witness(*wit));
    }

    template <typename T>
    ligetron_backend& assert_const(managed_witness& wit, const T& val) {
        manager_.constrain_constant(*wit, val);
        return *this;
    }

    ligetron_backend& assert_equal(managed_witness& x, managed_witness& y) {
        manager_.constrain_equal(*x, *y);
        return *this;
    }

    std::pair<managed_witness, managed_witness>
    idivide_qr(managed_witness& x, managed_witness& y) {
        auto q = acquire_witness();
        auto r = acquire_witness();

        mpz_fdiv_qr(q->value_ptr()->get_mpz_t(),
                    r->value_ptr()->get_mpz_t(),
                    x->value_ptr()->get_mpz_t(),
                    y->value_ptr()->get_mpz_t());

        // std::cout << "div: " << x.val() << " / " << y.val()
        //           << " = " << q.val() << " , " << r.val() << std::endl;

        auto tmp = eval(q * y + r);
        // std::cout << "q * y + r = " << tmp.val() << std::endl;

        manager_.constrain_equal(*tmp, *x);

        return std::make_pair(std::move(q), std::move(r));
    }

    decomposed_bits
    bit_decompose(managed_witness& x, size_t from_bits) {
        std::vector<managed_witness> bits;

        auto *decompose_rand = manager_.acquire_mpz();
        manager_.generate_linear_random(*decompose_rand);

        manager_.witness_sub_random(*x, *decompose_rand);

        mpz_class *tmp = manager_.acquire_mpz();
        for (size_t i = 0; i < from_bits; i++) {
            int bit = mpz_tstbit(x->value_ptr()->get_mpz_t(), i);
            auto *wit = manager_.acquire_witness(bit);
            manager_.constrain_bit(wit);

            *tmp = *decompose_rand << i;
            Field::reduce(*tmp, *tmp);

            manager_.witness_add_random(*wit, *tmp);

            bits.emplace_back(make_managed(wit));
        }

        manager_.recycle_mpz(tmp);
        manager_.recycle_mpz(decompose_rand);

        return decomposed_bits(std::move(bits));
    }

    template <typename T>
    decomposed_bits
    bit_decompose_constant(const T& k, size_t from_bits) {
        std::vector<managed_witness> bits;

        mpz_class *k_val = manager_.acquire_mpz();
        mpz_assign(*k_val, k);

        for (size_t i = 0; i < from_bits; i++) {
            auto *wit = manager_.acquire_witness((*k_val >> i) & 1u);
            manager_.constrain_constant(*wit);
            bits.emplace_back(make_managed(wit));
        }

        manager_.recycle_mpz(k_val);
        return decomposed_bits(std::move(bits));
    }

    managed_witness bit_compose(decomposed_bits& bits) {
        auto *sum = manager_.acquire_witness();
        auto *rand = manager_.acquire_mpz();
        manager_.generate_linear_random(*rand);
        manager_.witness_sub_random(*sum, *rand);

        mpz_class *tmp = manager_.acquire_mpz();
        for (size_t i = 0; i < bits.size(); i++) {
            *tmp = *bits[i]->value_ptr() << i;
            *sum->value_ptr() += *tmp;

            *tmp = *rand << i;
            Field::reduce(*tmp, *tmp);
            manager_.witness_add_random(*bits[i], *tmp);
        }
        manager_.recycle_mpz(tmp);
        manager_.recycle_mpz(rand);

        return make_managed(sum);
    }

    void bit_compose_constant(mpz_class& out, decomposed_bits& bits) {
        for (size_t i = 0; i < bits.size(); i++) {
            out += *bits[i]->value_ptr() << i;
        }
    }

    managed_witness bitwise_xor(managed_witness& x, managed_witness& y) {
        return eval(x + y - 2u * (x & y));
    }

    managed_witness bitwise_xnor(managed_witness& x, managed_witness& y) {
        return eval(~(x + y - 2u * (x & y)));
    }

    managed_witness
    bitwise_eqz(decomposed_bits& x) {
        const size_t num_bits = x.size();
        auto eqz = eval(~x[0]);

        for (size_t i = 1; i < num_bits; i++) {
            eqz = eval(eqz & ~x[i]);
        }

        return eqz;
    }

    managed_witness
    bitwise_eq(decomposed_bits& x, decomposed_bits& y) {
        assert(x.size() == y.size());

        const size_t num_bits = x.size();
        auto eq = bitwise_xnor(x[0], y[0]);

        for (size_t i = 1; i < num_bits; i++) {
            eq = eval(eq & bitwise_xnor(x[i], y[i]));
        }

        return eq;
    }

    std::pair<managed_witness, managed_witness>
    bitwise_gt(decomposed_bits& x, decomposed_bits& y, sign_kind sign) {
        assert(x.size() == y.size());

        const size_t num_bits = x.size();
        const size_t msb = num_bits - 1;

        managed_witness gt, eq;
        if (sign == sign_kind::sign) {
            gt = eval(~x[msb] & y[msb]);
        }
        else {
            gt = eval(x[msb] & ~y[msb]);
        }

        eq = bitwise_xnor(x[msb], y[msb]);

        for (int i = msb - 1; i >= 0; i--) {
            auto neq = bitwise_xnor(x[i], y[i]);

            gt = eval(gt + (eq & x[i] & ~y[i]));
            eq = eval(eq & neq);
        }

        return std::make_pair(std::move(gt), std::move(eq));
    }

    void finalize() {
        manager_.finalize();
    }

private:
    size_t packing_size_, padded_size_;
    witness_manager<Field, RandomPolicy> manager_;
};


}  // namespace ligero::vm::zkp
