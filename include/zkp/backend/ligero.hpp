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

#include <array>
#include <concepts>
#include <deque>
#include <memory>
#include <optional>
#include <vector>

#include <params.hpp>
#include <util/timer.hpp>
#include <util/log.hpp>
#include <zkp/common.hpp>
#include <zkp/finite_field_gmp.hpp>


namespace ligero::vm::zkp {
namespace zkp_ops {

struct u64_ops { };
struct u64_add  : u64_ops { };
struct u64_addc : u64_ops { };
struct u64_sub  : u64_ops { };
struct u64_subc : u64_ops { };
struct u64_mul  : u64_ops { };
struct u64_mulc : u64_ops { };
struct u64_div  : u64_ops { };

struct field_ops { };
struct field_add  : field_ops { };
struct field_addc : field_ops { };
struct field_sub  : field_ops { };
struct field_subc : field_ops { };
struct field_mul  : field_ops { };
struct field_mulc : field_ops { };
struct field_div  : field_ops { };

}  // namespace zkp_ops

template <typename Op>
concept IsU64Op   = std::derived_from<std::remove_reference_t<Op>, zkp_ops::u64_ops>;

template <typename Op>
concept IsFieldOp = std::derived_from<std::remove_reference_t<Op>, zkp_ops::field_ops>;

template <typename Op>
concept IsAddOp      = std::same_as<Op, zkp_ops::u64_add>  ||
                       std::same_as<Op, zkp_ops::field_add>;

template <typename Op>
concept IsAddConstOp = std::same_as<Op, zkp_ops::u64_addc> ||
                       std::same_as<Op, zkp_ops::field_addc>;

template <typename Op>
concept IsSubOp      = std::same_as<Op, zkp_ops::u64_sub>  ||
                       std::same_as<Op, zkp_ops::field_sub>;

template <typename Op>
concept IsSubConstOp = std::same_as<Op, zkp_ops::u64_subc> ||
                       std::same_as<Op, zkp_ops::field_subc>;

template <typename Op>
concept IsMulOp      = std::same_as<Op, zkp_ops::u64_mul>  ||
                       std::same_as<Op, zkp_ops::field_mul>;

template <typename Op>
concept IsMulConstOp = std::same_as<Op, zkp_ops::u64_mulc> ||
                       std::same_as<Op, zkp_ops::field_mulc>;

template <typename Op>
concept IsDivOp      = std::same_as<Op, zkp_ops::u64_div>  ||
                       std::same_as<Op, zkp_ops::field_div>;

// ------------------------------------------------------------

struct any_expr_base { };
struct u64_expr_base   : any_expr_base  { };
struct field_expr_base : any_expr_base  { };

template <typename Expr>
concept IsU64Expr   = std::derived_from<std::remove_reference_t<Expr>, u64_expr_base>;

template <typename Expr>
concept IsFieldExpr = std::derived_from<std::remove_reference_t<Expr>, field_expr_base>;

template <typename Expr>
concept IsZKPExpr   = std::derived_from<std::remove_reference_t<Expr>, any_expr_base>;


struct zkp_constant : u64_expr_base {
    u64 val;

    zkp_constant(u32 v) : val(v) { }
    zkp_constant(u64 v) : val(v) { }
};

template <typename Val, typename Rand>
struct zkp_variable {
    using value_type  = Val;
    using random_type = Rand;
    
    zkp_variable() = default;
    
    void reset() {
        val_ = 0ul;
        for (size_t i = 0; i < params::num_linear_test; i++) {
            random_[i] = 0ul;
        }
    }

    Val& val() { return val_; }
    const Val& val() const { return val_; }

    Rand* random() const { return random_.data(); }

protected:
    Val val_;
    mutable std::array<Rand, params::num_linear_test> random_;
};

template <typename T>
struct zkp_variable_ext {
    using value_type   = typename T::value_type;
    using random_type  = typename T::random_type;
    using element_type = T;
    
    zkp_variable_ext() = default;
    zkp_variable_ext(const element_type& v) : out_(v) { }

    value_type& val() { return out_.val(); }
    const value_type& val() const { return out_.val(); }

    random_type* random() const { return out_.random(); }

    bool is_multiply_node() const {
        return in_.has_value();
    }

    auto& input_wires() { return in_; }
    const auto& input_wires() const { return in_; }

    auto& output_wire() { return out_; }
    const auto& output_wire() const { return out_; }

    void reset() {
        in_.reset();
        out_.reset();
    }
    
    template <typename Ctx>
    const value_type& force(Ctx& ctx) const { return out_.val(); }

    template <typename Ctx>
    const value_type& force(Ctx& ctx, const random_type& r) const {
        ctx.append_randomness(*this, r);
        return out_.val();
    }

protected:
    std::optional<std::array<element_type, 2>> in_;
    element_type out_;
};

template <typename... Args>
struct is_zkvar_ext : std::false_type {};

template <typename... Args>
struct is_zkvar_ext<zkp_variable_ext<Args...>> : std::true_type {};

template <typename T>
concept IsZKPVarExt = is_zkvar_ext<T>::value;


template <typename T, typename ExprFamily, typename Deleter>
struct zkp_witness : ExprFamily {
    using value_type   = typename T::value_type;
    using random_type  = typename T::random_type;
    using element_type = T;
    using ptr_type = std::unique_ptr<element_type, Deleter>;
    
    zkp_witness() : ptr(nullptr) { }
    zkp_witness(element_type *p, Deleter d) : ptr(p, d) { }
    zkp_witness(std::unique_ptr<element_type, Deleter> p) : ptr(std::move(p)) { }

    zkp_witness(zkp_witness&& other) noexcept = default;
    zkp_witness& operator=(zkp_witness&& other) noexcept {
        ptr = std::move(other.ptr);
        return *this;
    }

    explicit operator bool() const noexcept { return static_cast<bool>(ptr); }

    element_type& operator*() { return *ptr; }
    const element_type& operator*() const { return *ptr; }

    element_type* operator->() { return ptr.get(); }
    const element_type *operator->() const { return ptr.get(); }

    element_type* release() { return ptr.release(); }

    auto& val() { return ptr->val(); }
    const auto& val() const { return ptr->val(); }

    auto* random() const { return ptr->random(); }

    // Note: Always return a copy for multiplication
    template <typename Ctx>
    zkp_witness force(Ctx& ctx) const {
        return ctx.duplicate(*this);
    }

    template <typename Ctx>
    auto force(Ctx& ctx, const random_type& r) const {
        return ptr->force(ctx, r);
    }

private:
    ptr_type ptr;
};

template <typename... Args>
struct is_witness : std::false_type {};

template <typename... Args>
struct is_witness<zkp_witness<Args...>> : std::true_type {};

template <typename T>
concept IsWitness = is_witness<T>::value;


template <typename ExprFamily, typename... Args>
struct zkp_expr : ExprFamily {
    std::tuple<Args...> args_;

    zkp_expr(Args&&... args) : args_(std::forward<Args>(args)...) { }

    template <typename Ctx>
    auto force(Ctx& ctx) const {
        return std::apply([&ctx](auto op, auto&&... args) {
            return ctx.eval(op, std::forward<decltype(args)>(args)...);
        }, args_);
    }

    template <typename Ctx>
    auto force(Ctx& ctx, const typename Ctx::bignum_type& r) const {
        return std::apply([&ctx, &r](auto op, auto&&... args) {
            return ctx.eval(op, r, std::forward<decltype(args)>(args)...);
        }, args_);
    }
};

template <typename... Args>
auto u64_expr(Args&&... args) {
    return zkp_expr<u64_expr_base, Args...>(std::forward<Args>(args)...);
}

template <typename... Args>
auto field_expr(Args&&... args) {
    return zkp_expr<field_expr_base, Args...>(std::forward<Args>(args)...);
}

// template <typename... Args>
// using field_expr = zkp_expr<field_expr_base, Args...>;

// Template argument deduction guide
template <typename... Args>
zkp_expr(Args&&...) -> zkp_expr<u64_expr_base, Args...>;

template <typename... Args>
zkp_expr(Args&&...) -> zkp_expr<field_expr_base, Args...>;


// ------------------------------------------------------------

template <typename Poly, typename RandomDist>
struct ligero_backend {

    struct commit_deleter;
    
    struct row_type {
        Poly val;
        Poly random[params::num_linear_test];
    };
    
    using ring_type     = typename Poly::value_type;
    using bignum_type   = typename ring_type::value_type;
    
    using u64_var_type   = zkp_variable<u64, bignum_type>;
    using field_var_type = zkp_variable<ring_type, bignum_type>;

    using u64_ext_type   = zkp_variable_ext<u64_var_type>;
    using field_ext_type = zkp_variable_ext<field_var_type>;
    
    using u64_witness_type   = zkp_witness<u64_ext_type, u64_expr_base, commit_deleter>;
    using field_witness_type = zkp_witness<field_ext_type, field_expr_base, commit_deleter>;

    struct commit_deleter {
        commit_deleter() : ctx_(nullptr) { }
        commit_deleter(ligero_backend *ctx) : ctx_(ctx) { }

        template <IsZKPVarExt T>
        void operator()(T* v) {
            assert(ctx_ != nullptr);
            assert(v != nullptr);
            
            if (v->is_multiply_node()) {
                // std::cout << "mul node: "
                //           << v->val().data()
                //           << ", rand = "
                //           << v->random()[0].data()
                //           << ", input = "
                //           << (*v->input_wires())[0].val().data() << " "
                //           << (*v->input_wires())[0].random()[0].data() << ", "
                //           << (*v->input_wires())[1].val().data() << " "
                //           << (*v->input_wires())[1].random()[0].data()
                //           << std::endl;

                auto& input = *v->input_wires();
                ctx_->commit_quadratic(v->output_wire(), input[0], input[1]);
            }
            else {
                // std::cout << "linear node: "
                //           << v->val().data()
                //           << ", rand = "
                //           << v->random()[0].data()
                //           << std::endl;
                
                ctx_->commit_linear(v->output_wire());
            }

            ctx_->release_variable(v);
        }

        ligero_backend *ctx_;
    };

    ligero_backend(size_t packing_size, size_t padded_size, RandomDist& dist)
        : packing_size_(packing_size),
          padded_size_(padded_size),
          dist_(dist)
        {
            linear_.val.allocate(padded_size);
            quad_l_.val.allocate(padded_size);
            quad_r_.val.allocate(padded_size);
            quad_o_.val.allocate(padded_size);

            for (size_t i = 0; i < params::num_linear_test; i++) {
                linear_.random[i].allocate(padded_size);
                quad_l_.random[i].allocate(padded_size);
                quad_r_.random[i].allocate(padded_size);
                quad_o_.random[i].allocate(padded_size);
            }
        }

    ~ligero_backend() {
        for (size_t i = 0; i < variable_pool_.size(); i++) {
            delete variable_pool_[i];
        }
    }

    template <typename Func>
    void on_linear(Func f) {
        on_linear_ = std::move(f);
    }

    template <typename Func>
    void on_quadratic(Func f) {
        on_quad_ = std::move(f);
    }

    template <IsWitness T>
    T make_witness() {
        if constexpr (std::is_same_v<T, u64_witness_type>) {
            return acquire_u64_witness();
        }
        else {
            return acquire_field_witness();
        }
    }
    
    u64_witness_type acquire_u64_witness() {
        if (variable_pool_.empty()) {
            for (size_t i = 0; i < pool_alloc_size_; i++) {
                variable_pool_.emplace_back(new u64_ext_type{});
            }
        }
        
        auto *p = variable_pool_.front();
        variable_pool_.pop_front();
        return u64_witness_type(p, commit_deleter{ this });
    }

    field_witness_type acquire_field_witness() {
        return field_witness_type(new field_ext_type{}, commit_deleter{ this });
    }

    void release_variable(u64_ext_type *p) {
        p->reset();
        variable_pool_.push_back(p);
    }

    void release_variable(field_ext_type *p) {
        delete p;
    }

    field_witness_type promote_u64_witness(u64_witness_type wit) {
        field_witness_type fp = acquire_field_witness();
        fp.val() = wit.val();
        build_equal(fp, wit);
        return fp;
    }

    u64_witness_type demote_field_witness(field_witness_type wit) {
        u64_witness_type wit64 = acquire_u64_witness();
        wit64.val() = static_cast<u64>(wit.val());
        build_equal(wit, wit64);
        return wit64;
    }

    // --------------------------------------------------

    bignum_type generate_randomness() {
        if constexpr(RandomDist::enabled) {
            return dist_().data();
        }
        else {
            return 0;
        }
    }

    template <typename V, typename R>
    void commit_linear(const zkp_variable<V, R>& var) {
        ++num_linear_constraints_;
        
        if (linear_.val.size() >= packing_size_) {
            on_linear_(linear_);
            
            linear_.val.reset();
            if constexpr (RandomDist::enabled) {
                for (size_t i = 0; i < params::num_linear_test; i++) {
                    linear_.random[i].reset();
                }
            }
        }

        linear_.val.push_back(var.val());

        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                linear_.random[i].push_back_consume(var.random()[i]);
            }
        }
    }

    template <typename V, typename R>
    void commit_quadratic(const zkp_variable<V, R>& out, const zkp_variable<V, R>& x, const zkp_variable<V, R>& y) {
        assert(quad_l_.val.size() == quad_r_.val.size());
        assert(quad_r_.val.size() == quad_o_.val.size());

        ++num_constraints_;
        
        if (quad_l_.val.size() >= packing_size_) {
            on_quad_(quad_l_, quad_r_, quad_o_);

            ++num_rows_;
            
            quad_l_.val.reset();
            quad_r_.val.reset();
            quad_o_.val.reset();
            
            if constexpr (RandomDist::enabled) {
                for (size_t i = 0; i < params::num_quadratic_test; i++) {
                    quad_l_.random[i].reset();
                    quad_r_.random[i].reset();
                    quad_o_.random[i].reset();
                }
            }
        }
        
        quad_l_.val.push_back(x.val());
        quad_r_.val.push_back(y.val());
        quad_o_.val.push_back(out.val());

        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_quadratic_test; i++) {
                quad_l_.random[i].push_back_consume(x.random()[i]);
                quad_r_.random[i].push_back_consume(y.random()[i]);
                quad_o_.random[i].push_back_consume(out.random()[i]);
            }
        }
    }

    auto const_sums() const {
        std::array<ring_type, params::num_linear_test> sums;

        for (size_t i = 0; i < params::num_linear_test; i++) {
            sums[i] = ring_type(const_sums_[i]);
        }
        
        return sums;
    }

    template <IsWitness T>
    void assert_const(const T& x, const bignum_type& k) {
        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                auto r = dist_();
                
                x->random()[i] += r.data();
                const_sums_[i] -= r.data() * k;
            }
        }
    }

    template <IsWitness T, IsWitness V>
    void build_equal(const T& z, const V& x) {
        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                auto r = dist_();
                z->random()[i] -= r.data();
                x->random()[i] += r.data();
            }
        }
    }

    template <IsWitness T>
    void build_linear(const T& z, const T& x, const T& y) {
        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                auto r = dist_();
                z->random()[i] -= r.data();
                x->random()[i] += r.data();
                y->random()[i] += r.data();
            }
        }
    }

    template <IsZKPVarExt T>
    void append_randomness(const T& x, const bignum_type& r) {
        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                x.random()[i] += r;
            }
        }
    }

    void append_const_sum(const bignum_type& r) {
        if constexpr (RandomDist::enabled) {
            for (size_t i = 0; i < params::num_linear_test; i++) {
                const_sums_[i] += r;
            }
        }
    }

    u64_witness_type make_const(u64 k) {
        u64_witness_type x = acquire_u64_witness();
        x.val() = k;
        assert_const(x, k);
        return x;
    }

    template <IsWitness T>
    T duplicate(const T& x) {
        auto p = make_witness<T>();
        p.val() = x.val();
        build_equal(p, x);
        return p;
    }

    template <IsWitness T>
    T make_multiply(T x, T y) {
        if (x->is_multiply_node()) {
            x = duplicate(x);
        }

        if(y->is_multiply_node()) {
            y = duplicate(y);
        }
        
        auto z = make_witness<T>();
        auto *px = x.release();
        auto *py = y.release();

        z->val() = px->val() * py->val();
        z->input_wires() = { px->output_wire(), py->output_wire() };

        // Remember to release variables too
        release_variable(px);
        release_variable(py);
        
        return z;
    }

    template <IsWitness T>
    T make_bit(T b) {
        assert(b.val() == 0 || b.val() == 1);
        
        if(b->is_multiply_node()) {
            b = duplicate(b);
        }
        
        auto bb = duplicate(b);
        auto bbb = duplicate(b);
        
        auto *px = b.release();
        auto *py = bb.release();

        bbb->input_wires() = { px->output_wire(), py->output_wire() };

        // Remember to release variables too
        release_variable(px);
        release_variable(py);
        
        return bbb;
    }

    template <IsZKPExpr Expr>
    auto eval(Expr&& expr) { return expr.force(*this); }

    // Helper
    // ------------------------------------------------------------
    template <typename Op> struct witness_selector { };
    template <IsU64Op Op>   struct witness_selector<Op> {
        using type = u64_witness_type;
    };
    template <IsFieldOp Op> struct witness_selector<Op> {
        using type = field_witness_type;
    };

    template <typename Op>
    using witness_selector_t = typename witness_selector<Op>::type;

    // Addition
    // ------------------------------------------------------------
    template <IsAddOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op op, const T& x, const V& y) {
        auto z = make_witness<witness_selector_t<Op>>();
        auto r = generate_randomness();
        
        z.val() = eval(op, r, x, y);

        append_randomness(*z, -r);
        return z;
    }

    template <IsAddOp Op, typename R, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op, const R& r, const T& expr_x, const V& expr_y) {
        auto x = expr_x.force(*this, r);
        auto y = expr_y.force(*this, r);

        return x + y;
    }

    
    // Addition with Constant
    // ------------------------------------------------------------
    template <IsAddConstOp Op, IsZKPExpr T>
    auto eval(Op op, const T& x, const zkp_constant& k) {
        auto z = make_witness<witness_selector_t<Op>>();
        auto r = generate_randomness();
        
        z.val() = eval_addc(op, r, x, k);
        append_randomness(*z, -r);
        return z;
    }

    template <IsAddConstOp Op, IsZKPExpr T>
    auto eval(Op, const bignum_type& r, const T& expr, const zkp_constant& k) {
        auto x = expr.force(*this, r);

        auto kv = mpz_promote(k.val);
        append_const_sum(r * kv);

        return x + k.val;
    }


    // Subtraction
    // ------------------------------------------------------------

    /* ------------------------------------------------------------ *
     * IMPORTANT: For subtract, It has to be in such form:
     *   Z   =   X    -    Y
     *  -r      +r        -r
     * Otherwise the randomness's sign won't be correct in nested expression.
     * e.g. (a - (b - c))
     * ------------------------------------------------------------ */
    template <IsSubOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op op, const T& x, const V& y) {
        auto z = make_witness<witness_selector_t<Op>>();
        auto r = generate_randomness();
        
        z.val() = eval(op, r, x, y);
        append_randomness(*z, -r);
        return z;
    }

    template <IsSubOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op, const bignum_type& r, const T& expr_x, const V& expr_y) {
        auto x = expr_x.force(*this, r);
        auto y = expr_y.force(*this, -r);

        return x - y;
    }


    // Subtraction with Constant
    // ------------------------------------------------------------
    template <IsSubConstOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op op, const T& x, const V& y) {
        auto z = make_witness<witness_selector_t<Op>>();
        auto r = generate_randomness();

        z.val() = eval(op, r, x, y);
        append_randomness(*z, -r);
        return z;
    }

    template <IsSubConstOp Op, IsZKPExpr T>
    auto eval(Op, const bignum_type& r, const T& expr, const zkp_constant& k) {
        auto x = expr.force(*this, r);

        auto kv = mpz_promote(k.val);
        append_const_sum(-r * kv);
        return x - k.val;
    }

    template <IsSubConstOp Op, IsZKPExpr T>
    auto eval(Op, const bignum_type& r, const zkp_constant& k, const T& expr) {
        auto kv = mpz_promote(k.val);
        append_const_sum(r * kv);
        
        auto x = expr.force(*this, -r);
        return k.val - x;
    }


    // Multiplication
    // ------------------------------------------------------------
    template <IsMulOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op, const T& expr_x, const V& expr_y) {
        auto x = eval(expr_x);
        auto y = eval(expr_y);
        
        return make_multiply(std::move(x), std::move(y));
    }

    template <IsMulOp Op, IsZKPExpr T, IsZKPExpr V>
    auto eval(Op op, const bignum_type& r, const T& expr_x, const V& expr_y) {
        auto z = eval(op, expr_x, expr_y);
        append_randomness(*z, r);
        
        return z.val();
    }


    // Multiplication with Constant
    // ------------------------------------------------------------
    template <IsMulConstOp Op, IsZKPExpr T>
    auto eval(Op op, const T& x, const zkp_constant& k) {
        auto z = make_witness<witness_selector_t<Op>>();
        auto r = generate_randomness();

        z.val() = eval(op, r, x, k);
        append_randomness(*z, -r);
        return z;
    }

    template <IsMulConstOp Op, IsZKPExpr T>
    auto eval(Op, const bignum_type& r, const T& expr, const zkp_constant& k) {
        auto kv = mpz_promote(k.val);
        auto x = expr.force(*this, r * kv);
        return x * k.val;
    }


    // Division
    // ------------------------------------------------------------
    // template <IsZKPExpr T, IsZKPExpr V>
    // auto eval(zkp_ops::u64_div, const T& expr_x, const V& expr_y) {
    //     auto x = eval(expr_x);
    //     auto y = eval(expr_y);

    //     auto q = acquire_u64_witness();
    //     auto r = acquire_u64_witness();

    //     q.val() = x.val() / y.val();
    //     r.val() = x.val() % y.val();

    //     auto z = eval(q * y + r);
    //     build_equal(x, z);
    //     return q;
    // }

    // template <IsZKPExpr T, IsZKPExpr V>
    // auto eval(zkp_ops::field_div, const T& expr_x, const V& expr_y) {
    //     auto x = eval(expr_x);
    //     auto y = eval(expr_y);

    //     auto y_inv = mod_inv(y);

    //     return eval(x * y_inv);
    // }

    // template <IsDivOp Op, IsZKPExpr T, IsZKPExpr V>
    // auto eval(Op op, const bignum_type& r, const T& expr_x, const V& expr_y) {
    //     auto q = eval(op, expr_x, expr_y);
    //     append_randomness(*q, r);

    //     return q;
    // }

    field_witness_type mod_inv(const field_witness_type& x) {
        auto x_inv = make_witness<field_witness_type>();
        x_inv.val() = x.val().inv();
        
        auto one = eval(x * x_inv);
        assert_const(one, 1u);
        
        return x_inv;
    }

    // u64_witness_type mod_inv(const u64_witness_type& x) {
    //     u64_witness_type x_inv = acquire_u64_witness();
    //     u64_witness_type one   = make_const(1u);
    //     x_inv.val() = x.val().inv();
        
    //     commit_quadratic(std::move(one), duplicate(x), std::move(x_inv));
    //     return x_inv;
    // }

    std::pair<u64_witness_type, u64_witness_type>
    divide_qr(const u64_witness_type& x, const u64_witness_type& y) {
        u64_witness_type q = acquire_u64_witness();
        u64_witness_type r = acquire_u64_witness();

        q.val() = x.val() / y.val();
        r.val() = x.val() % y.val();

        auto z = eval(q * y + r);
        build_equal(x, z);

        return std::make_pair(std::move(q), std::move(r));
    }

    template <IsWitness Wit>
    std::vector<Wit> bit_decompose(Wit& x, size_t from_bits, size_t to_bits) {
        std::vector<Wit> bits;

        bignum_type val_rand;

        if constexpr(RandomDist::enabled) {
            val_rand = generate_randomness();
            append_randomness(*x, -val_rand);
        }
        
        auto val = x.val();
        for (size_t i = 0; i < from_bits; i++) {
            auto bit = (val >> i) & 1;
            auto wit = make_witness<Wit>();
            wit->val() = bit;
            
            auto b = make_bit(std::move(wit));
            append_randomness(*b, val_rand << i);

            if (i < to_bits) {
                bits.emplace_back(std::move(b));
            }
        }

        return bits;
    }

    template <typename Iter>
    typename std::iterator_traits<Iter>::value_type
    bit_compose(Iter begin, Iter end, size_t offset = 0) {
        bignum_type val_rand;
        auto acc = make_witness<typename std::iterator_traits<Iter>::value_type>();

        size_t i = offset;
        for (auto it = begin; it != end; ++it, ++i) {
            auto v = it->val() << i;
            acc.val() += v;

            if constexpr(RandomDist::enabled) {
                for (size_t n = 0; n < params::num_linear_test; n++) {
                    if (i == offset) {
                        val_rand = generate_randomness();
                        append_randomness(*acc, -val_rand);
                    }

                    append_randomness(**it, val_rand << i);
                }
            }
        }

        return acc;
    }

    template <IsZKPExpr T, IsZKPExpr V>
    auto bitwise_xor(const T& x, const V& y) {
        return eval(x + y - 2u * x * y);
    }

    template <IsZKPExpr T, IsZKPExpr V>
    auto bitwise_xnor(const T& x, const V& y) {
        return eval((x + 1 - y) * (1 - x + y));
        // return eval(1 - x - y + 2u * x * y);
    }

    template <IsWitness Wit>
    Wit bitwise_eq(Wit& x, Wit& y, size_t num_bits) {
        auto xbits = bit_decompose(x, num_bits, num_bits);
        auto ybits = bit_decompose(y, num_bits, num_bits);

        auto iacc = bitwise_xnor(xbits[0], ybits[0]);
        
        for (size_t i = 1; i < num_bits; i++) {
            iacc = eval(iacc * bitwise_xnor(xbits[i], ybits[i]));
        }
        
        return iacc;
    }

    template <IsWitness Wit>
    std::pair<Wit, Wit> bitwise_gt(Wit& x, Wit& y, size_t num_bits, bool sign) {
        auto xbits = bit_decompose(x, num_bits, num_bits);
        auto ybits = bit_decompose(y, num_bits, num_bits);

        const size_t msb = num_bits - 1;

        u64_witness_type acc, iacc;
        
        if (sign) {
            acc = eval((1ULL - xbits[msb]) * ybits[msb]);
        }
        else {
            acc = eval(xbits[msb] * (1ULL - ybits[msb]));
        }
       
        iacc = bitwise_xnor(xbits[msb], ybits[msb]);
        
        for (int i = msb - 1; i >= 0; i--) {
            auto neq = bitwise_xnor(xbits[i], ybits[i]);

            acc  = eval(acc + iacc * xbits[i] * (1ULL - ybits[i]));
            iacc = eval(iacc * neq);
        }

        std::cout << "gt: " << acc.val() << std::endl;

        return { std::move(acc), std::move(iacc) };
    }


    void finalize() {

        if (!linear_.val.empty()) {
            linear_.val.resize(packing_size_);

            for (size_t i = 0; i < params::num_linear_test; i++) {
                linear_.random[i].resize(packing_size_);
            }

            on_linear_(linear_);
        }

        if (!quad_l_.val.empty()) {
            num_rows_++;

            quad_l_.val.resize(packing_size_);
            quad_r_.val.resize(packing_size_);
            quad_o_.val.resize(packing_size_);

            for (size_t i = 0; i < params::num_linear_test; i++) {
                quad_l_.random[i].resize(packing_size_);
                quad_r_.random[i].resize(packing_size_);
                quad_o_.random[i].resize(packing_size_);
            }

            on_quad_(quad_l_, quad_r_, quad_o_);
            
        }

        // std::cout << "Num Linear constraints:             "
        //           << num_linear_constraints_ << std::endl;
        // std::cout << "Num quadratic constraints:          "
        //           << num_constraints_ << std::endl;
        // std::cout << "Num quadratic constraints (padded): "
        //           << num_rows_ * packing_size_ << std::endl;
    }

protected:
    size_t packing_size_, padded_size_;
    RandomDist& dist_;
    
    row_type linear_;
    row_type quad_l_, quad_r_, quad_o_;

    size_t num_linear_constraints_ = 0, num_constraints_ = 0, num_rows_ = 0;

    std::function<void(row_type&)> on_linear_;
    std::function<void(row_type&, row_type&, row_type&)> on_quad_;

    std::array<bignum_type, params::num_linear_test> const_sums_ = { 0 };
    // std::unordered_map<u64, ref_type> const_map_;

    static constexpr size_t pool_alloc_size_ = 1024;
    std::deque<u64_ext_type*> variable_pool_;
};



template <IsU64Expr Op1, IsU64Expr Op2>
auto operator+(const Op1& op1, const Op2& op2) {
    return u64_expr(zkp_ops::u64_add{}, op1, op2);
}

template <IsU64Expr Op>
auto operator+(const Op& op, u64 v) {
    return u64_expr(zkp_ops::u64_addc{}, op, zkp_constant(v));
}

template <IsU64Expr Op>
auto operator+(u64 v, const Op& op) {
    return u64_expr(zkp_ops::u64_addc{}, op, zkp_constant(v));
}

// ------------------------------

template <IsFieldExpr Op1, IsFieldExpr Op2>
auto operator+(const Op1& op1, const Op2& op2) {
    return field_expr(zkp_ops::field_add{}, op1, op2);
}

template <IsFieldExpr Op>
auto operator+(const Op& op, u64 v) {
    return field_expr(zkp_ops::field_addc{}, op, zkp_constant(v));
}

template <IsFieldExpr Op>
auto operator+(u64 v, const Op& op) {
    return field_expr(zkp_ops::field_addc{}, op, zkp_constant(v));
}

// ------------------------------------------------------------

template <IsU64Expr Op1, IsU64Expr Op2>
auto operator-(const Op1& op1, const Op2& op2) {
    return u64_expr(zkp_ops::u64_sub{}, op1, op2);
}

template <IsU64Expr Op>
auto operator-(const Op& op, u64 v) {
    return u64_expr(zkp_ops::u64_subc{}, op, zkp_constant(v));
}

template <IsU64Expr Op>
auto operator-(u64 v, const Op& op) {
    return u64_expr(zkp_ops::u64_subc{}, zkp_constant(v), op);
}

// ------------------------------

template <IsFieldExpr Op1, IsFieldExpr Op2>
auto operator-(const Op1& op1, const Op2& op2) {
    return field_expr(zkp_ops::field_sub{}, op1, op2);
}

template <IsFieldExpr Op>
auto operator-(const Op& op, u64 v) {
    return field_expr(zkp_ops::field_subc{}, op, zkp_constant(v));
}

template <IsFieldExpr Op>
auto operator-(u64 v, const Op& op) {
    return field_expr(zkp_ops::field_subc{}, zkp_constant(v), op);
}

// ------------------------------------------------------------

template <IsU64Expr Op1, IsU64Expr Op2>
auto operator*(const Op1& op1, const Op2& op2) {
    return u64_expr(zkp_ops::u64_mul{}, op1, op2);
}

template <IsU64Expr Op>
auto operator*(const Op& op, u64 v) {
    return u64_expr(zkp_ops::u64_mulc{}, op, zkp_constant(v));
}

template <IsU64Expr Op>
auto operator*(u64 v, const Op& op) {
    return u64_expr(zkp_ops::u64_mulc{}, op, zkp_constant(v));
}

// ------------------------------

template <IsFieldExpr Op1, IsFieldExpr Op2>
auto operator*(const Op1& op1, const Op2& op2) {
    return field_expr(zkp_ops::field_mul{}, op1, op2);
}

template <IsFieldExpr Op>
auto operator*(const Op& op, u64 v) {
    return field_expr(zkp_ops::field_mulc{}, op, zkp_constant(v));
}

template <IsFieldExpr Op>
auto operator*(u64 v, const Op& op) {
    return field_expr(zkp_ops::field_mulc{}, op, zkp_constant(v));
}

// ------------------------------------------------------------

template <IsU64Expr Op1, IsU64Expr Op2>
auto operator/(const Op1& op1, const Op2& op2) {
    return u64_expr(zkp_ops::u64_div{}, op1, op2);
}

template <IsU64Expr Op>
auto operator/(const Op& op, u64 v) {
    return u64_expr(zkp_ops::u64_div{}, op, zkp_constant(v));
}

template <IsU64Expr Op>
auto operator/(u64 v, const Op& op) {
    return u64_expr(zkp_ops::u64_div{}, zkp_constant(v), op);
}

// ------------------------------

template <IsFieldExpr Op1, IsFieldExpr Op2>
auto operator/(const Op1& op1, const Op2& op2) {
    return field_expr(zkp_ops::field_div{}, op1, op2);
}

template <IsFieldExpr Op>
auto operator/(const Op& op, u64 v) {
    return field_expr(zkp_ops::field_div{}, op, zkp_constant(v));
}

template <IsFieldExpr Op>
auto operator/(u64 v, const Op& op) {
    return field_expr(zkp_ops::field_div{}, zkp_constant(v), op);
}


}  // namespace ligero::vm::zkp
