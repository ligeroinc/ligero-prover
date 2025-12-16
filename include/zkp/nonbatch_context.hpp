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

#include <array>
#include <random>
#include <span>
#include <unordered_map>

#include <zkp/random.hpp>
#include <zkp/merkle_tree.hpp>
#include <zkp/backend/core.hpp>
#include <host_modules/host_interface.hpp>
#include <util/mpz_get.hpp>
#include <util/mpz_vector.hpp>
#include <ligetron/webgpu/buffer_binding.hpp>

#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/unordered_map.hpp>

namespace ligero::vm::zkp {

enum class context_role : uint8_t {
    prover = 1,
    verifier
};

struct stage1_random_policy {
    static constexpr bool pad_encoding_random    = true;
    static constexpr bool enable_code_check      = false;
    static constexpr bool enable_linear_check    = false;
    static constexpr bool enable_quadratic_check = false;
};

struct stage2_random_policy {
    static constexpr bool pad_encoding_random    = true;
    static constexpr bool enable_code_check      = true;
    static constexpr bool enable_linear_check    = true;
    static constexpr bool enable_quadratic_check = true;
};

struct stage3_random_policy {
    static constexpr bool pad_encoding_random    = true;
    static constexpr bool enable_code_check      = false;
    static constexpr bool enable_linear_check    = false;
    static constexpr bool enable_quadratic_check = false;
};

struct verifier_random_policy {
    static constexpr bool pad_encoding_random    = false;
    static constexpr bool enable_code_check      = true;
    static constexpr bool enable_linear_check    = true;
    static constexpr bool enable_quadratic_check = true;
};


template <typename Field, typename Executor, typename RandomPolicy>
struct nonbatch_context_base {
    using field_type = Field;
    using backend_type = ligetron_backend<field_type, RandomPolicy>;
    using witness_row_type = typename backend_type::witness_row_type;
    using witness_type = managed_witness;

    using stack_value_type = stack_value;
    using frame_type = wasm_frame;

    nonbatch_context_base(Executor& exe)
        : executor_(exe),
          backend_(exe.message_size(), exe.padding_size())
        {
            backend_.manager().register_linear_callback([this](auto row) {
                return linear_callback(row);
            }).register_quadratic_callback([this](auto... rows) {
                return quadratic_callback(rows...);
            }).register_mask_callback([this](auto&... rows) {
                return mask_callback(rows...);
            });
        }

    virtual ~nonbatch_context_base() = default;

    nonbatch_context_base(const nonbatch_context_base&) = delete;
    nonbatch_context_base& operator=(const nonbatch_context_base&) = delete;

    nonbatch_context_base(nonbatch_context_base&&) = delete;
    nonbatch_context_base& operator=(nonbatch_context_base&&) = delete;

    template <typename... Args>
    nonbatch_context_base& init_encoding_random(Args&&... args) {
        backend_.manager().encoding_random_engine().init(std::forward<Args>(args)...);
        return *this;
    }

    template <typename... Args>
    nonbatch_context_base& init_witness_random(Args&&... args) {
        /** Initialize random generator to the same seed, but keep them separate */
        backend_.manager().code_random_engine().init(std::forward<Args>(args)...);
        backend_.manager().linear_random_engine().init(std::forward<Args>(args)...);
        backend_.manager().quadratic_random_engine().init(std::forward<Args>(args)...);
        return *this;
    }

    void stack_push(stack_value_type val) {
        stack_.push_back(std::move(val));
    }

    stack_value_type stack_pop() {
        assert(!stack_.empty());
        stack_value_type top = std::move(stack_.back());
        stack_.pop_back();
        return top;
    }

    stack_value_type& stack_peek() {
        return stack_.back();
    }

    void drop_n_below(size_t n, size_t pos = 0) {
        auto it = stack_.rbegin() + pos;
        auto begin = (it + n).base();
        auto end = it.base();

        for (auto iter = begin; iter != end; ++iter) {
            destroy_value(std::move(*iter));
        }

        stack_.erase((it + n).base(), it.base());
    }

    auto make_frame() const { return std::make_unique<frame_type>(); }

    frame_type* current_frame() const {
        return frames_.back();
    }

    void set_current_frame(frame_type *f) {
        frames_.emplace_back(f);
    }

    // void pop_frame() { frames_.pop_back(); }

    void block_entry(u32 param, u32 ret) {
        stack_.insert((stack_.rbegin() + param).base(), label_t{ ret });
    }

    store_t* store() { return store_; }
    void store(store_t *s) { store_ = s; }

    module_instance* module() { return module_; }
    void module(module_instance *mod) { module_ = mod; }

    template <typename T>
    T memory_load(address_t u8_offset) {
        T storage;
        std::memcpy(&storage, memory_data().data() + u8_offset, sizeof(T));
        return storage;
    }

    template <typename T> requires std::is_trivially_copyable_v<T>
    void memory_store(address_t u8_offset, const T& val, size_t size = sizeof(T)) {
        std::memcpy(memory_data().data() + u8_offset, &val, size);
    }

    memory_instance& memory() {
        return store_->memorys[module_->memaddrs[0]];
    }

    const memory_instance& memory() const {
        return store_->memorys[module_->memaddrs[0]];
    }

    std::span<u8> memory_data() {
        auto& buf = memory().data;
        return { buf.data(), buf.size() };
    }

    const std::span<const u8> memory_data() const {
        auto& buf = memory().data;
        return { buf.data(), buf.size() };
    }

    template <typename Module, typename... Args>
    void add_host_module(Args&&... args) {
        auto ptr = std::make_unique<Module>(std::forward<Args>(args)...);
        ptr->initialize();
        module_map_[Module::module_name] = ptr.get();
        host_module_.push_back(std::move(ptr));
    }

    exec_result call_host(address_t addr, std::string module_name, std::string func) {
        // std::cout << "call: " << addr << std::endl;
        if (!module_map_.contains(module_name)) {
            std::cerr << std::format("ERROR: Could not load module {}, aborting!", module_name) << std::endl;
            return exec_exit{ .exit_code = -1 };
        }
        return module_map_[module_name]->call_host(addr, func);
    }

    auto stack_bottom() { return stack_.rend(); }
    auto stack_top() { return stack_.rbegin(); }

    void show_stack() const {
        std::cout << "stack: ";
        for (const auto& v : stack_) {
            std::cout << v.to_string() << " ";
        }
        std::cout << std::endl;
    }

    void dump_memory(size_t start, size_t count) const {
        auto& data = store_->memorys[module_->memaddrs[0]].data;

        const size_t bytes_per_row = 16;
        for (size_t i = start; i < start + count; i += bytes_per_row) {
            std::cout << std::setw(8) << std::setfill('0') << std::hex << i << "  ";
            for (size_t j = 0; j < bytes_per_row && i + j < data.size(); ++j) {
                std::cout << std::setw(2) << std::setfill('0') << std::hex
                          << static_cast<int>(data[i + j]) << ' ';
            }
            std::cout << '\n';
        }
        std::cout << std::dec; // restore decimal output
    }

    // ------------------------------------------------------------

    void destroy_value(stack_value_type val) {
        if (val.is_frame()) {
            this->frames_.pop_back();   // Adjust current frame pointer

            // auto *f = val.frame();
            // for (auto& local : f->locals) {
            //     destroy_value(std::move(local));
            // }
        }
    }

    native_numeric make_numeric(stack_value_type s) {
        return std::visit(prelude::overloaded {
                [](native_numeric&& v) {
                    return std::move(v);
                },
                [](witness_type&& wit) {
                    // std::cout << "Warning: coercing witness value" << std::endl;
                    return native_numeric{ wit.as_u64() };
                },
                [&](decomposed_bits&& bits) {
                    // std::cout << "Warning: coercing witness  bit vector" << std::endl;
                    mpz_class *out = backend_.manager().acquire_mpz();
                    backend_.bit_compose_constant(*out, bits);

                    // Properly extract all 64-bits regardless of platform.
                    native_numeric ret { mpz_get_u64(*out) };

                    backend_.manager().recycle_mpz(out);
                    return ret;
                },
                [](auto&& x) -> native_numeric {
                    throw wasm_trap("Unexpected stack value");
                }
                }, std::move(s.data()));
    }

    witness_type make_witness(stack_value_type s) {
        return std::visit(prelude::overloaded {
                [this](native_numeric&& v) {
                    auto x = backend_.acquire_witness();
                    switch (v.type()) {
                        case native_numeric::i32:
                            x.val(v.as_u32()); break;
                        case native_numeric::i64:
                            x.val(v.as_u64()); break;
                        default:
                            throw wasm_trap("Unexpected numeric");
                    }
                    return x;
                },
                [](witness_type&& wit) {
                    return std::move(wit);
                },
                [this](decomposed_bits&& bits) {
                    return backend_.bit_compose(bits);
                },
                [](auto&& x) -> witness_type {
                    throw wasm_trap("Unexpected stack value");
                }
            }, std::move(s.data()));
    }

    decomposed_bits make_decomposed(stack_value_type s, size_t bits) {
        return std::visit(prelude::overloaded {
                [&](native_numeric&& v) {
                    return backend_.bit_decompose_constant(v.as_u64(), bits);
                },
                [&](witness_type&& wit) {
                    return backend_.bit_decompose(wit, bits);
                },
                [](decomposed_bits&& bits) {
                    return std::move(bits);
                },
                [](auto&& x) -> decomposed_bits {
                    throw wasm_trap("Unexpected stack value");
                }
            }, std::move(s.data()));
    }

    stack_value_type duplicate(stack_value_type& s) {
        return std::visit(prelude::overloaded {
                [](native_numeric& v) {
                    return stack_value_type{ v };
                },
                [](reference_t& ref) {
                    return stack_value_type{ ref };
                },
                [&](witness_type& wit) {
                    return stack_value_type{ backend_.duplicate(wit) };
                },
                [&](decomposed_bits& bits) {
                    return stack_value_type{ backend_.bit_compose(bits) };
                },
                [](auto& x) -> stack_value_type {
                    throw wasm_trap("Unexpected stack value");
                }
            }, s.data());
    }

    auto& backend() { return backend_; }

    virtual void linear_callback(witness_row_type row) = 0;

    virtual void quadratic_callback(witness_row_type x,
                                    witness_row_type y,
                                    witness_row_type z) = 0;

    virtual void mask_callback(mpz_vector& code,
                               mpz_vector& linear,
                               mpz_vector& quadratic) = 0;

    virtual void finalize() {
        for (auto& m : this->host_module_) {
            m->finalize();
        }

        backend_.finalize();
    }

    // template <typename Expr>
    // auto eval(Expr&& expr) { return expr.eval(backend_); }

    // auto& encoder() { return encoder_; }
    // const auto& encoder() const { return encoder_; }
    auto& executor() { return executor_; }

    // auto& encode_randomness() { return dist_; }

    mpz_class linear_sums() const {
        return backend_.manager().constsum();
    }

public:
    size_t linear_count = 0, quad_count = 0;

    // Stack operations
protected:
    store_t *store_ = nullptr;
    module_instance *module_ = nullptr;
    std::vector<frame_type*> frames_;
    std::vector<stack_value_type> stack_;

    std::unordered_map<std::string, host_module*> module_map_;
    std::vector<std::unique_ptr<host_module>> host_module_;

    // Zero-knowledge related
protected:
    Executor& executor_;
    backend_type backend_;
};

// Stage 1 (Merkle Tree)
/* ------------------------------------------------------------ */
template <typename Field, typename Executor, typename RandomPolicy, typename Hasher = sha256>
struct nonbatch_stage1_context
    : public nonbatch_context_base<Field, Executor, RandomPolicy> {

    using Base = nonbatch_context_base<Field, Executor, RandomPolicy>;
    using typename Base::field_type;
    using typename Base::witness_row_type;
    using typename Base::stack_value_type;
    using typename Base::frame_type;
    using Base::executor_;

    using executor_t = Executor;
    using buffer_t = typename Executor::buffer_type;
    using digest_type = typename Hasher::digest;

    static constexpr context_role role = context_role::prover;

    nonbatch_stage1_context(Executor& exe)
        : Base(exe)
        {
            executor_.sha256_init(executor_.encoding_size());

            batch_randomness_.resize(params::sample_size);
            limbs_.resize(2 * this->executor().padding_size() * field_type::num_u64_limbs);

            device_x_ = exe.make_codeword_buffer();
            device_y_ = exe.make_codeword_buffer();
            device_z_ = exe.make_codeword_buffer();

            size_t num_element = exe.encoding_size();
            size_t buffer_size = num_element * sizeof(digest_type);

            sha256_context_    = exe.make_device_buffer(executor_.encoding_size() * sizeof(typename Executor::sha256_context));
            sha256_digest_     = exe.make_device_buffer(buffer_size);

            bind_ntt_x_ = exe.bind_ntt(device_x_);
            bind_ntt_y_ = exe.bind_ntt(device_y_);
            bind_ntt_z_ = exe.bind_ntt(device_z_);

            bind_sha256_ctx_ = exe.bind_sha256_context(sha256_context_, sha256_digest_);
            bind_sha256_x_   = exe.bind_sha256_buffer(device_x_);
            bind_sha256_y_   = exe.bind_sha256_buffer(device_y_);
            bind_sha256_z_   = exe.bind_sha256_buffer(device_z_);

            // Initialize SHA256 context
            // --------------------------------------------------
            executor_.sha256_digest_init(bind_sha256_ctx_);
        }

    ~nonbatch_stage1_context() {
        
    }

    void linear_callback(witness_row_type row) override {
        auto [val, _] = row;
        val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
    }

    void quadratic_callback(witness_row_type x, witness_row_type y, witness_row_type z) override {
        auto [x_val, x_rand] = x;
        x_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);

        auto [y_val, y_rand] = y;
        y_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);

        auto [z_val, z_rand] = z;
        z_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_z_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);
    }

    void mask_callback(mpz_vector& code, mpz_vector& linear, mpz_vector& quad) override {
        const size_t K = this->executor().padding_size();

        assert(code.size() == K);
        code.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);

        assert(linear.size() == 2 * K);
        linear.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_y_);
        this->executor().ntt_forward_n(bind_ntt_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);

        assert(quad.size() == 2 * K);
        quad.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_z_);
        this->executor().ntt_forward_n(bind_ntt_z_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);
    }

    void on_batch_init(buffer_t& x) {
        batch_randomness_.clear();
        this->backend().manager().pad_encoding_random(batch_randomness_, params::sample_size);

        batch_randomness_.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer(
                                      x.slice(this->executor().message_size() * Executor::device_bignum_type::num_bytes),
            limbs_.data(),
            params::sample_size * Field::num_u64_limbs);

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
    }

    void on_batch_bit(buffer_t& x) {
        ++num_mul_gates_;

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
    }

    void on_batch_equal(buffer_t& x, buffer_t& y) {
        ++num_equal_gates_;

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().copy_buffer_clear(y, device_y_);

        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().encode_ntt_device(bind_ntt_y_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);
    }

    void on_batch_quadratic(buffer_t& x, buffer_t& y, buffer_t& z) {
        ++num_mul_gates_;

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);

        this->executor().copy_buffer_clear(z, device_z_);
        this->executor().encode_ntt_device(bind_ntt_z_);

        if (x == y) {
            this->executor().copy_buffer_to_buffer(device_x_, device_y_);
        }
        else {
            this->executor().copy_buffer_clear(y, device_y_);
            this->executor().encode_ntt_device(bind_ntt_y_);
        }

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);
    }

    std::vector<digest_type> flush_digests() {
        this->executor().sha256_digest_final(bind_sha256_ctx_);
        return this->executor().template copy_to_host<digest_type>(sha256_digest_);
    }

    void finalize() override {
        Base::finalize();

        std::cout << std::format("Num Batch Equal Gates:              {}", num_equal_gates_)
                  << std::endl
                  << std::format("Num Batch Multiply Gates:           {}", num_mul_gates_)
                  << std::endl;
    }

protected:
    mpz_vector batch_randomness_;
    std::vector<uint64_t> limbs_;

    size_t num_equal_gates_ = 0, num_mul_gates_ = 0;

    buffer_t device_x_, device_y_, device_z_;
    buffer_t sha256_context_, sha256_digest_;

    webgpu::buffer_binding bind_ntt_x_, bind_ntt_y_, bind_ntt_z_;
    webgpu::buffer_binding bind_sha256_ctx_;
    webgpu::buffer_binding bind_sha256_x_, bind_sha256_y_, bind_sha256_z_;
};


// Stage 2 (code test, linear test, qudratic test)
/* ------------------------------------------------------------ */
template <typename Field, typename Executor, typename RandomPolicy>
struct nonbatch_stage2_context : public nonbatch_context_base<Field, Executor, RandomPolicy> {
    using Base = nonbatch_context_base<Field, Executor, RandomPolicy>;
    using typename Base::field_type;
    using typename Base::witness_row_type;
    using typename Base::stack_value_type;
    using typename Base::frame_type;

    using executor_t = Executor;
    using buffer_t = typename Executor::buffer_type;

    static constexpr context_role role = context_role::prover;

    nonbatch_stage2_context(Executor& exe)
        : Base(exe)
        {
            batch_randomness_.resize(params::sample_size);
            limbs_.resize(2 * this->executor().padding_size() * field_type::num_u64_limbs);

            code_   = exe.make_codeword_buffer();
            linear_ = exe.make_codeword_buffer();
            quad_   = exe.make_codeword_buffer();

            tmp1_ = exe.make_codeword_buffer();
            tmp2_ = exe.make_codeword_buffer();

            device_x_      = exe.make_codeword_buffer();
            device_y_      = exe.make_codeword_buffer();
            device_z_      = exe.make_codeword_buffer();
            device_rand_x_ = exe.make_codeword_buffer();
            device_rand_y_ = exe.make_codeword_buffer();
            device_rand_z_ = exe.make_codeword_buffer();

            // Bindings
            // --------------------------------------------------
            bind_ntt_x_ = exe.bind_ntt(device_x_);
            bind_ntt_y_ = exe.bind_ntt(device_y_);
            bind_ntt_z_ = exe.bind_ntt(device_z_);

            bind_ntt_rand_x_ = exe.bind_ntt(device_rand_x_);
            bind_ntt_rand_y_ = exe.bind_ntt(device_rand_y_);
            bind_ntt_rand_z_ = exe.bind_ntt(device_rand_z_);

            bind_code_check_x_ = exe.bind_eltwise2(device_x_, code_);
            bind_code_check_y_ = exe.bind_eltwise2(device_y_, code_);
            bind_code_check_z_ = exe.bind_eltwise2(device_z_, code_);

            bind_linear_check_x_ = exe.bind_eltwise3(device_x_, device_rand_x_, linear_);
            bind_linear_check_y_ = exe.bind_eltwise3(device_y_, device_rand_y_, linear_);
            bind_linear_check_z_ = exe.bind_eltwise3(device_z_, device_rand_z_, linear_);

            bind_quadratic_check_mul_ = exe.bind_eltwise3(device_x_, device_y_, tmp1_);
            bind_quadratic_check_sub_ = exe.bind_eltwise3(tmp1_, device_z_, tmp2_);
            bind_quadratic_check_fma_ = exe.bind_eltwise2(tmp2_, quad_);

            bind_linear_mask_y_    = exe.bind_eltwise2(device_y_, linear_);
            bind_quadratic_mask_z_ = exe.bind_eltwise2(device_z_, quad_);

            // Batch bindings
            // --------------------------------------------------
            bind_batch_equal_sub_ = exe.bind_eltwise3(device_x_, device_y_, tmp1_);
            bind_batch_equal_fma_ = exe.bind_eltwise2(tmp1_, quad_);
        }

    ~nonbatch_stage2_context() {

    }

    void linear_callback(witness_row_type row) override {
        auto [val, rand] = row;

        val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());

        rand.export_limbs(limbs_.data(),
                           limbs_.size(),
                           sizeof(uint64_t),
                           field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_x_, limbs_.data(), limbs_.size());

        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().encode_ntt_device(bind_ntt_rand_x_);

        check_code(bind_code_check_x_);
        check_linear(bind_linear_check_x_);
    }

    void quadratic_callback(witness_row_type x, witness_row_type y, witness_row_type z) override {
        auto [x_val, x_rand] = x;
        auto [y_val, y_rand] = y;
        auto [z_val, z_rand] = z;

        x_val.export_limbs(limbs_.data(),
                           limbs_.size(),
                           sizeof(uint64_t),
                           field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());

        x_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_x_, limbs_.data(), limbs_.size());

        y_val.export_limbs(limbs_.data(),
                           limbs_.size(),
                           sizeof(uint64_t),
                           field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());

        y_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_y_, limbs_.data(), limbs_.size());

        z_val.export_limbs(limbs_.data(),
                           limbs_.size(),
                           sizeof(uint64_t),
                           field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());

        z_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_z_, limbs_.data(), limbs_.size());

        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().encode_ntt_device(bind_ntt_rand_x_);
        this->executor().encode_ntt_device(bind_ntt_y_);
        this->executor().encode_ntt_device(bind_ntt_rand_y_);
        this->executor().encode_ntt_device(bind_ntt_z_);
        this->executor().encode_ntt_device(bind_ntt_rand_z_);

        check_code(bind_code_check_x_);
        check_code(bind_code_check_y_);
        check_code(bind_code_check_z_);

        check_linear(bind_linear_check_x_);
        check_linear(bind_linear_check_y_);
        check_linear(bind_linear_check_z_);

        check_quadratic();
    }

    void mask_callback(mpz_vector& code, mpz_vector& linear, mpz_vector& quad) override {
        const size_t K = this->executor().padding_size();

        assert(code.size() == K);
        code.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().EltwiseAddAssignMod(bind_code_check_x_);

        assert(linear.size() == 2 * K);
        linear.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_y_);
        this->executor().ntt_forward_n(bind_ntt_y_);
        this->executor().EltwiseAddAssignMod(bind_linear_mask_y_);

        assert(quad.size() == 2 * K);
        quad.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_z_);
        this->executor().ntt_forward_n(bind_ntt_z_);
        this->executor().EltwiseAddAssignMod(bind_quadratic_mask_z_);
    }

    void check_code(webgpu::buffer_binding bind) {
        auto *r = this->backend().manager().acquire_mpz();
        for (size_t i = 0; i < params::num_code_test; i++) {
            this->backend().manager().generate_code_random(*r);
            this->executor().EltwiseFMAMod(bind, *r);
        }
        this->backend().manager().recycle_mpz(r);
    }

    void check_linear(webgpu::buffer_binding bind) {
        for (size_t i = 0; i < params::num_linear_test; i++) {
            this->executor().EltwiseFMAMod(bind);
        }
    }

    void check_quadratic() {
        auto *r = this->backend().manager().acquire_mpz();
        this->executor().EltwiseMultMod(bind_quadratic_check_mul_);
        this->executor().EltwiseSubMod(bind_quadratic_check_sub_);
        for (size_t i = 0; i < params::num_quadratic_test; i++) {
            this->backend().manager().generate_quadratic_random(*r);
            this->executor().EltwiseFMAMod(bind_quadratic_check_fma_, *r);
        }
        this->backend().manager().recycle_mpz(r);
    }

    void on_batch_init(buffer_t& x) {
        batch_randomness_.clear();
        this->backend().manager().pad_encoding_random(batch_randomness_, params::sample_size);
        batch_randomness_.export_limbs(limbs_.data(),
                                       limbs_.size(),
                                       sizeof(uint64_t),
                                       field_type::num_u64_limbs);
        this->executor().write_buffer(
                                      x.slice(this->executor().message_size() * Executor::device_bignum_type::num_bytes),
            limbs_.data(),
            params::sample_size * Field::num_u64_limbs);

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);
        check_code(bind_code_check_x_);
    }

    void on_batch_bit(buffer_t& x) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);

        check_code(bind_code_check_x_);

        this->executor().copy_buffer_to_buffer(device_x_, device_y_);
        this->executor().copy_buffer_to_buffer(device_x_, device_z_);

        check_quadratic();
    }

    void on_batch_equal(buffer_t& x, buffer_t& y) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().copy_buffer_clear(y, device_y_);

        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().encode_ntt_device(bind_ntt_y_);

        // Update equality constraint in quadratic test
        this->executor().EltwiseSubMod(bind_batch_equal_sub_);

        auto *r = this->backend().manager().acquire_mpz();
        this->backend().manager().generate_quadratic_random(*r);
        this->executor().EltwiseFMAMod(bind_batch_equal_fma_, *r);
        this->backend().manager().recycle_mpz(r);
    }

    void on_batch_quadratic(buffer_t& x, buffer_t& y, buffer_t& z) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);

        this->executor().copy_buffer_clear(z, device_z_);
        this->executor().encode_ntt_device(bind_ntt_z_);

        if (x == y) {
            this->executor().copy_buffer_to_buffer(device_x_, device_y_);
        }
        else {
            this->executor().copy_buffer_clear(y, device_y_);
            this->executor().encode_ntt_device(bind_ntt_y_);
        }

        check_code(bind_code_check_x_);
        check_code(bind_code_check_y_);
        check_code(bind_code_check_z_);

        check_quadratic();
    }

    buffer_t code()      { return code_;   }
    buffer_t linear()    { return linear_; }
    buffer_t quadratic() { return quad_;   }

protected:
    mpz_vector batch_randomness_;

    std::vector<uint64_t> limbs_;

    buffer_t tmp1_, tmp2_;
    buffer_t code_, linear_, quad_;
    buffer_t device_x_, device_y_, device_z_;
    buffer_t device_rand_x_, device_rand_y_, device_rand_z_;

    webgpu::buffer_binding bind_ntt_x_, bind_ntt_y_, bind_ntt_z_;
    webgpu::buffer_binding bind_ntt_rand_x_, bind_ntt_rand_y_, bind_ntt_rand_z_;
    
    webgpu::buffer_binding bind_code_check_x_, bind_code_check_y_, bind_code_check_z_;
    webgpu::buffer_binding bind_linear_check_x_, bind_linear_check_y_, bind_linear_check_z_;
    webgpu::buffer_binding bind_quadratic_check_mul_, bind_quadratic_check_sub_, bind_quadratic_check_fma_;
    webgpu::buffer_binding bind_linear_mask_y_, bind_quadratic_mask_z_;

    webgpu::buffer_binding bind_batch_equal_sub_, bind_batch_equal_fma_;
};


template <typename Field,
          typename Executor,
          typename RandomPolicy,
          typename OutputArchive>
struct nonbatch_stage3_context
    : public nonbatch_context_base<Field, Executor, RandomPolicy>
{
    using Base = nonbatch_context_base<Field, Executor, RandomPolicy>;
    using typename Base::field_type;
    using typename Base::witness_row_type;
    using typename Base::stack_value_type;
    using typename Base::frame_type;

    using executor_t = Executor;
    using buffer_t = typename Executor::buffer_type;

    static constexpr context_role role = context_role::prover;

    nonbatch_stage3_context(Executor& exe,
                            const std::vector<size_t>& si,
                            OutputArchive& oa)
        : Base(exe),
          sample_index_(si),
          oa_(oa)
        {
            exe.sampling_init(si);

            batch_randomness_.resize(params::sample_size);
            limbs_.resize(2 * this->executor().padding_size() * field_type::num_u64_limbs);

            device_x_ = exe.make_codeword_buffer();
            device_y_ = exe.make_codeword_buffer();
            device_z_ = exe.make_codeword_buffer();

            device_samplings_ = exe.make_device_buffer(
                si.size() *
                Executor::device_bignum_type::num_bytes *
                num_sampling_threshold_);
            
            bind_ntt_x_ = exe.bind_ntt(device_x_);
            bind_ntt_y_ = exe.bind_ntt(device_y_);
            bind_ntt_z_ = exe.bind_ntt(device_z_);

            bind_sample_x_ = exe.bind_sampling(device_x_, device_samplings_);
            bind_sample_y_ = exe.bind_sampling(device_y_, device_samplings_);
            bind_sample_z_ = exe.bind_sampling(device_z_, device_samplings_);
        }

    ~nonbatch_stage3_context() {

    }

    void sync_sample_to_host() {
        const size_t sampling_offset = sampling_count_ * sample_index_.size() * Executor::device_bignum_type::num_bytes;
        auto device_buf = device_samplings_.slice(0, sampling_offset);
        auto host_buf = this->executor().template copy_to_host<u32>(device_buf);

        host_samplings_.insert(host_samplings_.end(), host_buf.cbegin(), host_buf.cend());

        sampling_count_ = 0;
        this->executor().clear_buffer(device_buf);
    }

    void sample_row(webgpu::buffer_binding bind) {
        if (sampling_count_ >= num_sampling_threshold_) {        
            sync_sample_to_host();
        }

        this->executor().sample_gather(bind, sampling_count_);
        ++sampling_count_;
    }

    void linear_callback(witness_row_type row) override {
        auto [val, _] = row;
        val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        sample_row(bind_sample_x_);
    }

    void quadratic_callback(witness_row_type x, witness_row_type y, witness_row_type z) override {
        auto [x_val, x_rand] = x;
        x_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        sample_row(bind_sample_x_);

        auto [y_val, y_rand] = y;
        y_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_y_);
        sample_row(bind_sample_y_);

        auto [z_val, z_rand] = z;
        z_val.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_z_);
        sample_row(bind_sample_z_);
    }

    void mask_callback(mpz_vector& code, mpz_vector& linear, mpz_vector& quad) override {
        const size_t K = this->executor().padding_size();

        assert(code.size() == K);
        code.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_x_, limbs_.data(), limbs_.size());
        this->executor().encode_ntt_device(bind_ntt_x_);
        sample_row(bind_sample_x_);

        assert(linear.size() == 2 * K);
        linear.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_y_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_y_);
        this->executor().ntt_forward_n(bind_ntt_y_);
        sample_row(bind_sample_y_);

        assert(quad.size() == 2 * K);
        quad.export_limbs(limbs_.data(), limbs_.size(), sizeof(uint64_t), field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_z_, limbs_.data(), limbs_.size());
        this->executor().ntt_inverse_2k(bind_ntt_z_);
        this->executor().ntt_forward_n(bind_ntt_z_);
        sample_row(bind_sample_z_);
    }

    void on_batch_init(buffer_t& x) {
        batch_randomness_.clear();
        this->backend().manager().pad_encoding_random(batch_randomness_, params::sample_size);
        batch_randomness_.export_limbs(limbs_.data(),
                                       limbs_.size(),
                                       sizeof(uint64_t),
                                       field_type::num_u64_limbs);
        this->executor().write_buffer(
                                      x.slice(this->executor().message_size() * Executor::device_bignum_type::num_bytes),
            limbs_.data(),
            params::sample_size * Field::num_u64_limbs);

        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);
        sample_row(bind_sample_x_);
    }

    void on_batch_bit(buffer_t& x) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);
        sample_row(bind_sample_x_);
    }

    void on_batch_equal(buffer_t& x, buffer_t& y) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().copy_buffer_clear(y, device_y_);

        this->executor().encode_ntt_device(bind_ntt_x_);
        this->executor().encode_ntt_device(bind_ntt_y_);
        sample_row(bind_sample_x_);
        sample_row(bind_sample_y_);
    }

    void on_batch_quadratic(buffer_t& x, buffer_t& y, buffer_t& z) {
        this->executor().copy_buffer_clear(x, device_x_);
        this->executor().encode_ntt_device(bind_ntt_x_);

        this->executor().copy_buffer_clear(z, device_z_);
        this->executor().encode_ntt_device(bind_ntt_z_);

        if (x == y) {
            this->executor().copy_buffer_to_buffer(device_x_, device_y_);
        }
        else {
            this->executor().copy_buffer_clear(y, device_y_);
            this->executor().encode_ntt_device(bind_ntt_y_);
        }

        sample_row(bind_sample_x_);
        sample_row(bind_sample_y_);
        sample_row(bind_sample_z_);
    }

    void finalize() override {
        Base::finalize();

        sync_sample_to_host();
        oa_ << host_samplings_;
    }

protected:
    std::vector<size_t> sample_index_;
    std::vector<uint64_t> limbs_;
    OutputArchive& oa_;

    buffer_t device_x_, device_y_, device_z_;
    buffer_t device_samplings_;

    mpz_vector batch_randomness_;
    webgpu::buffer_binding bind_ntt_x_, bind_ntt_y_, bind_ntt_z_;
    webgpu::buffer_binding bind_sample_x_, bind_sample_y_, bind_sample_z_;

    const size_t num_sampling_threshold_ = 256;
    size_t sampling_count_ = 0;
    std::vector<uint32_t> host_samplings_;
};





template <typename Field,
          typename Executor,
          typename RandomPolicy,
          typename Hasher,
          typename InputArchive>
struct nonbatch_verifier_context
    : public nonbatch_context_base<Field, Executor, RandomPolicy>
{
    using Base = nonbatch_context_base<Field, Executor, RandomPolicy>;
    using typename Base::field_type;
    using typename Base::witness_row_type;
    using typename Base::stack_value_type;
    using typename Base::frame_type;

    using executor_t  = Executor;
    using builder_t   = typename merkle_tree<Hasher>::template builder<field_type>;
    using digest_type = typename Hasher::digest;
    using buffer_t    = typename Executor::buffer_type;

    static constexpr context_role role = context_role::verifier;

    nonbatch_verifier_context(Executor& exe,
                              const std::vector<size_t>& si,
                              InputArchive& ia)
        : Base(exe), sample_index_(si),
          pop_offset_(0),
          ia_(ia)
        {
            exe.sha256_init(si.size());
            exe.sampling_init(si);

            ia_ >> host_samplings_;

            limbs_.resize(2 * this->executor().padding_size() * field_type::num_u64_limbs);

            code_   = exe.make_sample_buffer();
            linear_ = exe.make_sample_buffer();
            quad_   = exe.make_sample_buffer();

            tmp1_ = exe.make_sample_buffer();
            tmp2_ = exe.make_sample_buffer();

            device_x_ = exe.make_sample_buffer();
            device_y_ = exe.make_sample_buffer();
            device_z_ = exe.make_sample_buffer();

            device_rand_x_ = exe.make_codeword_buffer();
            device_rand_y_ = exe.make_codeword_buffer();
            device_rand_z_ = exe.make_codeword_buffer();

            sample_rand_x_ = exe.make_sample_buffer();
            sample_rand_y_ = exe.make_sample_buffer();
            sample_rand_z_ = exe.make_sample_buffer();

            size_t buffer_size = si.size() * sizeof(digest_type);

            sha256_context_ = exe.make_device_buffer(si.size() * sizeof(typename Executor::sha256_context));
            sha256_digest_  = exe.make_device_buffer(buffer_size);

            // Bindings
            // --------------------------------------------------
            bind_ntt_rand_x_ = exe.bind_ntt(device_rand_x_);
            bind_ntt_rand_y_ = exe.bind_ntt(device_rand_y_);
            bind_ntt_rand_z_ = exe.bind_ntt(device_rand_z_);

            bind_sha256_ctx_ = exe.bind_sha256_context(sha256_context_, sha256_digest_);
            bind_sha256_x_   = exe.bind_sha256_buffer(device_x_);
            bind_sha256_y_   = exe.bind_sha256_buffer(device_y_);
            bind_sha256_z_   = exe.bind_sha256_buffer(device_z_);

            bind_code_check_x_ = exe.bind_eltwise2(device_x_, code_);
            bind_code_check_y_ = exe.bind_eltwise2(device_y_, code_);
            bind_code_check_z_ = exe.bind_eltwise2(device_z_, code_);

            bind_linear_check_x_ = exe.bind_eltwise3(device_x_, sample_rand_x_, linear_);
            bind_linear_check_y_ = exe.bind_eltwise3(device_y_, sample_rand_y_, linear_);
            bind_linear_check_z_ = exe.bind_eltwise3(device_z_, sample_rand_z_, linear_);

            bind_quadratic_check_mul_ = exe.bind_eltwise3(device_x_, device_y_, tmp1_);
            bind_quadratic_check_sub_ = exe.bind_eltwise3(tmp1_, device_z_, tmp2_);
            bind_quadratic_check_fma_ = exe.bind_eltwise2(tmp2_, quad_);

            bind_sample_rand_x_ = exe.bind_sampling(device_rand_x_, sample_rand_x_);
            bind_sample_rand_y_ = exe.bind_sampling(device_rand_y_, sample_rand_y_);
            bind_sample_rand_z_ = exe.bind_sampling(device_rand_z_, sample_rand_z_);

            /// Masking
            /// --------------------------------------------------
            bind_linear_mask_y_    = exe.bind_eltwise2(device_y_, linear_);
            bind_quadratic_mask_z_ = exe.bind_eltwise2(device_z_, quad_);

            // Batch bindings
            // --------------------------------------------------
            bind_batch_equal_sub_ = exe.bind_eltwise3(device_x_, device_y_, tmp1_);
            bind_batch_equal_fma_ = exe.bind_eltwise2(tmp1_, quad_);

            // Initialize SHA256 context
            // --------------------------------------------------
            exe.sha256_digest_init(bind_sha256_ctx_);
        }

    ~nonbatch_verifier_context() {

    }

    void pop_sample(buffer_t buf) {
        const size_t num_u32_size = sample_index_.size() * Executor::device_bignum_type::num_limbs;
        this->executor().write_buffer(buf,
                                      host_samplings_.data() + pop_offset_,
                                      num_u32_size);

        pop_offset_ += num_u32_size;
    }

    void sample_row(webgpu::buffer_binding bind) {
        this->executor().sample_gather(bind, 0);
    }

    void check_code(webgpu::buffer_binding bind) {
        auto *r = this->backend().manager().acquire_mpz();
        for (size_t i = 0; i < params::num_code_test; i++) {
            this->backend().manager().generate_code_random(*r);
            this->executor().EltwiseFMAMod(bind, *r);
        }
        this->backend().manager().recycle_mpz(r);
    }

    void check_linear(webgpu::buffer_binding bind) {
        for (size_t i = 0; i < params::num_linear_test; i++) {
            this->executor().EltwiseFMAMod(bind);
        }
    }

    void check_quadratic() {
        this->executor().EltwiseMultMod(bind_quadratic_check_mul_);
        this->executor().EltwiseSubMod(bind_quadratic_check_sub_);

        auto *r = this->backend().manager().acquire_mpz();
        for (size_t i = 0; i < params::num_quadratic_test; i++) {
            this->backend().manager().generate_quadratic_random(*r);
            this->executor().EltwiseFMAMod(bind_quadratic_check_fma_, *r);
        }
        this->backend().manager().recycle_mpz(r);
    }

    void linear_callback(witness_row_type row) override {
        auto [_, rand] = row;

        pop_sample(device_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);

        rand.export_limbs(limbs_.data(),
                          limbs_.size(),
                          sizeof(uint64_t),
                          field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_x_, limbs_.data(), limbs_.size());

        this->executor().encode_ntt_device(bind_ntt_rand_x_);

        sample_row(bind_sample_rand_x_);

        check_code(bind_code_check_x_);
        check_linear(bind_linear_check_x_);
    }

    void quadratic_callback(witness_row_type x, witness_row_type y, witness_row_type z) override {
        auto [x_val, x_rand] = x;
        auto [y_val, y_rand] = y;
        auto [z_val, z_rand] = z;

        pop_sample(device_x_);
        pop_sample(device_y_);
        pop_sample(device_z_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);

        x_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_x_, limbs_.data(), limbs_.size());

        y_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_y_, limbs_.data(), limbs_.size());

        z_rand.export_limbs(limbs_.data(),
                            limbs_.size(),
                            sizeof(uint64_t),
                            field_type::num_u64_limbs);
        this->executor().write_buffer_clear(device_rand_z_, limbs_.data(), limbs_.size());

        this->executor().encode_ntt_device(bind_ntt_rand_x_);
        this->executor().encode_ntt_device(bind_ntt_rand_y_);
        this->executor().encode_ntt_device(bind_ntt_rand_z_);

        sample_row(bind_sample_rand_x_);
        sample_row(bind_sample_rand_y_);
        sample_row(bind_sample_rand_z_);

        check_code(bind_code_check_x_);
        check_code(bind_code_check_y_);
        check_code(bind_code_check_z_);

        check_linear(bind_linear_check_x_);
        check_linear(bind_linear_check_y_);
        check_linear(bind_linear_check_z_);

        check_quadratic();
    }

    void mask_callback(mpz_vector& code, mpz_vector& linear, mpz_vector& quad) override {
        pop_sample(device_x_);
        pop_sample(device_y_);
        pop_sample(device_z_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);

        this->executor().EltwiseAddAssignMod(bind_code_check_x_);
        this->executor().EltwiseAddAssignMod(bind_linear_mask_y_);
        this->executor().EltwiseAddAssignMod(bind_quadratic_mask_z_);
    }

    void on_batch_init(buffer_t& x) {
        pop_sample(device_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        check_code(bind_code_check_x_);
    }

    void on_batch_bit(buffer_t& x) {
        pop_sample(device_x_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);

        check_code(bind_code_check_x_);

        this->executor().copy_buffer_to_buffer(device_x_, device_y_);
        this->executor().copy_buffer_to_buffer(device_x_, device_z_);
        check_quadratic();
    }

    void on_batch_equal(buffer_t& x, buffer_t& y) {
        pop_sample(device_x_);
        pop_sample(device_y_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);

        // Update equality constraint in quadratic test
        this->executor().EltwiseSubMod(bind_batch_equal_sub_);

        auto *r = this->backend().manager().acquire_mpz();
        this->backend().manager().generate_quadratic_random(*r);
        this->executor().EltwiseFMAMod(bind_batch_equal_fma_, *r);
        this->backend().manager().recycle_mpz(r);
    }

    void on_batch_quadratic(buffer_t& x, buffer_t& y, buffer_t& z) {
        pop_sample(device_x_);
        pop_sample(device_y_);
        pop_sample(device_z_);

        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_x_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_y_);
        this->executor().sha256_digest_update(bind_sha256_ctx_, bind_sha256_z_);

        check_code(bind_code_check_x_);
        check_code(bind_code_check_y_);
        check_code(bind_code_check_z_);

        check_quadratic();
    }

    std::vector<digest_type> flush_digests() {
        this->executor().sha256_digest_final(bind_sha256_ctx_);
        return this->executor().template copy_to_host<digest_type>(sha256_digest_);
    }

    buffer_t code()      { return code_;   }
    buffer_t linear()    { return linear_; }
    buffer_t quadratic() { return quad_;   }

protected:
    size_t pop_offset_;
    std::vector<size_t> sample_index_;
    std::vector<uint32_t> host_samplings_;
    std::vector<uint64_t> limbs_;

    InputArchive& ia_;

    buffer_t code_, linear_, quad_;
    buffer_t tmp1_, tmp2_;
    buffer_t sample_rand_x_, sample_rand_y_, sample_rand_z_;
    buffer_t device_x_, device_y_, device_z_;
    buffer_t device_rand_x_, device_rand_y_, device_rand_z_;
    buffer_t sha256_context_, sha256_digest_;

    webgpu::buffer_binding bind_ntt_x_, bind_ntt_y_, bind_ntt_z_;
    webgpu::buffer_binding bind_ntt_rand_x_, bind_ntt_rand_y_, bind_ntt_rand_z_;
    webgpu::buffer_binding bind_sample_rand_x_, bind_sample_rand_y_, bind_sample_rand_z_;

    webgpu::buffer_binding bind_sha256_ctx_;
    webgpu::buffer_binding bind_sha256_x_, bind_sha256_y_, bind_sha256_z_;

    webgpu::buffer_binding bind_code_check_x_, bind_code_check_y_, bind_code_check_z_;
    webgpu::buffer_binding bind_linear_check_x_, bind_linear_check_y_, bind_linear_check_z_;
    webgpu::buffer_binding bind_quadratic_check_mul_, bind_quadratic_check_sub_, bind_quadratic_check_fma_;
    webgpu::buffer_binding bind_linear_mask_y_, bind_quadratic_mask_z_;

    webgpu::buffer_binding bind_batch_equal_sub_, bind_batch_equal_fma_;
};


}  // namespace ligero::vm::zkp
