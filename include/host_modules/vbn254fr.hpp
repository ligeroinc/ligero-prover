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

#include <bit>
#include <deque>

#include <host_modules/host_interface.hpp>
#include <util/log.hpp>
#include <util/recycle_pool.hpp>
#include <wgpu.hpp>
#include <zkp/backend/lazy_witness.hpp>
#include <zkp/backend/witness_manager.hpp>

namespace ligero::vm {

template <typename Context>
struct vbn254fr_module : public host_module {
    using executor_t    = typename Context::executor_t;
    using buffer_t      = typename executor_t::buffer_type;
    using device_bignum = typename executor_t::device_bignum_type;
    static constexpr auto device_bignum_bytes = device_bignum::num_bytes;
    static constexpr auto device_bignum_num_limbs = device_bignum::num_limbs;

    using Self  = vbn254fr_module<Context>;
    typedef void (Self::*host_function_type)();

    static constexpr auto module_name = "vbn254fr";
    static constexpr size_t max_variables = 512;

    vbn254fr_module() = default;

    // Delay the buffer allocation to avoid unnecessary allocation in non-batch
    vbn254fr_module(Context *ctx)
        : ctx_(ctx),
          executor_(ctx->executor()),
          initialized_(false)
        { }

    void initialize_buffer() {
        /// Number of elements in a batch row, equals to l = k - sampling size
        num_buf_elements_ = executor_.message_size();
        /// Number of bytes in a PADDED buffer, equals to k * sizeof(bignum_t)
        num_buf_bytes_    = executor_.padding_size() * device_bignum_bytes;
        tmp_buf_          = executor_.make_device_buffer(num_buf_bytes_);

        buffer_base_ = executor_.make_device_buffer(max_variables * num_buf_bytes_);

        buffer_t base_view = buffer_base_.slice_n(0, num_buf_bytes_);

        bind_compute2_ = executor_.bind_eltwise2(base_view, tmp_buf_);
        bind_compute3_ = executor_.bind_eltwise3(base_view, base_view, tmp_buf_);

        for (size_t i = 0; i < max_variables; i++) {
            free_list_.push_back(i * executor_.padding_size());
        }

        initialized_ = true;
    }

    buffer_t get_buffer_from_offset(size_t element_offset) {
        return buffer_base_.slice_n(element_offset * device_bignum_bytes,
                                    num_buf_bytes_);
    }

    u32 vbn254fr_allocate() {
        if (!initialized_) {
            initialize_buffer();
        }

        if (initialized_ && free_list_.empty()) {
            LIGERO_LOG_FATAL << std::format("Bad alloc: 0/{} free buffer available",
                                            max_variables);
            std::abort();
        }
        else {
            u32 offset = free_list_.front();
            free_list_.pop_front();
            return offset;
        }
    }

    u32 load_vbn254(u32 vbn254_addr) {
        u32 offset = 0;
        std::memcpy(&offset, ctx_->memory_data().data() + vbn254_addr, sizeof(offset));
        return offset;
    }

    void store_vbn254(u32 vbn254_addr, u32 idx) {
        std::memcpy(ctx_->memory_data().data() + vbn254_addr, &idx, sizeof(idx));

        // The BN254 handle we store here is public,
        // Ensure the written range is not marked secret.
        ctx_->memory().unmark_closed(vbn254_addr, vbn254_addr + sizeof(idx));
    }

    void vbn254fr_deallocate(u32 offset) {
        buffer_t view = get_buffer_from_offset(offset);
        executor_.clear_buffer(view);
        free_list_.emplace_back(offset);
    }

    // ------------------------------------------------------------

    void vbn254fr_get_size() {
        u64 size = executor_.message_size();
        ctx_->stack_push(size);
    }

    void vbn254fr_alloc() {
        u32 fp_addr = ctx_->stack_pop().as_u32();
        u32 addr = vbn254fr_allocate();

        store_vbn254(fp_addr, addr);
    }

    void vbn254fr_free() {
        u32 fp_addr = ctx_->stack_pop().as_u32();

        u32 handle = load_vbn254(fp_addr);
        vbn254fr_deallocate(handle);
        store_vbn254(fp_addr, 0);
    }

    void vbn254fr_set_ui() {
        u64 len     = ctx_->stack_pop().as_u64();
        u32 ui_ptr  = ctx_->stack_pop().as_u32();
        u32 fp_addr = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();

        u32 fp_handle = load_vbn254(fp_addr);
        u32 *mem32 = reinterpret_cast<u32*>(mem + ui_ptr);

        buffer_t x = get_buffer_from_offset(fp_handle);
        std::vector<device_bignum> vals;
        for (size_t i = 0; i < len; i++) {
            vals[i] = mem32[i];
        }
        executor_.write_buffer_clear(x, vals.data(), vals.size());

        ctx_->on_batch_init(x);
    }

    void vbn254fr_set_ui_scalar() {
        u32 ui      = ctx_->stack_pop().as_u32();
        u32 fp_addr = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();

        u32 fp_handle = load_vbn254(fp_addr);
        buffer_t x = get_buffer_from_offset(fp_handle);

        std::vector<device_bignum> v(num_buf_elements_, device_bignum(ui));
        executor_.write_buffer_clear(x, v.data(), v.size());

        ctx_->on_batch_init(x);
    }

    void vbn254fr_set_str() {
        u32 base        = ctx_->stack_pop().as_u32();
        u64 len         = ctx_->stack_pop().as_u64();
        u32 str_ptr_ptr = ctx_->stack_pop().as_u32();
        u32 fp_addr     = ctx_->stack_pop().as_u32();

        assert(len <= executor_.message_size());

        const auto *mem = ctx_->memory_data().data();
        u32 handle = load_vbn254(fp_addr);
        buffer_t x = get_buffer_from_offset(handle);

        std::vector<mpz_class> mpz;

        u32 success = 0;
        for (size_t i = 0; i < len; i++) {
            mpz_class tmp;
            u32 str_ptr = *reinterpret_cast<const u32*>(mem + str_ptr_ptr + i);
            success |= tmp.set_str(reinterpret_cast<const char *>(mem) + str_ptr, base);
            mpz.emplace_back(std::move(tmp));
        }

        if (!success) {
            LIGERO_LOG_WARNING << std::format("{}: mpz_set_str failed", __func__);
        }

        executor_.write_limbs(x, mpz);

        ctx_->on_batch_init(x);
        ctx_->stack_push(success);
    }

    void vbn254fr_set_str_scalar() {
        u32 base     = ctx_->stack_pop().as_u32();
        u32 str_addr = ctx_->stack_pop().as_u32();
        u32 fp_addr  = ctx_->stack_pop().as_u32();

        const auto *mem = ctx_->memory_data().data();
        u32 handle = load_vbn254(fp_addr);
        buffer_t x = get_buffer_from_offset(handle);

        mpz_class tmp;
        u32 err = tmp.set_str(reinterpret_cast<const char *>(mem + str_addr), base);

        if (err) {
            LIGERO_LOG_WARNING << std::format("{}: mpz_set_str failed", __func__);
        }

        executor_.write_limbs(x, tmp, num_buf_elements_);

        ctx_->on_batch_init(x);
        ctx_->stack_push(err);
    }

    void vbn254fr_set_bytes() {
        u64 count     = ctx_->stack_pop().as_u64();
        u64 len       = ctx_->stack_pop().as_u64();
        u32 bytes_ptr = ctx_->stack_pop().as_u32();
        u32 fp_addr   = ctx_->stack_pop().as_u32();

        assert(len <= executor_.message_size());

        const auto *mem = ctx_->memory_data().data();
        u32 handle = load_vbn254(fp_addr);
        const u8 *bytes = reinterpret_cast<const u8*>(mem + bytes_ptr);

        buffer_t x = get_buffer_from_offset(handle);
        std::vector<mpz_class> mpz;

        mpz_class tmp;
        for (size_t k = 0; k < count; k++) {
            mpz_import(tmp.get_mpz_t(), len, 1, sizeof(u8), 0, 0, bytes + len * count);

            std::cout << "imported: " << tmp << std::endl;
            mpz.push_back(tmp);
        }

        executor_.write_limbs(x, mpz);
        ctx_->on_batch_init(x);
    }

    void vbn254fr_set_bytes_scalar() {
        u64 len       = ctx_->stack_pop().as_u64();
        u32 bytes_ptr = ctx_->stack_pop().as_u32();
        u32 fp_addr   = ctx_->stack_pop().as_u32();

        assert(len <= executor_.message_size());

        const auto *mem = ctx_->memory_data().data();
        u32 handle = load_vbn254(fp_addr);
        const u8 *bytes = reinterpret_cast<const u8*>(mem + bytes_ptr);

        buffer_t x = get_buffer_from_offset(handle);

        mpz_class tmp;
        mpz_import(tmp.get_mpz_t(), len, 1, sizeof(u8), 0, 0, bytes);

        executor_.write_limbs(x, tmp, num_buf_elements_);
        ctx_->on_batch_init(x);
    }

    void vbn254fr_copy() {
        u32 in_addr  = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();

        u32 in_handle  = load_vbn254(in_addr);
        u32 out_handle = load_vbn254(out_addr);

        buffer_t in  = get_buffer_from_offset(in_handle);
        buffer_t out = get_buffer_from_offset(out_handle);

        if (in.get() == out.get()) {
            executor_.copy_buffer_to_buffer(in, tmp_buf_);
            executor_.copy_buffer_to_buffer(tmp_buf_, out);
        }
        else {
            executor_.copy_buffer_to_buffer(in, out);
        }

        ctx_->on_batch_equal(out, in);
    }

    void vbn254fr_print() {
        u32 base = ctx_->stack_pop().as_u32();
        u32 addr = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();
        u32 handle = load_vbn254(addr);
        buffer_t x = get_buffer_from_offset(handle);

        auto host = executor_.template copy_to_host<typename executor_t::device_bignum_type>(x);

        std::cout << std::format("@print [handle={}] vec: ", handle);
        for (size_t i = 0; i < 3; i++) {
            switch (base)
            {
                case 10:
                    gmp_printf("%Zd ", host[i].to_mpz().get_mpz_t());
                    break;
                case 16:
                    gmp_printf("%#Zx ", host[i].to_mpz().get_mpz_t());
                    break;
                default:
                        LIGERO_LOG_ERROR
                            << "Invalid base value: "
                            << base;
                        throw wasm_trap("bad conversion");
                    break;
            }
        }
        std::cout << "..." << std::endl;
    }

    void vbn254fr_constant_set_str() {
        u32 base     = ctx_->stack_pop().as_u32();
        u32 str_addr = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();
        const char *str = reinterpret_cast<const char *>(mem) + str_addr;

        mpz_class m;
        u32 err = mpz_set_str(m.get_mpz_t(), str, base);

        u32 *out = reinterpret_cast<u32*>(mem + out_addr);

        std::memset(out, 0, Context::field_type::num_u32_limbs);

        // Use platform-native word size for best performance
        mpz_export(out, nullptr, -1, sizeof(void*), 0, 0, m.get_mpz_t());

        ctx_->stack_push(err);
    }

    // ------------------------------------------------------------

    void vbn254fr_addmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);
        u32 y_offset   = load_vbn254(y_addr);

        buffer_t x = get_buffer_from_offset(x_offset);
        buffer_t y = get_buffer_from_offset(y_offset);
        buffer_t out = get_buffer_from_offset(out_offset);

        executor_.EltwiseAddMod(bind_compute3_, { .x = x_offset, .y = y_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_addmod_constant() {
        u32 k_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);

        auto *mem = ctx_->memory_data().data();
        const u32 *k = reinterpret_cast<const u32*>(mem + k_addr);
        mpz_class mpz;
        mpz_import(mpz.get_mpz_t(), device_bignum_num_limbs, -1, sizeof(uint32_t), 0, 0, k);

        buffer_t out = get_buffer_from_offset(out_offset);
        executor_.EltwiseAddMod(bind_compute2_, mpz, { .x = x_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_submod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);
        u32 y_offset   = load_vbn254(y_addr);

        buffer_t out = get_buffer_from_offset(out_offset);

        executor_.EltwiseSubMod(bind_compute3_, { .x = x_offset, .y = y_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_submod_constant() {
        u32 k_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);

        auto *mem = ctx_->memory_data().data();
        const u32 *k = reinterpret_cast<const u32*>(mem + k_addr);
        mpz_class mpz;
        mpz_import(mpz.get_mpz_t(), device_bignum_num_limbs, -1, sizeof(u32), 0, 0, k);

        buffer_t out = get_buffer_from_offset(out_offset);
        // buffer_t& x   = mem_map_.at(x_handle);

        executor_.EltwiseSubConstMod(bind_compute2_, mpz, { .x = x_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_constant_submod() {
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 k_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);

        auto *mem = ctx_->memory_data().data();
        const u32 *k = reinterpret_cast<const u32*>(mem + k_addr);
        mpz_class mpz;
        mpz_import(mpz.get_mpz_t(), device_bignum_num_limbs, -1, sizeof(u32), 0, 0, k);

        buffer_t out = get_buffer_from_offset(out_offset);
        // buffer_t& x   = mem_map_.at(x_handle);

        executor_.EltwiseConstSubMod(bind_compute2_, mpz, { .x = x_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_mulmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);
        u32 y_offset   = load_vbn254(y_addr);

        buffer_t x   = get_buffer_from_offset(x_offset);
        buffer_t y   = get_buffer_from_offset(y_offset);
        buffer_t out = get_buffer_from_offset(out_offset);

        executor_.EltwiseMultMod(bind_compute3_, { .x = x_offset, .y = y_offset });

        // auto ht = executor_.template copy_to_host<uint32_t>(boo);

        // LIGERO_LOG_DEBUG << "@mulmod: " << hx[0]
        //                  << " * " << hy[0]
        //                  << " = " << ht[0];

        ctx_->on_batch_quadratic(x, y, tmp_buf_);

        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_mulmod_constant() {
        u32 k_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);

        auto *mem = ctx_->memory_data().data();
        const u32 *k = reinterpret_cast<const u32*>(mem + k_addr);
        mpz_class mpz;
        mpz_import(mpz.get_mpz_t(), device_bignum_num_limbs, -1, sizeof(u32), 0, 0, k);

        buffer_t out = get_buffer_from_offset(out_offset);
        buffer_t x   = get_buffer_from_offset(x_offset);

        executor_.EltwiseMultMod(bind_compute2_, mpz, { .x = x_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_mont_mul_constant() {
        u32 k_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);

        auto *mem = ctx_->memory_data().data();
        const u32 *k = reinterpret_cast<const u32*>(mem + k_addr);
        mpz_class mpz;
        mpz_import(mpz.get_mpz_t(), device_bignum_num_limbs, -1, sizeof(u32), 0, 0, k);

        buffer_t out = get_buffer_from_offset(out_offset);
        buffer_t x   = get_buffer_from_offset(x_offset);

        executor_.EltwiseMontMultMod(bind_compute2_, mpz, { .x = x_offset });
        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_divmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        u32 out_offset = load_vbn254(out_addr);
        u32 x_offset   = load_vbn254(x_addr);
        u32 y_offset   = load_vbn254(y_addr);

        buffer_t out = get_buffer_from_offset(out_offset);
        buffer_t x   = get_buffer_from_offset(x_offset);
        buffer_t y   = get_buffer_from_offset(y_offset);

        executor_.EltwiseDivMod(bind_compute3_, { .x = x_offset, .y = y_offset });

        ctx_->on_batch_quadratic(tmp_buf_, y, x);

        executor_.copy_buffer_to_buffer(tmp_buf_, out);
    }

    void vbn254fr_assert_equal() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *mem = ctx_->memory_data().data();

        u32 x_offset   = load_vbn254(x_addr);
        u32 y_offset   = load_vbn254(y_addr);

        buffer_t x = get_buffer_from_offset(x_offset);
        buffer_t y = get_buffer_from_offset(y_offset);

        // auto hx = executor_.template copy_to_host<typename executor_t::device_bignum_type>(x);
        // auto hy = executor_.template copy_to_host<typename executor_t::device_bignum_type>(y);

        // LIGERO_LOG_DEBUG << "@assert: "
        //                  << "x[offset=" << x_offset << "]: " << hx[0].to_mpz()
        //                  <<" == "
        //                  << "y[offset=" << y_offset << "]: " << hy[0].to_mpz();

        ctx_->on_batch_equal(x, y);
    }

    void vbn254fr_bit_decompose() {
        u32 x_addr       = ctx_->stack_pop().as_u32();
        u32 out_arr_base = ctx_->stack_pop().as_u32();

        u32 x_offset = load_vbn254(x_addr);
        for (uint32_t i = 0; i < Context::field_type::num_bits; i++) {
            u32 handle = ctx_->template memory_load<u32>(out_arr_base + i * sizeof(u32));

            buffer_t bit = get_buffer_from_offset(handle);

            executor_.EltwiseBitDecompose(bind_compute2_, i, { .x = x_offset });

            executor_.copy_buffer_to_buffer(tmp_buf_, bit);
            ctx_->on_batch_bit(bit);
        }

        // TODO: add linear constraints
    }

    exec_result call_host(address_t addr, std::string_view name) override {
        (this->*call_map_[name])();
        return exec_ok();
    }

    void initialize() override {
        call_map_ = {
            { "vbn254fr_get_size",              &Self::vbn254fr_get_size               },
            { "vbn254fr_alloc",                 &Self::vbn254fr_alloc                  },
            { "vbn254fr_free",                  &Self::vbn254fr_free                   },
            { "vbn254fr_set_ui",                &Self::vbn254fr_set_ui                 },
            { "vbn254fr_set_ui_scalar",         &Self::vbn254fr_set_ui_scalar          },
            { "vbn254fr_set_str",               &Self::vbn254fr_set_str                },
            { "vbn254fr_set_str_scalar",        &Self::vbn254fr_set_str_scalar         },
            { "vbn254fr_set_bytes",             &Self::vbn254fr_set_bytes              },
            { "vbn254fr_set_bytes_scalar",      &Self::vbn254fr_set_bytes_scalar       },
            { "vbn254fr_copy",                  &Self::vbn254fr_copy                   },
            { "vbn254fr_print",                 &Self::vbn254fr_print                  },
            { "vbn254fr_constant_set_str",      &Self::vbn254fr_constant_set_str       },
            { "vbn254fr_addmod",                &Self::vbn254fr_addmod                 },
            { "vbn254fr_addmod_constant",       &Self::vbn254fr_addmod_constant        },
            { "vbn254fr_submod",                &Self::vbn254fr_submod                 },
            { "vbn254fr_submod_constant",       &Self::vbn254fr_submod_constant        },
            { "vbn254fr_constant_submod",       &Self::vbn254fr_constant_submod        },
            { "vbn254fr_mulmod",                &Self::vbn254fr_mulmod                 },
            { "vbn254fr_mulmod_constant",       &Self::vbn254fr_mulmod_constant        },
            { "vbn254fr_mont_mul_constant",     &Self::vbn254fr_mont_mul_constant      },
            { "vbn254fr_divmod",                &Self::vbn254fr_divmod                 },
            { "vbn254fr_assert_equal",          &Self::vbn254fr_assert_equal           },
            { "vbn254fr_bit_decompose",         &Self::vbn254fr_bit_decompose          }
        };
    }

    void finalize() override {
        executor_.device_synchronize();
    }

protected:
    Context *ctx_;
    executor_t& executor_;

    bool initialized_;
    size_t num_buf_elements_;
    size_t num_buf_bytes_;

    u32 alloc_addr_ = 1;
    std::deque<size_t> free_list_;

    buffer_t buffer_base_, tmp_buf_;

    webgpu::buffer_binding bind_compute2_, bind_compute3_;

    std::unordered_map<std::string_view, host_function_type> call_map_;
};


} // namespace ligero::vm
