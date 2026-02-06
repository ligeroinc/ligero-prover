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
#include <util/recycle_pool.hpp>
#include <util/log.hpp>
#include <util/mpz_get.hpp>
#include <zkp/backend/lazy_witness.hpp>
#include <zkp/backend/witness_manager.hpp>
#include <host_modules/host_interface.hpp>

namespace ligero::vm {

template <typename Context>
struct bn254fr_module : public host_module {
    using Field = typename Context::field_type;
    using Self  = bn254fr_module<Context>;
    typedef void (Self::*host_function_type)();

    static constexpr auto module_name = "bn254fr";

    bn254fr_module(Context *ctx) : ctx_(ctx) { }

    zkp::lazy_witness* load_bn254(u32 bn254_addr) {
        uintptr_t ptr = ctx_->template memory_load<uintptr_t>(bn254_addr);
        zkp::lazy_witness* ret = std::bit_cast<zkp::lazy_witness*>(ptr);
        return ret;
    }

    void store_bn254(u32 bn254_addr, zkp::lazy_witness *ptr) {
        uintptr_t val = std::bit_cast<uintptr_t>(ptr);
        ctx_->memory_store(bn254_addr, val);

        // The BN254 handle we store here is public,
        // Ensure the written range is not marked secret.
        ctx_->memory().unmark_closed(bn254_addr, bn254_addr + sizeof(val));
    }

    void bn254fr_alloc() {
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        /** Allocate an instance (non-witness) first */
        zkp::lazy_witness *wit = ctx_->backend().manager().acquire_instance();
        // printf("bn254fr_alloc: allocate %p to %d\n", wit, bn254_addr);
        store_bn254(bn254_addr, wit);
    }

    void bn254fr_free() {
        u32 bn254_addr = ctx_->stack_pop().as_u32();
        zkp::lazy_witness *wit = load_bn254(bn254_addr);

        if (wit) {
            ctx_->backend().manager().commit_release_witness(wit);
        }
        // printf("bn254fr_free: ptr: free %p at %d\n", wit, bn254_addr);
        store_bn254(bn254_addr, nullptr);
    }

    void bn254fr_assert_equal() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        x->set_witness_status(true);
        y->set_witness_status(true);

        ctx_->backend().manager().constrain_equal(*x, *y);
    }

    void bn254fr_assert_equal_u32() {
        auto y       = ctx_->stack_pop();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        x->set_witness_status(true);

        if (auto y_num = y.get_if_numeric()) {
            ctx_->backend().manager().constrain_constant(*x, y_num->as_u32());
        } else {
            auto y_wit = ctx_->make_witness(std::move(y));
            ctx_->backend().manager().constrain_equal(*x, *y_wit);
        }
    }

    void bn254fr_assert_equal_u64() {
        auto y       = ctx_->stack_pop();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        x->set_witness_status(true);

        if (auto y_num = y.get_if_numeric()) {
            ctx_->backend().manager().constrain_constant(*x, y_num->as_u64());
        } else {
            auto y_wit = ctx_->make_witness(std::move(y));
            ctx_->backend().manager().constrain_equal(*x, *y_wit);
        }
    }

    void bn254fr_assert_equal_bytes() {
        s32 order      = ctx_->stack_pop().as_u32();
        u32 size       = ctx_->stack_pop().as_u32();
        u32 bytes_addr = ctx_->stack_pop().as_u32();
        u32 x_addr     = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        x->set_witness_status(true);

        auto *f = ctx_->current_frame();
        address_t a = f->module->memaddrs[0];
        memory_instance &mem = ctx_->store()->memorys[a];
        bool bytes_secret = mem.contains_secret(bytes_addr, bytes_addr + 1);

        for (size_t i = 0; i < size; ++i) {
            bool bs = mem.contains_secret(bytes_addr + i, bytes_addr + i + 1);
            if (bs != bytes_secret) {
                throw wasm_trap("bad bytes equal constraint");
            }
        }

        if (bytes_secret) {
            std::vector<zkp::managed_witness> bytes{size};

            for (size_t i = 0; i < size; ++i) {
                auto b = ctx_->template memory_load<u8>(bytes_addr + i);
                auto idx = order == -1 ? i : (size - i - 1);
                bytes[idx] = ctx_->make_witness(b);
            }

            auto sum = ctx_->backend().acquire_witness();
            auto *exp = ctx_->backend().manager().acquire_mpz();
            *exp = 1;

            for (size_t i = 0; i < size; ++i) {
                sum = ctx_->backend().eval(sum + bytes[i] * *exp);
                mpz_mul_2exp(exp->get_mpz_t(), exp->get_mpz_t(), 8);
            }

            ctx_->backend().manager().recycle_mpz(exp);
            ctx_->backend().manager().constrain_equal(*x, *sum);
        } else {
            auto *y = ctx_->backend().manager().acquire_mpz();
            mpz_import(y->get_mpz_t(),
                       size,
                       order,
                       sizeof(u8),
                       0,
                       0,
                       ctx_->memory_data().data() + bytes_addr);
            if (*y >= Field::modulus) {
                throw wasm_trap("bad bytes equal constraint");
            }

            ctx_->backend().manager().constrain_constant(*x, *y);
            ctx_->backend().manager().recycle_mpz(y);
        }
    }

    void bn254fr_assert_add() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        x->set_witness_status(true);
        y->set_witness_status(true);
        out->set_witness_status(true);

        ctx_->backend().manager().constrain_linear(*out, *x, *y);
    }

    void bn254fr_assert_mul() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        x->set_witness_status(true);
        y->set_witness_status(true);
        out->set_witness_status(true);

        ctx_->backend().manager().constrain_quadratic(out, x, y);
    }

    void bn254fr_assert_mulc() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        x->set_witness_status(true);
        y->set_witness_status(true);
        out->set_witness_status(true);

        ctx_->backend().manager().constrain_quadratic_constant(*out, *x, *y->value_ptr());
    }

    void bn254fr_to_bits_checked() {
        u32 bitcount = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 arr_addr = ctx_->stack_pop().as_u32();

        auto *x = load_bn254(x_addr);
        x->set_witness_status(true);

        auto *rand = ctx_->backend().manager().acquire_mpz();
        ctx_->backend().manager().generate_linear_random(*rand);
        ctx_->backend().manager().witness_sub_random(*x, *rand);

        auto *tmp = ctx_->backend().manager().acquire_mpz();

        for (size_t i = 0; i < bitcount; i++) {
            auto *bit = load_bn254(arr_addr + i * sizeof(uint64_t));
            *bit->value_ptr() = mpz_tstbit(x->value_ptr()->get_mpz_t(), i);
            bit->set_witness_status(true);

            ctx_->backend().manager().constrain_bit(bit);

            *tmp = *rand << i;
            Field::reduce(*tmp, *tmp);
            ctx_->backend().manager().witness_add_random(*bit, *tmp);
        }

        ctx_->backend().manager().recycle_mpz(tmp);
        ctx_->backend().manager().recycle_mpz(rand);
    }

    void bn254fr_from_bits_checked() {
        u32 bitcount = ctx_->stack_pop().as_u32();
        u32 arr_addr = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x = load_bn254(x_addr);
        x->set_witness_status(true);

        auto *rand = ctx_->backend().manager().acquire_mpz();
        ctx_->backend().manager().generate_linear_random(*rand);
        ctx_->backend().manager().witness_sub_random(*x, *rand);

        auto *tmp = ctx_->backend().manager().acquire_mpz();

        for (size_t i = 0; i < bitcount; i++) {
            auto *bit = load_bn254(arr_addr + i * sizeof(uint64_t));
            bit->set_witness_status(true);
            *tmp = *bit->value_ptr() << i;
            *x->value_ptr() += *tmp;

            *tmp = *rand << i;
            Field::reduce(*tmp, *tmp);
            ctx_->backend().manager().witness_add_random(*bit, *tmp);
        }

        ctx_->backend().manager().recycle_mpz(tmp);
        ctx_->backend().manager().recycle_mpz(rand);
    }

    void bn254fr_set_u32() {
        u32 ui         = ctx_->make_numeric(ctx_->stack_pop()).as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
        *wit->value_ptr() = ui;
    }

    void bn254fr_set_u64() {
        u64 ull        = ctx_->make_numeric(ctx_->stack_pop()).as_u64();
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
        mpz_assign(*wit->value_ptr(), ull);
    }

    void bn254fr_set_bytes() {
        s32 order      = ctx_->stack_pop().as_u32();
        u32 size       = ctx_->stack_pop().as_u32();
        u32 data_addr  = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto *wit = load_bn254(bn254_addr);
        mpz_import(wit->value_ptr()->get_mpz_t(),
                size,
                order,
                sizeof(u8),
                0,
                0,
                mem + data_addr);
    }

    void bn254fr_set_str() {
        u32 base       = ctx_->stack_pop().as_u32();
        u32 str_addr   = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto *wit = load_bn254(bn254_addr);
        int failed = mpz_set_str(wit->value_ptr()->get_mpz_t(),
                                 reinterpret_cast<const char *>(mem) + str_addr,
                                 base);

        if (failed) {
            LIGERO_LOG_ERROR
                << "Error parsing string \""
                << (const char*)(mem + str_addr)
                << "\", did you forget the prefix \"0x\"?";
            throw wasm_trap("bad conversion");
        }
    }

    void bn254fr_get_u64() {
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
        ctx_->stack_push(mpz_get_u64(*wit->value_ptr()));
    }

    void bn254fr_to_bytes() {
        s32 order      = ctx_->stack_pop().as_u32();
        u32 size       = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();
        u32 data_addr  = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto *wit = load_bn254(bn254_addr);
        auto mpz = wit->value_ptr()->get_mpz_t();

        auto bits = 8 * sizeof(u8);
        auto required_size = (mpz_sizeinbase(mpz, 2) + bits - 1) / bits;

        if (size > 32 || size < required_size) {
            throw wasm_trap{"invalid size for bn254fr_to_bytes"};
        }

        //memset(mem + data_addr, 0, size);
        size_t written = 0;
        memset(mem + data_addr, 0, size);
        mpz_export(mem + data_addr,
                   &written,
                   order,
                   sizeof(u8),
                   0,
                   0,
                   mpz);

        assert(written <= size && "invalid number of bytes written");
    }

    void bn254fr_copy() {
        u32 src_addr  = ctx_->stack_pop().as_u32();
        u32 dest_addr = ctx_->stack_pop().as_u32();

        auto *dest = load_bn254(dest_addr);
        auto *src  = load_bn254(src_addr);

        *dest->value_ptr() = *src->value_ptr();
    }

    void bn254fr_print() {
        u32 base = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
            printf("@bn254fr_print: addr=%p, val=", wit);
        switch (base)
        {
            case 10:
                gmp_printf("%Zd\n", wit->value_ptr()->get_mpz_t());
                break;
            case 16:
                gmp_printf("%#Zx\n", wit->value_ptr()->get_mpz_t());
                break;
            default:
                    LIGERO_LOG_ERROR
                        << "Invalid base value: "
                        << base;
                    throw wasm_trap("bad conversion");
                break;
        }
    }

    void bn254fr_addmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        Field::addmod(*out->value_ptr(), *x->value_ptr(), *y->value_ptr());
    }

    void bn254fr_submod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        Field::submod(*out->value_ptr(), *x->value_ptr(), *y->value_ptr());
    }

    void bn254fr_mulmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        Field::mulmod(*out->value_ptr(), *x->value_ptr(), *y->value_ptr());
    }

    void bn254fr_divmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        Field::divmod(*out->value_ptr(), *x->value_ptr(), *y->value_ptr());
    }

    void bn254fr_invmod() {
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *out = load_bn254(out_addr);

        Field::invmod(*out->value_ptr(), *x->value_ptr());
    }

    void bn254fr_negmod() {
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *out = load_bn254(out_addr);

        Field::negate(*out->value_ptr(), *x->value_ptr());
    }

    void bn254fr_powmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        Field::powmod(*out->value_ptr(), *x->value_ptr(), *y->value_ptr());
    }

    void bn254fr_idiv() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        mpz_fdiv_q(out->value_ptr()->get_mpz_t(),
                   x->value_ptr()->get_mpz_t(),
                   y->value_ptr()->get_mpz_t());
    }

    void bn254fr_irem() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        mpz_fdiv_r(out->value_ptr()->get_mpz_t(),
                   x->value_ptr()->get_mpz_t(),
                   y->value_ptr()->get_mpz_t());
    }

    // ------------------------------------------------------------

    void bn254fr_eq() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() == *y->value_ptr();
        ctx_->stack_push(result);
    }

    void bn254fr_eqz() {
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);

        u32 result = *x->value_ptr() == 0u;
        ctx_->stack_push(result);
    }

    void bn254fr_lt() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() < *y->value_ptr();
        ctx_->stack_push(result);
    }

    void bn254fr_lte() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() <= *y->value_ptr();
        ctx_->stack_push(result);
    }

    void bn254fr_gt() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() > *y->value_ptr();
        ctx_->stack_push(result);
    }

    void bn254fr_gte() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() >= *y->value_ptr();
        ctx_->stack_push(result);
    }

    // ------------------------------------------------------------

    void bn254fr_land() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() && *y->value_ptr();
        ctx_->stack_push(result);
    }

    void bn254fr_lor() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);

        u32 result = *x->value_ptr() || *y->value_ptr();
        ctx_->stack_push(result);
    }

    // ------------------------------------------------------------

    void bn254fr_band() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        mpz_and(out->value_ptr()->get_mpz_t(),
                x->value_ptr()->get_mpz_t(),
                y->value_ptr()->get_mpz_t());
    }

    void bn254fr_bor() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        mpz_ior(out->value_ptr()->get_mpz_t(),
                x->value_ptr()->get_mpz_t(),
                y->value_ptr()->get_mpz_t());
    }

    void bn254fr_bxor() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        mpz_xor(out->value_ptr()->get_mpz_t(),
                x->value_ptr()->get_mpz_t(),
                y->value_ptr()->get_mpz_t());
    }

    void bn254fr_bnot() {
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *out = load_bn254(out_addr);

        mpz_com(out->value_ptr()->get_mpz_t(), x->value_ptr()->get_mpz_t());
    }

    // ------------------------------------------------------------

    void do_bn254_shlmod(mpz_class *out, mpz_class *x, mpz_class *k) {
        if (*k >= 0) {
            if (*k < Field::modulus_middle) {
                assert(k->get_ui() == *k && "shift value too large");
                mpz_mul_2exp(out->get_mpz_t(), x->get_mpz_t(), k->get_ui());
                Field::reduce(*out, *out);
            }
            else {
                mpz_class wrap_k = Field::modulus - *k;
                do_bn254_shrmod(out, x, &wrap_k);
            }
        }
    }

    void do_bn254_shrmod(mpz_class *out, mpz_class *x, mpz_class *k) {
        if (*k >= 0) {
            if (*k < Field::modulus_middle) {
                mpz_fdiv_q_2exp(out->get_mpz_t(), x->get_mpz_t(), k->get_ui());
            }
            else {
                mpz_class wrap_k = Field::modulus - *k;
                do_bn254_shlmod(out, x, &wrap_k);
            }
        }
    }

    void bn254fr_shlmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        do_bn254_shlmod(out->value_ptr(), x->value_ptr(), y->value_ptr());
    }

    void bn254fr_shrmod() {
        u32 y_addr   = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto *x   = load_bn254(x_addr);
        auto *y   = load_bn254(y_addr);
        auto *out = load_bn254(out_addr);

        do_bn254_shrmod(out->value_ptr(), x->value_ptr(), y->value_ptr());
    }

    void bn254fr_to_bits() {
        u32 bitcount = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();
        u32 arr_addr = ctx_->stack_pop().as_u32();

        auto *x = load_bn254(x_addr);
        for (size_t i = 0; i < bitcount; i++) {
            auto *bi = load_bn254(arr_addr + i * sizeof(uint64_t));
            *bi->value_ptr() = (*x->value_ptr()) >> i & 1u;
        }
    }

    void bn254fr_from_bits() {
        u32 bitcount = ctx_->stack_pop().as_u32();
        u32 arr_addr = ctx_->stack_pop().as_u32();
        u32 x_addr   = ctx_->stack_pop().as_u32();

        auto *x = load_bn254(x_addr);
        for (size_t i = 0; i < bitcount; i++) {
            auto *bi = load_bn254(arr_addr + i * sizeof(uint64_t));
            *x->value_ptr() |= *bi->value_ptr() << i;
        }
    }

    void bn254fr_bigint_mul_checked_no_carry() {
        u32 b_count  = ctx_->stack_pop().as_u32();
        u32 a_count  = ctx_->stack_pop().as_u32();
        u32 b_addr = ctx_->stack_pop().as_u32();
        u32 a_addr = ctx_->stack_pop().as_u32();
        u32 c_addr = ctx_->stack_pop().as_u32();

        // compute c = a * b multiplication
        auto mul_res = ctx_->backend().manager().acquire_mpz();
        for (size_t i = 0; i < a_count; ++i) {
            for (size_t j = 0; j < b_count; ++j) {
                auto *a_i = load_bn254(a_addr + i * sizeof(uint64_t));
                auto *b_j = load_bn254(b_addr + j * sizeof(uint64_t));
                auto *c_i_j = load_bn254(c_addr + i * sizeof(uint64_t) +
                                                  j * sizeof(uint64_t));

                Field::mulmod(*mul_res, *a_i->value_ptr(), *b_j->value_ptr());
                Field::addmod(*c_i_j->value_ptr(), *c_i_j->value_ptr(), *mul_res);
            }
        }

        // check equality of c and a * b polynomials
        bn254fr_assert_poly_mul(c_addr, a_addr, b_addr, a_count, b_count);
    }

    void bn254fr_bigint_mul() {
        u32 bits = ctx_->stack_pop().as_u32();
        u32 b_count  = ctx_->stack_pop().as_u32();
        u32 a_count  = ctx_->stack_pop().as_u32();
        u32 b_addr = ctx_->stack_pop().as_u32();
        u32 a_addr = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto a = compose_big_int(a_addr, a_count, bits);
        auto b = compose_big_int(b_addr, b_count, bits);

        auto out = ctx_->backend().manager().acquire_mpz();
        *out = (*a) * (*b);

        decompose_big_int(out_addr, a_count + b_count, out, bits);

        ctx_->backend().manager().recycle_mpz(a);
        ctx_->backend().manager().recycle_mpz(b);
        ctx_->backend().manager().recycle_mpz(out);
    }

    void bn254fr_bigint_idiv() {
        u32 bits = ctx_->stack_pop().as_u32();
        u32 b_count  = ctx_->stack_pop().as_u32();
        u32 a_count  = ctx_->stack_pop().as_u32();
        u32 b_addr = ctx_->stack_pop().as_u32();
        u32 a_addr = ctx_->stack_pop().as_u32();
        u32 r_addr = ctx_->stack_pop().as_u32();
        u32 q_addr = ctx_->stack_pop().as_u32();

        auto a = compose_big_int(a_addr, a_count, bits);
        auto b = compose_big_int(b_addr, b_count, bits);

        auto q = ctx_->backend().manager().acquire_mpz();
        auto r = ctx_->backend().manager().acquire_mpz();
        mpz_fdiv_qr(q->get_mpz_t(),
                    r->get_mpz_t(),
                    a->get_mpz_t(),
                    b->get_mpz_t());

        decompose_big_int(q_addr, a_count, q, bits);
        decompose_big_int(r_addr, b_count, r, bits);

        ctx_->backend().manager().recycle_mpz(q);
        ctx_->backend().manager().recycle_mpz(r);
    }

    void bn254fr_bigint_invmod() {
        u32 bits = ctx_->stack_pop().as_u32();
        u32 m_count  = ctx_->stack_pop().as_u32();
        u32 a_count  = ctx_->stack_pop().as_u32();
        u32 m_addr = ctx_->stack_pop().as_u32();
        u32 a_addr = ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto a = compose_big_int_signed(a_addr, a_count, bits);
        auto m = compose_big_int_signed(m_addr, m_count, bits);

        auto out = ctx_->backend().manager().acquire_mpz();
        mpz_invert(out->get_mpz_t(),
                   a->get_mpz_t(),
                   m->get_mpz_t());

        decompose_big_int(out_addr, m_count, out, bits);

        ctx_->backend().manager().recycle_mpz(out);
    }

    /// Splits mpz value into two values n_bits bits each
    void split_mpz(mpz_class *out_1, mpz_class *out_2, const mpz_class *in, uint32_t n_bits) {
        // out_1 = in % (1 << n_bits)
        mpz_fdiv_r_2exp(out_1->get_mpz_t(), in->get_mpz_t(), n_bits);

        // res_2 = (in \ (1 << n_bits)) % (1 << n_bits)
        *out_2 = *in >> n_bits;
        mpz_fdiv_r_2exp(out_2->get_mpz_t(), out_2->get_mpz_t(), n_bits);
    }

    /// Splits mpz value into three values n_bits bits each
    std::array<mpz_class*, 3> split_mpz_3(const mpz_class *in, uint32_t n_bits) {
        assert(n_bits <= 126 && "invalid n_bits value passed to split_mpz");

        std::array<mpz_class*, 3> res = {
            ctx_->backend().manager().acquire_mpz(),
            ctx_->backend().manager().acquire_mpz(),
            ctx_->backend().manager().acquire_mpz()
        };

        // res[0] = in % (1 << n_bits)
        mpz_fdiv_r_2exp(res[0]->get_mpz_t(), in->get_mpz_t(), n_bits);

        // res[1] = (in \ (1 << n_bits)) % (1 << n_bits)
        *res[1] = *in >> n_bits;
        mpz_fdiv_r_2exp(res[1]->get_mpz_t(), res[1]->get_mpz_t(), n_bits);

        // res[2] = (in \ (1 << (n_bits * 2))) % (1 << n_bits)
        *res[2] = *in >> (n_bits * 2);
        mpz_fdiv_r_2exp(res[2]->get_mpz_t(), res[2]->get_mpz_t(), n_bits);

        return res;
    }

    void bn254fr_bigint_convert_to_proper_representation_signed() {
        u32 bits      = ctx_->stack_pop().as_u32();
        u32 in_count  = ctx_->stack_pop().as_u32();
        u32 out_count = ctx_->stack_pop().as_u32();
        u32 in_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr  = ctx_->stack_pop().as_u32();

        auto val = compose_big_int_signed(in_addr, in_count, bits);
        decompose_big_int(out_addr, out_count, val, bits);
        ctx_->backend().manager().recycle_mpz(val);
    }

    void bn254fr_bigint_print() {
        u32 bits  = ctx_->stack_pop().as_u32();
        u32 limbs = ctx_->stack_pop().as_u32();
        u32 addr  = ctx_->stack_pop().as_u32();

        auto val = compose_big_int_signed(addr, limbs, bits);
        gmp_printf("@bn254fr_bigint_print %Zx\n", val->get_mpz_t());
        ctx_->backend().manager().recycle_mpz(val);
    }

    void bn254fr_bigint_convert_to_proper_representation_unsigned() {
        u32 bits      = ctx_->stack_pop().as_u32();
        u32 in_count  = ctx_->stack_pop().as_u32();
        u32 out_count = ctx_->stack_pop().as_u32();
        u32 in_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr  = ctx_->stack_pop().as_u32();

        auto val = compose_big_int(in_addr, in_count, bits);
        decompose_big_int(out_addr, out_count, val, bits);
        ctx_->backend().manager().recycle_mpz(val);
    }

    void bn254fr_bigint_convert_to_proper_representation() {
        u32 bits      = ctx_->stack_pop().as_u32();
        u32 count     = ctx_->stack_pop().as_u32();
        u32 in_addr   = ctx_->stack_pop().as_u32();
        u32 out_addr  = ctx_->stack_pop().as_u32();

        // split all limbs into 3 values bits each
        std::vector<std::array<mpz_class*, 3>> splits;
        splits.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            auto *in_i = load_bn254(in_addr + i * sizeof(uint64_t));
            splits.push_back(split_mpz_3(in_i->value_ptr(), bits));
        }

        // acquire mpzs for carry
        std::vector<mpz_class*> carry;
        carry.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            carry.push_back(ctx_->backend().manager().acquire_mpz());
        }

        // calculate first limb and carry
        {
            auto *out_0 = load_bn254(out_addr + 0 * sizeof(uint64_t));
            *out_0->value_ptr() = *splits[0][0];
            *carry[0] = 0;
        }

        if (count == 1) {
            auto *out_1 = load_bn254(out_addr + 1 * sizeof(uint64_t));
            *out_1->value_ptr() = *splits[0][1];
        } else {
            // calculate second limb and carry
            {
                auto *out_1 = load_bn254(out_addr + 1 * sizeof(uint64_t));
                auto tmp = ctx_->backend().manager().acquire_mpz();
                *tmp = *splits[0][1] + *splits[1][0];
                split_mpz(out_1->value_ptr(), carry[1], tmp, bits);
                ctx_->backend().manager().recycle_mpz(tmp);
            }

            if (count == 2) {
                auto *out_2 = load_bn254(out_addr + 2 * sizeof(uint64_t));
                *out_2->value_ptr() = *splits[1][1] + *splits[0][2] + *carry[1];
            } else {
                // calculate all other limbs and carry values
                for (size_t i = 2; i < count; ++i) {
                    auto *out_i = load_bn254(out_addr + i * sizeof(uint64_t));
                    auto tmp = ctx_->backend().manager().acquire_mpz();
                    *tmp = *splits[i][0] + *splits[i - 1][1] + *splits[i - 2][2] + *carry[i - 1];
                    split_mpz(out_i->value_ptr(), carry[i], tmp, bits);
                    ctx_->backend().manager().recycle_mpz(tmp);
                }

                // calculate the last limb
                auto *out_last = load_bn254(out_addr + count * sizeof(uint64_t));
                *out_last->value_ptr() = *splits[count - 1][1] +
                                         *splits[count - 2][2] +
                                         *carry[count - 1];
            }
        }

        // recycle mpzs used for splits
        for (size_t i = 0; i < count; ++i) {
            ctx_->backend().manager().recycle_mpz(splits[i][0]);
            ctx_->backend().manager().recycle_mpz(splits[i][1]);
            ctx_->backend().manager().recycle_mpz(splits[i][2]);
        }

        // recycle mpzs used for carry
        for (size_t i = 0; i < count; ++i) {
            ctx_->backend().manager().recycle_mpz(carry[i]);
        }
    }

    void bn254fr_bigint_convert_to_overflow_representation() {
        u32 overflow_bits = ctx_->stack_pop().as_u32();
        u32 bits          = ctx_->stack_pop().as_u32();
        u32 in_count      = ctx_->stack_pop().as_u32();
        u32 out_count     = ctx_->stack_pop().as_u32();
        u32 in_addr       = ctx_->stack_pop().as_u32();
        u32 out_addr      = ctx_->stack_pop().as_u32();

        auto val = compose_big_int(in_addr, in_count, bits);
        decompose_big_int_overflow(out_addr,
                                   out_count,
                                   val,
                                   bits,
                                   overflow_bits);
        ctx_->backend().manager().recycle_mpz(val);
    }

    void initialize() override {
        call_lookup_table_ = {
            // Memory management
            { "bn254fr_alloc",              &Self::bn254fr_alloc              },
            { "bn254fr_free",               &Self::bn254fr_free               },

            // Setters
            { "bn254fr_set_u32",            &Self::bn254fr_set_u32            },
            { "bn254fr_set_u64",            &Self::bn254fr_set_u64            },
            { "bn254fr_set_bytes",          &Self::bn254fr_set_bytes          },
            { "bn254fr_set_str",            &Self::bn254fr_set_str            },

            // Getters
            { "bn254fr_get_u64",            &Self::bn254fr_get_u64            },
            { "bn254fr_to_bytes",           &Self::bn254fr_to_bytes           },

            // Copy / Print
            { "bn254fr_copy",               &Self::bn254fr_copy               },
            { "bn254fr_print",              &Self::bn254fr_print              },

            // Constraint assertions
            { "bn254fr_assert_equal",       &Self::bn254fr_assert_equal       },
            { "bn254fr_assert_equal_u32",   &Self::bn254fr_assert_equal_u32   },
            { "bn254fr_assert_equal_u64",   &Self::bn254fr_assert_equal_u64   },
            { "bn254fr_assert_equal_bytes", &Self::bn254fr_assert_equal_bytes },
            { "bn254fr_assert_add",         &Self::bn254fr_assert_add         },
            { "bn254fr_assert_mul",         &Self::bn254fr_assert_mul         },
            { "bn254fr_assert_mulc",        &Self::bn254fr_assert_mulc        },

            // Checked bit operations
            { "bn254fr_to_bits_checked",    &Self::bn254fr_to_bits_checked    },
            { "bn254fr_from_bits_checked",  &Self::bn254fr_from_bits_checked  },

            // Arithmetic
            { "bn254fr_addmod",             &Self::bn254fr_addmod             },
            { "bn254fr_submod",             &Self::bn254fr_submod             },
            { "bn254fr_mulmod",             &Self::bn254fr_mulmod             },
            { "bn254fr_divmod",             &Self::bn254fr_divmod             },
            { "bn254fr_invmod",             &Self::bn254fr_invmod             },
            { "bn254fr_negmod",             &Self::bn254fr_negmod             },
            { "bn254fr_powmod",             &Self::bn254fr_powmod             },
            { "bn254fr_idiv",               &Self::bn254fr_idiv               },
            { "bn254fr_irem",               &Self::bn254fr_irem               },

            // Comparison
            { "bn254fr_eq",                 &Self::bn254fr_eq                 },
            { "bn254fr_lt",                 &Self::bn254fr_lt                 },
            { "bn254fr_lte",                &Self::bn254fr_lte                },
            { "bn254fr_gt",                 &Self::bn254fr_gt                 },
            { "bn254fr_gte",                &Self::bn254fr_gte                },
            { "bn254fr_eqz",                &Self::bn254fr_eqz                },

            // Logical
            { "bn254fr_land",               &Self::bn254fr_land               },
            { "bn254fr_lor",                &Self::bn254fr_lor                },

            // Bitwise
            { "bn254fr_band",               &Self::bn254fr_band               },
            { "bn254fr_bor",                &Self::bn254fr_bor                },
            { "bn254fr_bxor",               &Self::bn254fr_bxor               },
            { "bn254fr_bnot",               &Self::bn254fr_bnot               },

            // Unchecked bit operations
            { "bn254fr_to_bits",            &Self::bn254fr_to_bits            },
            { "bn254fr_from_bits",          &Self::bn254fr_from_bits          },

            // Shift
            { "bn254fr_shrmod",             &Self::bn254fr_shrmod             },
            { "bn254fr_shlmod",             &Self::bn254fr_shlmod             },

            // Bigint
            { "bn254fr_bigint_mul_checked_no_carry",
                &Self::bn254fr_bigint_mul_checked_no_carry },
            { "bn254fr_bigint_mul",
                &Self::bn254fr_bigint_mul },
            { "bn254fr_bigint_idiv",
                &Self::bn254fr_bigint_idiv },
            { "bn254fr_bigint_invmod",
                &Self::bn254fr_bigint_invmod },
            { "bn254fr_bigint_convert_to_proper_representation",
                &Self::bn254fr_bigint_convert_to_proper_representation },
            { "bn254fr_bigint_convert_to_proper_representation_signed",
                &Self::bn254fr_bigint_convert_to_proper_representation_signed },
            { "bn254fr_bigint_convert_to_proper_representation_unsigned",
                &Self::bn254fr_bigint_convert_to_proper_representation_unsigned },
            { "bn254fr_bigint_convert_to_overflow_representation",
                &Self::bn254fr_bigint_convert_to_overflow_representation },
            { "bn254fr_bigint_print",
                &Self::bn254fr_bigint_print },
        };
    }

    exec_result call_host(address_t addr, std::string_view name) override {
        if (!call_cache_.contains(addr)) {
            call_cache_[addr] = call_lookup_table_[name];
        }
        (this->*call_cache_[addr])();
        return exec_ok();
    }

    void finalize() override {
        // ctx_->backend().manager().finalize();
    }

protected:
    // Composes mpz value from big integer number represented as bn254fr array
    mpz_class *compose_big_int(u32 addr, u32 count, u32 bits) {
        auto sum = ctx_->backend().manager().acquire_mpz();

        // exp = 2^bits
        auto exp = ctx_->backend().manager().acquire_mpz();
        *exp = 1;

        for (size_t i = 0; i < count; i++) {
            auto *a_i = load_bn254(addr + i * sizeof(uint64_t));
            *sum = *sum + *a_i->value_ptr() * *exp;
            mpz_mul_2exp(exp->get_mpz_t(), exp->get_mpz_t(), bits);
        }

        ctx_->backend().manager().recycle_mpz(exp);

        return sum;
    }

    // Decomposes mpz value to big integer number represented as bn254fr array
    void decompose_big_int(u32 addr, u32 count, mpz_class *x, u32 bits) {
        auto curr_x = ctx_->backend().manager().acquire_mpz();
        *curr_x = *x;

        for (size_t i = 0; i < count; i++) {
            auto *a_i = load_bn254(addr + i * sizeof(uint64_t));

            mpz_fdiv_r_2exp(a_i->value_ptr()->get_mpz_t(),
                            curr_x->get_mpz_t(),
                            bits);
            *curr_x >>= bits;
        }

        ctx_->backend().manager().recycle_mpz(curr_x);
    }

    // Decomposes mpz value to big integer in overflow representation
    void decompose_big_int_overflow(u32 addr,
                                    u32 count,
                                    mpz_class *x,
                                    u32 bits,
                                    u32 overflow_bits) {
        auto curr_x = ctx_->backend().manager().acquire_mpz();
        *curr_x = *x;

        for (size_t i = 0; i < count; i++) {
            auto *x_i = load_bn254(addr + i * sizeof(uint64_t));

            // x_i = curr_x % 2^overflow_bits
            mpz_fdiv_r_2exp(x_i->value_ptr()->get_mpz_t(),
                            curr_x->get_mpz_t(),
                            overflow_bits);

            // curr_x = (curr_x - x_i) >> bits
            *curr_x = *curr_x - *x_i->value_ptr();
            mpz_fdiv_q_2exp(curr_x->get_mpz_t(), curr_x->get_mpz_t(), bits);
        }

        ctx_->backend().manager().recycle_mpz(curr_x);
    }

    // Composes mpz value from big integer number represented as array of
    // signed bn254fr limbs
    mpz_class *compose_big_int_signed(u32 addr, u32 count, u32 bits) {
        auto sum = ctx_->backend().manager().acquire_mpz();

        // exp = 2^bits
        auto exp = ctx_->backend().manager().acquire_mpz();
        *exp = 1;

        for (size_t i = 0; i < count; i++) {
            auto *a_i = load_bn254(addr + i * sizeof(uint64_t));
            if (*a_i->value_ptr() < Field::modulus_middle) {
                *sum = *sum + *a_i->value_ptr() * *exp;
            } else {
                *sum = *sum - (Field::modulus - *a_i->value_ptr()) * *exp;
            }

            mpz_mul_2exp(exp->get_mpz_t(), exp->get_mpz_t(), bits);
        }

        ctx_->backend().manager().recycle_mpz(exp);

        return sum;
    }

    /// Calculates value of polynomial at specified point
    zkp::managed_witness calc_poly_val(u32 addr, mpz_class *x, u32 count) {
        auto sum = ctx_->backend().acquire_witness();

        // sum = a_0
        auto *a_0 = load_bn254(addr);
        *sum->value_ptr() = *a_0->value_ptr();
        a_0->set_witness_status(true);
        ctx_->backend().manager().constrain_equal(*sum, *a_0);

        auto x_i = ctx_->backend().manager().acquire_mpz();
        *x_i = *x;

        for (size_t i = 1; i < count; i++) {
            auto *a_i = load_bn254(addr + i * sizeof(uint64_t));

            // x_i_mul = a_i * x_i
            auto x_i_mul = ctx_->backend().acquire_witness();
            Field::mulmod(*x_i_mul->value_ptr(), *a_i->value_ptr(), *x_i);
            a_i->set_witness_status(true);
            ctx_->backend().manager().constrain_quadratic_constant(*x_i_mul,
                                                                   *a_i,
                                                                   *x_i);

            // sum += x_i_mul
            auto sum_tmp = ctx_->backend().acquire_witness();
            Field::addmod(*sum_tmp->value_ptr(),
                          *sum->value_ptr(),
                          *x_i_mul->value_ptr());
            ctx_->backend().manager().constrain_linear(*sum_tmp, *sum, *x_i_mul);
            sum = sum_tmp;

            // x_i = x_i * x
            Field::mulmod(*x_i, *x_i, *x);
        }

        ctx_->backend().manager().recycle_mpz(x_i);

        return sum;
    }

    // Asserts polynomial c is equal to multiplication of polynomials a and b.
    // a_addr should point to array of length `a_count`
    // a_addr should point to array of length `b_count`
    // c_addr should point to array of length `a_count + b_count - 1`
    void bn254fr_assert_poly_mul(u32 c_addr,
                                 u32 a_addr,
                                 u32 b_addr,
                                 u32 a_count,
                                 u32 b_count) {
        auto x = ctx_->backend().manager().acquire_mpz();

        auto c_count = a_count + b_count - 1;
        for (u32 i = 0; i <= c_count; ++i) {
            *x = i;

            auto a_val = calc_poly_val(a_addr, x, a_count);
            auto b_val = calc_poly_val(b_addr, x, b_count);
            auto c_val = calc_poly_val(c_addr, x, c_count);

            ctx_->backend().manager().constrain_quadratic(c_val.get(),
                                                          a_val.get(),
                                                          b_val.get());
        }

        ctx_->backend().manager().recycle_mpz(x);
    }


    Context *ctx_;

    std::unordered_map<std::string_view, host_function_type> call_lookup_table_;
    std::unordered_map<address_t, host_function_type> call_cache_;
};


} // namespace ligero::vm
