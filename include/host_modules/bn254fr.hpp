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
        uintptr_t ptr = 0;
        std::memcpy(&ptr, ctx_->memory() + bn254_addr, sizeof(ptr));
        zkp::lazy_witness* ret = std::bit_cast<zkp::lazy_witness*>(ptr);
        return ret;
    }

    void store_bn254(u32 bn254_addr, zkp::lazy_witness *ptr) {
        uintptr_t val = std::bit_cast<uintptr_t>(ptr);
        std::memcpy(ctx_->memory() + bn254_addr, &val, sizeof(val));
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

    void bn254fr_set_u32() {
        u32 ui         = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
        *wit->value_ptr() = ui;
    }

    void bn254fr_set_u64() {
        u64 ull        = ctx_->stack_pop().as_u64();
        u32 bn254_addr = ctx_->stack_pop().as_u32();

        auto *wit = load_bn254(bn254_addr);
        mpz_assign(*wit->value_ptr(), ull);
    }

    void bn254fr_set_bytes() {
        s32 order      = ctx_->stack_pop().as_u32();
        u32 size       = ctx_->stack_pop().as_u32();
        u32 data_addr  = ctx_->stack_pop().as_u32();
        u32 bn254_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory();

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
        auto *mem = ctx_->memory();

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
        ctx_->stack_push(static_cast<uint64_t>(wit->value_ptr()->get_ui()));
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
        //    u32 bi_addr = *(reinterpret_cast<const u32*>(ctx_->memory() + arr_addr) + i);
        //    auto *bi = load_bn254(bi_addr);
            auto *bi = load_bn254(arr_addr + i * sizeof(uint64_t));
            *bi->value_ptr() = (*x->value_ptr()) >> i & 1u;
        }
    }

    void initialize() override {
        call_lookup_table_ = {
            { "bn254fr_alloc",              &Self::bn254fr_alloc              },
            { "bn254fr_free",               &Self::bn254fr_free               },

            { "bn254fr_set_u32",            &Self::bn254fr_set_u32            },
            { "bn254fr_set_u64",            &Self::bn254fr_set_u64            },
            { "bn254fr_set_bytes",          &Self::bn254fr_set_bytes          },
            { "bn254fr_set_str",            &Self::bn254fr_set_str            },

            { "bn254fr_get_u64",            &Self::bn254fr_get_u64            },

            { "bn254fr_copy",               &Self::bn254fr_copy               },
            { "bn254fr_print",              &Self::bn254fr_print              },

            { "bn254fr_assert_equal",       &Self::bn254fr_assert_equal       },
            { "bn254fr_assert_add",         &Self::bn254fr_assert_add         },
            { "bn254fr_assert_mul",         &Self::bn254fr_assert_mul         },
            { "bn254fr_assert_mulc",        &Self::bn254fr_assert_mulc        },

            { "bn254fr_addmod",             &Self::bn254fr_addmod             },
            { "bn254fr_submod",             &Self::bn254fr_submod             },
            { "bn254fr_mulmod",             &Self::bn254fr_mulmod             },
            { "bn254fr_divmod",             &Self::bn254fr_divmod             },
            { "bn254fr_invmod",             &Self::bn254fr_invmod             },
            { "bn254fr_negmod",             &Self::bn254fr_negmod             },
            { "bn254fr_powmod",             &Self::bn254fr_powmod             },
            { "bn254fr_idiv",               &Self::bn254fr_idiv               },
            { "bn254fr_irem",               &Self::bn254fr_irem               },

            { "bn254fr_eq",                 &Self::bn254fr_eq                 },
            { "bn254fr_lt",                 &Self::bn254fr_lt                 },
            { "bn254fr_lte",                &Self::bn254fr_lte                },
            { "bn254fr_gt",                 &Self::bn254fr_gt                 },
            { "bn254fr_gte",                &Self::bn254fr_gte                },
            { "bn254fr_eqz",                &Self::bn254fr_eqz                },

            { "bn254fr_land",               &Self::bn254fr_land               },
            { "bn254fr_lor",                &Self::bn254fr_lor                },

            { "bn254fr_band",               &Self::bn254fr_band               },
            { "bn254fr_bor",                &Self::bn254fr_bor                },
            { "bn254fr_bxor",               &Self::bn254fr_bxor               },
            { "bn254fr_bnot",               &Self::bn254fr_bnot               },

            { "bn254fr_to_bits",            &Self::bn254fr_to_bits            },

            { "bn254fr_shrmod",             &Self::bn254fr_shrmod             },
            { "bn254fr_shlmod",             &Self::bn254fr_shlmod             },
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
    Context *ctx_;
    
    std::unordered_map<std::string_view, host_function_type> call_lookup_table_;
    std::unordered_map<address_t, host_function_type> call_cache_;
};


} // namespace ligero::vm
