#pragma once

#include <bit>
#include <gmp.h>
#include <util/recycle_pool.hpp>
#include <util/log.hpp>
#include <zkp/backend/lazy_witness.hpp>
#include <zkp/backend/witness_manager.hpp>
#include <host_modules/host_interface.hpp>

namespace ligero::vm {

template <typename Context>
struct uint256_module : public host_module {
    using Field = typename Context::field_type;
    using Self  = uint256_module<Context>;
    typedef void (Self::*host_function_type)();
    static constexpr size_t nlimbs = 4;
    static constexpr auto limb_bits = 64;

    struct uint256_data {
        zkp::lazy_witness* limbs[nlimbs];
    };
    
    static constexpr auto module_name = "uint256";

    uint256_module(Context *ctx) : ctx_(ctx) {}

    zkp::lazy_witness* load_bn254(u32 bn254_addr) {
        uintptr_t ptr = ctx_->template memory_load<uintptr_t>(bn254_addr);
        zkp::lazy_witness* ret = std::bit_cast<zkp::lazy_witness*>(ptr);
        return ret;
    }

    uint256_data load_uint256(u32 uint256_addr) {
        uint256_data data;
        for (size_t i = 0; i < nlimbs; ++i) {
            data.limbs[i] = load_bn254(uint256_addr + i * sizeof(uint64_t));
        }

        return data;
    }

    // Decompose unt256 value stored in mpz into limbs
    void uint256_decompose(const uint256_data &uint256, mpz_class *mpz) {
        for (size_t i = 0; i < nlimbs; ++i) {
            // limb[i] = value & (2^limb_bits - 1)
            mpz_fdiv_r_2exp(uint256.limbs[i]->value_ptr()->get_mpz_t(),
                            mpz->get_mpz_t(),
                            limb_bits);

            // mpz = mpz >> limb_bits
            mpz_fdiv_q_2exp(mpz->get_mpz_t(), mpz->get_mpz_t(), limb_bits);
        }
    }

    // Compose uint256 value stored in limbs into single mpz value
    void uint256_compose(mpz_class *mpz, const uint256_data &uint256) {
        *mpz = *uint256.limbs[nlimbs - 1]->value_ptr();

        for (size_t i = 1; i < nlimbs; ++i) {
            *mpz <<= limb_bits;
            *mpz |= *uint256.limbs[nlimbs - i - 1]->value_ptr();
        }
    }

    void uint256_set_bytes_little() {
        u32 size       = ctx_->stack_pop().as_u32();
        u32 data_addr  = ctx_->stack_pop().as_u32();
        u32 uint256_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto uint256 = load_uint256(uint256_addr);

        auto tmp = ctx_->backend().manager().acquire_mpz();
        mpz_import(tmp->get_mpz_t(),
                   size,
                   -1,
                   sizeof(u8),
                   -1,
                   0,
                   mem + data_addr);
        
        uint256_decompose(uint256, tmp);

        ctx_->backend().manager().recycle_mpz(tmp);
    }

    void uint256_set_bytes_big() {
        u32 size       = ctx_->stack_pop().as_u32();
        u32 data_addr  = ctx_->stack_pop().as_u32();
        u32 uint256_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto uint256 = load_uint256(uint256_addr);

        auto tmp = ctx_->backend().manager().acquire_mpz();
        mpz_import(tmp->get_mpz_t(),
                   size,
                   1,
                   sizeof(u8),
                   1,
                   0,
                   mem + data_addr);

        uint256_decompose(uint256, tmp);

        ctx_->backend().manager().recycle_mpz(tmp);
    }

    void uint256_set_str() {
        u32 base       = ctx_->stack_pop().as_u32();
        u32 str_addr   = ctx_->stack_pop().as_u32();
        u32 uint256_addr = ctx_->stack_pop().as_u32();
        auto *mem = ctx_->memory_data().data();

        auto uint256 = load_uint256(uint256_addr);

        auto tmp = ctx_->backend().manager().acquire_mpz();
        int failed = mpz_set_str(
                tmp->get_mpz_t(),
                reinterpret_cast<const char *>(mem) + str_addr,
                base);

        if (failed) {
            LIGERO_LOG_ERROR
                << "Error parsing string \""
                << (const char*)(mem + str_addr)
                << "\", did you forget the prefix \"0x\"?";
            throw wasm_trap("bad conversion");
        }

        uint256_decompose(uint256, tmp);

        ctx_->backend().manager().recycle_mpz(tmp);
    }

    void uint256_print() {
        u32 uint256_addr = ctx_->stack_pop().as_u32();

        auto uint256 = load_uint256(uint256_addr);

        auto value = ctx_->backend().manager().acquire_mpz();
        uint256_compose(value, uint256);
        printf("@uint256_print: val=");
        gmp_printf("%Zx\n", value);

        ctx_->backend().manager().recycle_mpz(value);
    }

    void uint512_idiv_normalized() {
        u32 b_addr      = ctx_->stack_pop().as_u32();
        u32 a_high_addr = ctx_->stack_pop().as_u32();
        u32 a_low_addr  = ctx_->stack_pop().as_u32();
        u32 r_addr      = ctx_->stack_pop().as_u32();
        u32 q_high_addr = ctx_->stack_pop().as_u32();
        u32 q_low_addr  = ctx_->stack_pop().as_u32();

        auto b      = load_uint256(b_addr);
        auto a_high = load_uint256(a_high_addr);
        auto a_low  = load_uint256(a_low_addr);
        auto r      = load_uint256(r_addr);
        auto q_high = load_bn254(q_high_addr);
        auto q_low  = load_uint256(q_low_addr);

        // compose a_low limbs into a value
        auto *a_val = ctx_->backend().manager().acquire_mpz();
        uint256_compose(a_val, a_high);

        // add a_high limbs to a value
        for (size_t i = 0; i < nlimbs; ++i) {
            *a_val <<= limb_bits;
            *a_val |= *a_low.limbs[nlimbs - 1 - i]->value_ptr();
        }

        // compose b limbs into b value
        auto *b_val = ctx_->backend().manager().acquire_mpz();
        uint256_compose(b_val, b);

        // perform integed division
        auto *q_val = ctx_->backend().manager().acquire_mpz();
        auto *r_val = ctx_->backend().manager().acquire_mpz();
        mpz_fdiv_qr(q_val->get_mpz_t(),
                    r_val->get_mpz_t(),
                    a_val->get_mpz_t(),
                    b_val->get_mpz_t());

        // decompose q into q_low limbs
        for (size_t i = 0; i < nlimbs; ++i) {
            mpz_fdiv_r_2exp(q_low.limbs[i]->value_ptr()->get_mpz_t(),
                            q_val->get_mpz_t(),
                            limb_bits);
            *q_val >>= limb_bits;
        }

        // move rest of q decomposition into q_high
        mpz_fdiv_r_2exp(q_high->value_ptr()->get_mpz_t(),
                        q_val->get_mpz_t(),
                        limb_bits);

        // decompose r value into limbs
        uint256_decompose(r, r_val);

        ctx_->backend().manager().recycle_mpz(a_val);
        ctx_->backend().manager().recycle_mpz(b_val);
        ctx_->backend().manager().recycle_mpz(q_val);
        ctx_->backend().manager().recycle_mpz(r_val);
    }

    void uint256_invmod() {
        u32 m_addr =   ctx_->stack_pop().as_u32();
        u32 a_addr =   ctx_->stack_pop().as_u32();
        u32 out_addr = ctx_->stack_pop().as_u32();

        auto out = load_uint256(out_addr);
        auto a   = load_uint256(a_addr);
        auto m   = load_uint256(m_addr);

        auto *a_val = ctx_->backend().manager().acquire_mpz();
        auto *m_val = ctx_->backend().manager().acquire_mpz();

        uint256_compose(a_val, a);
        uint256_compose(m_val, m);

        mpz_invert(a_val->get_mpz_t(), a_val->get_mpz_t(), m_val->get_mpz_t());

        uint256_decompose(out, a_val);

        ctx_->backend().manager().recycle_mpz(a_val);
        ctx_->backend().manager().recycle_mpz(m_val);
    }

    void initialize() override {
        call_lookup_table_ = {
            { "uint256_set_bytes_little",   &Self::uint256_set_bytes_little   },
            { "uint256_set_bytes_big",      &Self::uint256_set_bytes_big      },
            { "uint256_set_str",            &Self::uint256_set_str            },
            { "uint256_print",              &Self::uint256_print              },
            { "uint512_idiv_normalized",    &Self::uint512_idiv_normalized    },
            { "uint256_invmod",             &Self::uint256_invmod             },
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
