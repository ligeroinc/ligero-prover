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

#include <util/log.hpp>
#include <boost/algorithm/hex.hpp>
#include <host_modules/host_interface.hpp>

namespace ligero::vm {

template <typename Context>
struct env_module : public host_module {
    using Self = env_module<Context>;
    using witness_type = typename Context::witness_type;
    typedef void (Self::*host_function_type)();

    constexpr static auto module_name = "env";

    env_module() = default;
    env_module(Context *ctx) : ctx_(ctx) { }

    // /* -------------------------------------------------- */

    void assert_zero() {
    /*
        if (var.val() != 0) {
            LIGERO_LOG_ERROR
                << std::format("Assertion failed: expect 0, got {}", var.val());
        }
    */
        auto s = ctx_->stack_pop();
        auto wit = ctx_->make_witness(std::move(s));
        ctx_->backend().assert_const(wit, 0);
    }

    void assert_one() {
    /*
        if (var.val() != 1) {
            LIGERO_LOG_ERROR
                << std::format("Assertion failed: expect 1, got {}", var.val());
        }
    */
        auto s = ctx_->stack_pop();
        auto wit = ctx_->make_witness(std::move(s));
        ctx_->backend().assert_const(wit, 1);
    }

    void assert_equal() {
        auto sy = ctx_->stack_pop();
        auto sx = ctx_->stack_pop();

        auto wx = ctx_->make_witness(std::move(sx));
        auto wy = ctx_->make_witness(std::move(sy));

        if (wx.val() != wy.val()) {
            LIGERO_LOG_ERROR << "Assertion failed: "
                             << wx.val() << " != " << wy.val();
        }

        ctx_->backend().assert_equal(wx, wy);
    }

    void assert_constant() {
        auto s = ctx_->stack_pop();
        auto wit = ctx_->make_witness(std::move(s));
        ctx_->backend().assert_const(wit, wit.val());
        // ctx_->backend().assert_const(var, mpz_promote(var.val()));
    }

    void witness_cast() {
        auto sx = ctx_->stack_pop();
        auto wx = ctx_->make_witness(std::move(sx));
        ctx_->stack_push(wx);
    }

    void print_str() {
        u32 len = ctx_->stack_pop().as_u32();
        u32 ptr = ctx_->stack_pop().as_u32();

        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& memi = ctx_->store()->memorys[addr];
        auto *mem = reinterpret_cast<const unsigned char*>(memi.data.data());
        // std::cout << "@print str: ";
        // std::cout << std::hex << std::setw(2) << std::setfill('0');
        for (size_t i = 0; i < len; i++) {
            std::cout << mem[ptr + i];
        }
        // std::cout << std::endl;
    }

    void dump_memory() {
        u32 len = ctx_->stack_pop().as_u32();
        u32 ptr = ctx_->stack_pop().as_u32();

        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& memi = ctx_->store()->memorys[addr];
        auto *mem = reinterpret_cast<const unsigned char*>(memi.data.data());
        std::cout << "@dump: ";

        std::string tmp;
        boost::algorithm::hex(mem + ptr,
                              mem + ptr + len,
                              std::back_inserter(tmp));
        // std::vector<unsigned char> tmp(mem + ptr, mem + ptr + len);
        std::cout << tmp << std::endl;
        // std::cout << std::hex << std::setw(2) << std::setfill('0');
        // for (size_t i = 0; i < len; i++) {
        //     std::cout << int(mem[ptr + i]);
        // }
        // std::cout << std::dec << std::setw(0) << std::endl;
    }

    void file_size_get() {
        u64 name_ptr = ctx_->stack_pop().as_u64();

        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& memi = ctx_->store()->memorys[addr];
        auto *mem = reinterpret_cast<const char*>(memi.data.data());

        std::filesystem::path p{ mem + name_ptr };
        u32 len = std::filesystem::file_size(p);
        // std::cout << "@file " << p << " size is " << len << std::endl;
        ctx_->stack_push(len);
    }

    void file_get() {
        u64 name_ptr = ctx_->stack_pop().as_u64();
        u64 buf_ptr  = ctx_->stack_pop().as_u64();

        address_t addr = ctx_->module()->memaddrs[0];
        memory_instance& memi = ctx_->store()->memorys[addr];
        auto *mem = reinterpret_cast<char*>(memi.data.data());

        std::filesystem::path p{ mem + name_ptr };
        u32 len = std::filesystem::file_size(p);

        std::ifstream ifs(p, std::ios::binary);
        if (!ifs.read(mem + buf_ptr, len)) {
            throw wasm_trap("Cannot read file "s + p.string());
        }

        ctx_->stack_push(len);
    }

    void i32_private_const() {
        u32 v = ctx_->stack_pop().as_u32();
        auto x = ctx_->backend().acquire_witness();
        x.val(v);
        ctx_->stack_push(std::move(x));
    }

    void i64_private_const() {
        u64 v = ctx_->stack_pop().as_u64();
        auto x = ctx_->backend().acquire_witness();
        x.val(v);
        ctx_->stack_push(std::move(x));
    }

    void initialize() override {
        call_lookup_table_ = {
            { "assert_zero",       &Self::assert_zero        },
            { "assert_one",        &Self::assert_one         },
            { "assert_equal",      &Self::assert_equal       },
            { "assert_constant",   &Self::assert_constant    },
            { "witness_cast_u32",  &Self::witness_cast       },
            { "witness_cast_u64",  &Self::witness_cast       },
            { "i32_private_const", &Self::i32_private_const  },
            { "i64_private_const", &Self::i64_private_const  },
            // { "print",             &Self::print              },
            { "print_str",         &Self::print_str          },
            { "dump_memory",       &Self::dump_memory        },
            { "file_size_get",     &Self::file_size_get      },
            { "file_get",          &Self::file_get           },
        };
    }

    exec_result call_host(address_t global_id, std::string_view name) override {
        (this->*call_lookup_table_[name])();
        return exec_ok();
    }

    void finalize()   override { }

protected:
    Context *ctx_;
    std::unordered_map<std::string_view, host_function_type> call_lookup_table_;
};

} // namespace ligero::vm
