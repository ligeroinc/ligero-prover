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

#include <runtime.hpp>
#include <host_modules/env.hpp>
#include <host_modules/bn254fr.hpp>
#include <host_modules/vbn254fr.hpp>
#include <host_modules/wasi_preview1.hpp>
#include <host_modules/uint256.hpp>
#include <util/timer.hpp>
#include <interpreter.hpp>

#include <wabt/binary-reader-ir.h>
#include <wabt/binary-reader.h>

namespace ligero::vm {

template <typename Interpreter>
void invoke(module_instance& module,
            Interpreter& interp,
            const std::vector<std::vector<u8>>& args,
            const std::unordered_set<int>& indices)
{
    auto& ctx = interp.context();
    
    auto dummy = ctx.make_frame();
    dummy->module = &module;

    ctx.set_current_frame(dummy.get());
    ctx.stack_push(std::move(dummy));

    using Context = std::remove_reference_t<decltype(ctx)>;
    ctx.template add_host_module<wasi_preview1_module<Context>>(&ctx, args, indices);
    ctx.template add_host_module<env_module<Context>>(&ctx);
    ctx.template add_host_module<bn254fr_module<Context>>(&ctx);
    ctx.template add_host_module<vbn254fr_module<Context>>(&ctx);
    ctx.template add_host_module<uint256_module<Context>>(&ctx);
    // ctx.template add_host_module<zkp::rescue_prime_module<Context>>(&ctx);

    // if constexpr (requires { Context::support_RAM; }) {
    //     ctx.template add_host_module<RAM_module<Context>>(&ctx);
    // }

    // std::cout << "Parameters: ";
    // exe.context().show_stack();
    try {
        auto result = interp.run(call{ module.exports["_start"] });
        if (result.is_exit()) {
            std::cout << "Exit with code " << result.exit_code() << std::endl;
        }
    }
    catch (const wasm_trap& e) {
        throw e;
    }

    interp.context().stack_pop();  // Pop dummy frame
    
    // std::cout << "Result: ";
    // exe.context().show_stack();
}

template <typename Context>
void run_program(const wabt::Module& module,
                 Context& ctx,
                 const std::vector<std::vector<u8>>& args,
                 const std::unordered_set<int>& indices)
{
    auto t = make_timer("Instantiate");
    store_t store;
    wasm_interpreter interp(ctx);
    ctx.store(&store);
    
    module_instance m = instantiate(store, module, interp);
    ctx.module(&m);
    t.stop();

    invoke(m, interp, args, indices);
    ctx.finalize();

    // interp.display_opcode_count();
}

}  // namespace ligero::vm
