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

#include <exception>
#include <tuple>
#include <limits>
#include <bit>

#include <interpreter_impl.hpp>
#include <opcode.hpp>
#include <prelude.hpp>
#include <runtime.hpp>
#include <stack_value.hpp>
#include <types.hpp>

namespace ligero::vm {

template <typename Context>
struct wasm_interpreter : opcode_interpreter<Context> {
    wasm_interpreter(Context& ctx)
        : opcode_interpreter<Context>(ctx),
          ctx_(ctx)
        { }

    Context&       context()       { return ctx_; }
    const Context& context() const { return ctx_; }

    exec_result run(opcode op) {
        // std::cout << opcode::to_string(op.tag) << std::endl;
        auto fn = opcode_interpreter<Context>::opcode_dispatch_table[op.tag];
        this->increase_opcode_count(op);
        return (this->*fn)(op);
    }

    exec_result run(const instr_ptr& ptr) {
        return run(*ptr);
    }

    exec_result run(const structured_instr& ins) {
        // std::cout << ins.name() << std::endl;
        switch(ins.kind) {
            case structured_instr::basic_block:
                return run_basic_block(static_cast<const basic_block&>(ins));
            case structured_instr::scoped_block:
                return run_scoped_block(static_cast<const scoped_block&>(ins));
            case structured_instr::loop:
                return run_loop(static_cast<const loop&>(ins));
            case structured_instr::if_then_else:
                return run_if_then_else(static_cast<const if_then_else&>(ins));
            case structured_instr::br:
                return run_br(static_cast<const br&>(ins));
            case structured_instr::br_if:
                return run_br_if(static_cast<const br_if&>(ins));
            case structured_instr::br_table:
                return run_br_table(static_cast<const br_table&>(ins));
            case structured_instr::call:
                return run_call(static_cast<const call&>(ins));
            case structured_instr::call_indirect:
                return run_call_indirect(static_cast<const call_indirect&>(ins));
            case structured_instr::ret:
                return run_return(static_cast<const ret&>(ins));
            default:
                std::cout << "Unexpected structured block" << std::endl;
                std::abort();
        }
    }


    exec_result run_basic_block(const basic_block& block) {
        for (const auto& op : block.body) {
            run(op);
        }
        return exec_ok();
    }

    exec_result run_scoped_block(const scoped_block& block) {
        /* Entering block with Label L */
        u32 m = 0, n = 0;
        std::visit(prelude::overloaded {
                [&](index_t i) {
                    const auto& type = ctx_.module()->types[i];
                    m = type.params.size();
                    n = type.returns.size();
                },
                [&m, &n](const block_kind& k) {
                    m = k.params.size();
                    n = k.returns.size();
                }
            }, block.type);

        // std::cout << std::format("[Debug] Entering Block with m={}, n={}", m, n)
        //           << std::endl;

        ctx_.block_entry(m, n);

        for (const instr_ptr& instr : block.body) {
            auto ret = run(*instr);

            if (!ret.ok()) {
                ret.unwind();
                return ret;
            }
        }

        /* Exiting block with Label L if no jump happended */
        // std::cout << std::format("[Debug] Exiting Block with m={}, n={}", m, n)
        //           << std::endl;

        ctx_.drop_n_below(1, n);

        return exec_ok();
    }

    exec_result run_loop(const loop& block) {
        /* Entering block with Label L */
        u32 m = 0, n = 0;
        std::visit(prelude::overloaded {
                [&](index_t i) {
                    const auto& type = ctx_.module()->types[i];
                    m = type.params.size();
                    n = type.returns.size();
                },
                [&m, &n](const block_kind& k) {
                    m = k.params.size();
                    n = k.returns.size();
                }
            }, block.type);

    loop_start:
        // std::cout << std::format("[Debug] Entering Loop with m={}, n={}", m, n)
        //           << std::endl;

        /** Remember to enter the block each time we enter the loop */
        ctx_.block_entry(m, m);

        for (const auto& instr : block.body) {
            auto ret = run(*instr);

            if (!ret.ok()) {
                if (bool should_jump = ret.unwind()) {
                    goto loop_start;
                }
                else {
                    return ret;
                }
            }
        }

        /* Exiting block with Label L if no jump happended */

        // std::cout << std::format("[Debug] Exiting Loop with m={}, n={}", m, n)
        //           << std::endl;
        ctx_.drop_n_below(1, n);
        return exec_ok();
    }

    exec_result run_if_then_else(const if_then_else& branch) {
        u32 m = 0, n = 0;
        std::visit(prelude::overloaded {
                [&](index_t i) {
                    const auto& type = ctx_.module()->types[i];
                    m = type.params.size();
                    n = type.returns.size();
                },
                [&m, &n](const block_kind& k) {
                    m = k.params.size();
                    n = k.returns.size();
                }
            }, branch.type);

        auto tmp = ctx_.stack_pop();

        u32 c = ctx_.make_numeric(std::move(tmp)).as_u32();

        // std::cout << std::format("[Debug] Entering if-then-else with m={}, n={}", m, n)
        //           << std::endl;

        ctx_.block_entry(m, n);

        auto& ins_vec = c ? branch.then_body : branch.else_body;

        for (const instr_ptr& instr : ins_vec) {
            auto ret = run(*instr);

            if (!ret.ok()) {
                ret.unwind();
                return ret;
            }
        }

        // std::cout << std::format("[Debug] Exiting if-then-else with m={}, n={}", m, n)
        //           << std::endl;

        ctx_.drop_n_below(1, n);
        return exec_ok();
    }

    exec_result run_br(const br& b) {
        const int l = b.label;

        /* Find L-th label */
        auto it = prelude::find_if_n(ctx_.stack_top(), ctx_.stack_bottom(), l + 1,
                                     [](const auto& v) {
                                         return std::holds_alternative<label_t>(v.data());
                                     });
        assert(it != ctx_.stack_bottom());
        size_t distance = std::distance(ctx_.stack_top(), it);

        /* Pop unused stack values */
        const size_t n = it->as_label().arity;
        ctx_.drop_n_below(distance - n + 1, n);

        // std::cout << "<br " << l << "> ";
        // ctx_.show_stack();
        return exec_jump(l);
    }

    exec_result run_br_if(const br_if& b) {
        auto v = ctx_.stack_pop();

        u32 cond = ctx_.make_numeric(std::move(v)).as_u32();
        if (cond) {
            return run(br{ b.label });
        }
        return exec_ok();
    }

    exec_result run_br_table(const br_table& b) {
        auto v = ctx_.stack_pop();

        u32 i = ctx_.make_numeric(std::move(v)).as_u32();
        if (i < b.branches.size()) {
            return run(br{ b.branches[i] });
        }
        else {
            return run(br{ b.default_ });
        }
        return exec_ok();
    }

    exec_result run_return(const ret& r) {
        // std::cout << "Ret" << std::endl;
        const size_t arity = ctx_.current_frame()->arity;
        // auto top = stack_.rbegin() + arity;
        // auto it = top;

        auto frm = std::find_if(ctx_.stack_top(),
                                ctx_.stack_bottom(),
                                [](const auto& v) {
                                    return v.is_frame();
                                });
        assert(frm != ctx_.stack_bottom());
        size_t distance = std::distance(ctx_.stack_top(), frm);

        ctx_.drop_n_below(distance - arity + 1, arity);

        return exec_return();
    }

    exec_result run_call(const call& c) {
        address_t addr =  ctx_.current_frame()->module->funcaddrs[c.func];
        const function_instance& func = ctx_.store()->functions[addr];
        u32 params = func.kind.params.size();
        u32 arity = func.kind.returns.size();

        // const auto& param_kinds = func.kind.params;

        // std::cout << std::format("[Debug] Call function {} with m={}, n={}", addr, params, arity)
        //           << std::endl;

        // std::cout << fp->locals.size() << ", " << fp->arity << std::endl;

        /* Invoke the function (native function) */
        /* -------------------------------------------------- */
        if (auto *pcode = std::get_if<function_instance::func_code>(&func.code)) {
            /* Push arguments */
            /* -------------------------------------------------- */
            std::vector<stack_value> arguments;
            for (size_t i = 0; i < params; i++) {
                arguments.emplace_back(ctx_.stack_pop());
            }
            std::reverse(arguments.begin(), arguments.end());

            auto frame = std::make_unique<wasm_frame>();

            assert(frame.get() != nullptr);

            frame->arity = arity;
            frame->module = ctx_.module();
            frame->locals = std::move(arguments);

            for (const value_kind& type : pcode->locals) {
                switch (type) {
                case value_kind::i32:
                    frame->locals.emplace_back(u32{ 0UL });
                    break;
                case value_kind::i64:
                    frame->locals.emplace_back(u64{ 0ULL });
                    break;
                case value_kind::f32:
                    frame->locals.emplace_back(0.0f);
                    break;
                case value_kind::f64:
                    frame->locals.emplace_back(0.0);
                    break;
                default:
                    std::cout << "Unsupported local type" << std::endl;
                    std::abort();
                }
            }

            ctx_.set_current_frame(frame.get());
            ctx_.stack_push(std::move(frame));

            for (const auto& instr : pcode->body) {
                auto ret = run(*instr);

                if (ret.is_return()) {
                    // std::cout << std::format("[Debug] Return from {} with return", addr)
                    //           << std::endl;
                    return exec_ok();
                }
                else if (ret.is_exit()) {
                    // Unwind stack
                    auto it = std::find_if(ctx_.stack_top(), ctx_.stack_bottom(),
                                           [](const auto& v) {
                                               return v.is_frame();
                                           });
                    if (it != ctx_.stack_bottom()) {
                        size_t distance = std::distance(ctx_.stack_top(), it);
                        ctx_.drop_n_below(distance + 1, 0);
                    }

                    return ret;
                }
            }

            // Clean up if no jump happend during call

            // std::cout << std::format("[Debug] Return from {}", addr)
            //           << std::endl;
            ctx_.drop_n_below(1, arity);
        }
        /* Invoke host calls (handle arguments internally)    */
        /* -------------------------------------------------- */
        else {
            const auto& hostc = std::get<function_instance::host_code>(func.code);
            // std::cout << "calling " << hostc.module << ", " << hostc.name << std::endl;
            return ctx_.call_host(addr, hostc.module, hostc.name);
        }


        // std::cout << "<call[" << addr << "].exit>" << std::endl;
        return exec_ok();
    }

    exec_result run_call_indirect(const call_indirect& ins) {
        auto *f = ctx_.current_frame();
        address_t ta = f->module->tableaddrs[ins.table_index];
        table_instance& tab = ctx_.store()->tables[ta];

        u32 i = ctx_.stack_pop().as_u32();
        if (i >= tab.elem.size()) {
            throw wasm_trap("call_indirect: index out of bound");
        }

        reference_t r = tab.elem[i];
        if (!r) {
            std::cout << "table " << ta << "[" << i << "]";
            for (auto& ref : tab.elem) {
                if (ref)
                    std::cout << *ref << " ";
                else
                    std::cout << 0 << " ";
            }
            std::cout << std::endl;
            throw wasm_trap("call_indirect: null pointer");
        }

        // TODO: check type match
        return run(call{ *r });
    }

private:
    Context& ctx_;
};



}  // namespace ligero::vm
