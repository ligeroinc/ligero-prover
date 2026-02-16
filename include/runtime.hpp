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

#include <instruction.hpp>
#include <prelude.hpp>
#include <stack_value.hpp>
#include <transpiler.hpp>
#include <types.hpp>

#include <optional>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include <boost/icl/interval_set.hpp>
#include <boost/icl/discrete_interval.hpp>

using namespace boost;

namespace ligero::vm {

// Forward Declaration
/* ------------------------------------------------------------ */
struct function_instance;
struct table_instance;
struct memory_instance;
struct global_instance;
struct element_instance;
struct data_instance;
// struct export_instance;


// Module Instance
/* ------------------------------------------------------------ */
struct module_instance {
    module_instance() = default;
    
    std::vector<function_kind> types;
    std::vector<address_t> funcaddrs;
    std::vector<address_t> tableaddrs;
    std::vector<address_t> memaddrs;
    std::vector<address_t> globaladdrs;
    std::vector<address_t> elemaddrs;
    std::vector<address_t> dataaddrs;
    // std::vector<export_instance> exports;
    std::unordered_map<std::string, u32> exports;
};

// Function Instance
/* ------------------------------------------------------------ */
struct function_instance {
    struct func_code {
        index_t type_index;
        std::vector<value_kind> locals;
        std::vector<instr_ptr>  body;
    };

    struct host_code {
        index_t type_index;
        std::string module, name;
    };

    function_instance(function_kind k) : kind(k) { }
    function_instance(function_kind k, const module_instance *module) : kind(k), module(module) { }

    template <typename T>
    function_instance(name_t name, function_kind k, const module_instance *module, T&& code)
        : name(name), kind(k), module(module), code(std::move(code)) { }

    name_t name;
    function_kind kind;
    const module_instance *module = nullptr;
    std::variant<func_code, host_code> code;
};

// Table Instance
/* ------------------------------------------------------------ */
struct table_instance {
    table_instance(table_kind k, const std::vector<reference_t>& e)
        : kind(k), elem(e) { }
    
    table_kind kind;
    std::vector<reference_t> elem;
};

// Memory Instance
/* ------------------------------------------------------------ */
struct memory_instance {
    constexpr static size_t page_size = 65536;  /* 64KB */
    memory_instance(memory_kind k, size_t mem_size) : kind(k), data(mem_size, 0) { }

    void mark_secret_closed(u32 begin, u32 end) {
        // std::cout << "mark[" << begin << " - " << end << "]" << std::endl;
        secret_set_ += icl::discrete_interval<u32>::right_open(begin, end);
    }

    void unmark_closed(u32 begin, u32 end) {
        // std::cout << "unmark[" << begin << " - " << end << "]" << std::endl;
        secret_set_ -= icl::discrete_interval<u32>::right_open(begin, end);
    }

    bool contains_secret(u32 begin, u32 end) {
        bool overlap = icl::intersects(secret_set_, icl::discrete_interval<u32>::right_open(begin, end));
        return overlap;
    }

    bool contains_secret(u32 x) {
        return icl::contains(secret_set_, x);
    }

    void memcpy_secrets(u32 dst, const u32 src, size_t count) {
        if (src + count > data.size()) {
            throw wasm_trap("memcpy_secrets: src out of range");
        }

        if (dst + count > data.size()) {
            throw wasm_trap("memcpy_secrets: dst out of range");
        }

        // Step 1: Collect all intervals overlap with range [src, src + count)
        //          and map it to [dst, dst + count)
        icl::interval_set<u32> dst_secret_set;
        auto src_range = icl::discrete_interval<u32>::right_open(src, src + count);
        auto [sec_begin, sec_end] = secret_set_.equal_range(src_range);
        const u32 offset = dst - src;

        for (auto it = sec_begin; it != sec_end; ++it) {
            const u32 dst_lower = it->lower() + offset;
            const u32 dst_upper = it->upper() + offset;
            auto dst_interval = icl::discrete_interval<u32>::right_open(dst_lower,
                                                                        dst_upper);

            dst_secret_set += dst_interval;
        }

        // Step 2: Unmark all secrets within [dst, dst + count)
        auto dst_range = icl::discrete_interval<u32>::right_open(dst, dst + count);
        secret_set_ -= dst_range;

        // Step 3: Add the intersection of adjusted src and [dst, dst + count)
        //         to secret set since the set from step 1 may contain
        //         out of range intervals.
        secret_set_ += dst_secret_set & dst_range;

        // Use std::memmove to handle overlapping case
        std::memmove(data.data() + dst, data.data() + src, count);
    }
    
    memory_kind kind;
    std::vector<u8> data;
    icl::interval_set<u32> secret_set_;
};

// Global Instance
/* ------------------------------------------------------------ */
struct global_instance {
    template <typename T>
    global_instance(value_kind k, const T& v) : kind(k), val(v) { }
    
    value_kind kind;
    native_numeric val;
};

// Element Instance
/* ------------------------------------------------------------ */
struct element_instance {
    element_instance(value_kind k, const std::vector<reference_t>& vec) : kind(k), elem(vec) { }

    value_kind kind;
    std::vector<reference_t> elem;
    
    // element_instance(value_kind k, index_t table_index, instr_vec&& offset, std::vector<instr_vec>&& exprs)
    //     : kind(k), table(table_index), offset_expr(std::move(offset)), elem_expr(std::move(exprs)) { }

    // value_kind kind;
    // index_t table;
    // instr_vec offset_expr;
    // std::vector<instr_vec> elem_expr;
};

// Data Instance
/* ------------------------------------------------------------ */
struct data_instance{ 
    data_instance(const std::vector<u8>& d) : data(d) { }
    std::vector<u8> data;
};

// Export Instance
/* ------------------------------------------------------------ */

// Store
/* ------------------------------------------------------------ */
struct store_t {
    store_t() = default;

    template <typename T, typename... Args>
    index_t emplace_back(Args&&... args) {
        if constexpr (std::is_same_v<T, function_instance>) {
            size_t index = functions.size();
            functions.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else if constexpr (std::is_same_v<T, table_instance>) {
            size_t index = tables.size();
            tables.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else if constexpr (std::is_same_v<T, memory_instance>) {
            size_t index = memorys.size();
            memorys.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else if constexpr (std::is_same_v<T, global_instance>) {
            size_t index = globals.size();
            globals.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else if constexpr (std::is_same_v<T, element_instance>) {
            size_t index = elements.size();
            elements.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else if constexpr (std::is_same_v<T, data_instance>) {
            size_t index = datas.size();
            datas.emplace_back(std::forward<Args>(args)...);
            return index;
        }
        else {
            // C++20 Compile-time magic
            []<bool flag = false>{ static_assert(flag, "Unexpected instance type"); }();
        }
    }
    
    std::vector<function_instance> functions;
    std::vector<table_instance> tables;
    std::vector<memory_instance> memorys;
    std::vector<global_instance> globals;
    std::vector<element_instance> elements;
    std::vector<data_instance> datas;
};


/* ------------------------------------------------------------ */
index_t allocate_function(store_t& store,
                          const module_instance *inst,
                          const wabt::Func& func,
                          bool is_imported = false,
                          std::string module_name = "",
                          std::string field_name = "") {
    std::vector<value_kind> local_type;
    for (const auto& type : func.local_types) {
        local_type.push_back(transpile_wabt_type(type));
    }

    std::vector<instr_ptr> body = transpile(func.exprs.begin(), func.exprs.end());
    // for (const auto& expr : func.exprs) {
    //     body.push_back(transpile(expr));
    // }

    std::vector<value_kind> param, result;
    for (const auto& type : func.decl.sig.param_types) {
        param.push_back(transpile_wabt_type(type));
    }

    for (const auto& type : func.decl.sig.result_types) {
        result.push_back(transpile_wabt_type(type));
    }

    std::variant<function_instance::func_code, function_instance::host_code> code;
    if (is_imported) {
        code = function_instance::host_code {
            func.decl.type_var.index(),
            module_name,
            field_name
        };
    }
    else {
        code = function_instance::func_code {
            func.decl.type_var.index(),
            std::move(local_type),
            std::move(body)
        };
    }

    return store.emplace_back<function_instance>(func.name,
                                                 function_kind{
                                                     std::move(param),
                                                     std::move(result) },
                                                 inst,
                                                 std::move(code));
}

index_t allocate_table(store_t& store,
                       const wabt::Table& table,
                       reference_t init_val = std::nullopt)
{
    limits limit{ table.elem_limits.initial };
    if (table.elem_limits.has_max)
        limit.max.emplace(table.elem_limits.max);

    value_kind type = transpile_wabt_type(table.elem_type);
    return store.emplace_back<table_instance>(
        table_kind{ type, limit },
        std::vector<reference_t>(table.elem_limits.initial, init_val));
}


index_t allocate_memory(store_t& store, const wabt::Memory& memory) {
    limits limit{ memory.page_limits.initial };
    if (memory.page_limits.has_max)
        limit.max.emplace(memory.page_limits.max);

    size_t memory_size = std::max<u64>(limit.min, 256) + 128; // 16MB heap + 8MB stack
    
    return store.emplace_back<memory_instance>(memory_kind{ limit },
                                               memory_instance::page_size * memory_size);
}

template <typename Executor>
module_instance instantiate(store_t& store, const wabt::Module& module, Executor& exe) {
    module_instance minst_init;

    // Preallocate types
    // ------------------------------------------------------------
    std::vector<function_kind> func_kinds;
    for (const auto *tp : module.types) {
        std::vector<value_kind> param, result;
        if (auto *p = dynamic_cast<const wabt::FuncType*>(tp)) {
            const wabt::FuncSignature& sig = p->sig;
            for (const auto& t : sig.param_types)
                param.push_back(transpile_wabt_type(t));
            for (const auto& t : sig.result_types)
                result.push_back(transpile_wabt_type(t));
        }
        else {
            std::cerr << "Expect Function type" << std::endl;
            std::abort();
        }
        func_kinds.emplace_back(std::move(param), std::move(result));
    }

    minst_init.types = func_kinds;

    // Preallocate functions
    // ------------------------------------------------------------
    std::vector<address_t> func_addrs;

    {
        std::unordered_map<index_t, std::pair<std::string, std::string>> imported_functions;

        for (index_t i = 0; i < module.imports.size(); i++) {
            const auto *imp = module.imports[i];
            if (auto *p = dynamic_cast<const wabt::FuncImport*>(imp)) {
                // std::cout << "import func: " << p->func.decl.type_var.index()
                //           << ", " << imp->module_name << ", " << imp->field_name << std::endl;
                // Do not use `p->func.decl.type_var.index()` because it's type index
                imported_functions.emplace(std::piecewise_construct,
                                           std::forward_as_tuple(i),
                                           std::forward_as_tuple(imp->module_name, imp->field_name));
            }
        }

        for (index_t i = 0; i < module.funcs.size(); i++) {
            const auto *p = module.funcs[i];
            if (imported_functions.contains(i)) {
                const auto& [m, f] = imported_functions[i];
                // std::cout << "imported function: " << m  << ", " << f << std::endl;
                index_t fi = allocate_function(store, nullptr, *p, true, m, f);
                func_addrs.push_back(fi);
            }
            else {
                // std::cout << "native function: " << i << std::endl;
                index_t fi = allocate_function(store, nullptr, *p);
                func_addrs.push_back(fi);
            }
        }
        // std::vector<std::pair<std::string, std::string>> imports(module.funcs.size());        // size_t count = 0;
        // for (const auto *imp : module.imports) {
        //     if (auto *p = dynamic_cast<const wabt::FuncImport*>(imp)) {
        //         imports[count] = std::make_pair(imp->module_name, imp->field_name);
        //     }
        //     ++count;
        // }

        // count = 0;
        // for (const auto *p : module.funcs) {
        //     auto [module_name, field_name] = imports[count++];
        //     func_addrs.push_back(
        //         allocate_function(store, nullptr, *p, module_name, field_name));
        // }
    }

    minst_init.funcaddrs = func_addrs;

    // Create init frame
    // ------------------------------------------------------------
    auto frame_init = exe.context().make_frame();
    frame_init->module = &minst_init;

    exe.context().set_current_frame(frame_init.get());
    exe.context().stack_push(std::move(frame_init));

    // Initialize globals
    // ------------------------------------------------------------
    std::vector<address_t> global_addrs;
    for (const auto *p : module.globals) {

        auto init_expr = transpile(p->init_expr.begin(), p->init_expr.end());
        for (const auto& expr : init_expr) {
            exe.run(expr);
        }
        // for (const auto& expr : p->init_expr) {
        //     transpile(expr)->run(exe);
        // }

        value_kind type = transpile_wabt_type(p->type);

        if (type == value_kind::i32) {
            u32 val = exe.context().stack_pop().as_u32();
            global_addrs.push_back(
                store.emplace_back<global_instance>(type, val));
        }
        else if (type == value_kind::i64) {
            u64 val = exe.context().stack_pop().as_u64();
            global_addrs.push_back(
                store.emplace_back<global_instance>(type, val));
        }
        else {
            throw wasm_trap("Unexpected global value type");
        }
    }

    // Instantiate Elements
    // ------------------------------------------------------------
    std::vector<address_t> element_addrs;
    for (const auto *p : module.elem_segments) {
        std::vector<reference_t> elems;
        for (const auto& exprs : p->elem_exprs) {
            auto v = transpile(exprs.begin(), exprs.end());
            for (const auto& expr : v) {
                exe.run(expr);
            }
            // for (const auto& expr : exprs) {
            //     transpile(expr)->run(exe);
            // }
            reference_t ref = exe.context().stack_pop().as_ref();
            elems.push_back(std::move(ref));
        }
        element_addrs.push_back(
            store.emplace_back<element_instance>(transpile_wabt_type(p->elem_type),
                                                 std::move(elems)));
    }


    // Pop init frame
    // ------------------------------------------------------------
    exe.context().stack_pop();


    // Allocate and instantiate
    // ------------------------------------------------------------
    module_instance minst;
    minst.types = func_kinds;
    minst.funcaddrs = func_addrs;
    minst.globaladdrs = global_addrs;
    minst.elemaddrs = element_addrs;

    // Allocate tables
    // ------------------------------------------------------------
    for (const auto *p : module.tables) {
        minst.tableaddrs.push_back(allocate_table(store, *p));
    }

    // Allocate memory
    // ------------------------------------------------------------
    for (const auto *p : module.memories) {
        minst.memaddrs.push_back(allocate_memory(store, *p));
    }

    // Push another auxilary frame
    // ------------------------------------------------------------
    auto frame_aux = exe.context().make_frame();
    frame_aux->module = &minst;
    
    exe.context().set_current_frame(frame_aux.get());
    exe.context().stack_push(std::move(frame_aux));

    // Instantiate element segment
    // ------------------------------------------------------------
    for (u32 i = 0; i < module.elem_segments.size(); i++) {
        const auto *p = module.elem_segments[i];
        if (p->kind == wabt::SegmentKind::Active) {
            u32 n = p->elem_exprs.size();
            auto v = transpile(p->offset.begin(), p->offset.end());
            for (const auto& expr : v) {
                exe.run(expr);
            }
            // for (const auto& expr : p->offset) {
            //     transpile(expr)->run(exe);
            // }
            exe.context().stack_push(u32{ 0 });
            exe.context().stack_push(n);
            // exe.run(op::table_init{ p->table_var.index(), i });
            exe.run(opcode(opcode::table_init, p->table_var.index(), i));
        }
        else {
            // exe.run(op::elem_drop{ i });
            exe.run(opcode(opcode::elem_drop, i));
        }
    }

    // Instantiate and allocate Datas
    // ------------------------------------------------------------
    for (const auto *p : module.data_segments) {
        u32 i = store.emplace_back<data_instance>(p->data);
        minst.dataaddrs.push_back(i);
        
        if (p->kind == wabt::SegmentKind::Active) {
            assert(p->memory_var.index() == 0);
            u32 n = p->data.size();
            auto v = transpile(p->offset.begin(), p->offset.end());
            for (const auto& expr : v) {
                exe.run(expr);
            }
            // for (const auto& expr : p->offset) {
            //     transpile(expr)->run(exe);
            // }
            exe.context().stack_push(u32{ 0 });
            exe.context().stack_push(n);

            exe.run(opcode(opcode::memory_init, i));
            exe.run(opcode(opcode::data_drop, i));
            // exe.run(op::memory_init{ i });
            // exe.run(op::data_drop{ i });
        }
    }
    
    // {
    //     for (address_t addr : minst.dataaddrs) {
    //         data_instance& dinst = store.datas[addr];
    //         u32 n = dinst.data.size();
    //         for (auto& expr : dinst.offset_expr) {
    //             expr->run(exe);
    //         }
    //         exe.context().stack_push(typename Executor::value_type{ 0U });
    //         exe.context().stack_push(n);
    //         exe.run(op::memory_init{ static_cast<u32>(addr) });

    //         // Do not drop to avoid duplicate initialization
    //         // exe.run(op::data_drop{ static_cast<u32>(addr) });
    //     }
    // }

    // Pop auxilary frame
    // ------------------------------------------------------------
    exe.context().stack_pop();


    // TODO: full export support
    for (const auto *p : module.exports) {
        if (p->name == "_start") {
            // start = p->var.index();
            minst.exports["_start"] = p->var.index();
            // std::cout << "Start function: " << start << std::endl;
        }
        // else if (p->name == "stackSave") {
        //     mins.exports["stackSave"] = p->var.index();
        // }
        // else if (p->name == "stackRestore") {
        //     mins.exports["stackRestore"] = p->var.index();
        // }
    }

    return minst;

    // return { minst, start };
}

}  // namespace ligero::vm
