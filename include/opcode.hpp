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

#include <string>
#include <cstdint>
#include <memory>

#include <types.hpp>

namespace ligero::vm {

using namespace std::string_literals;

struct opcode {
    enum kind {
        nop = 0,

        inn_const,
        inn_clz,
        inn_ctz,
        inn_popcnt,
        inn_eqz,
        inn_add,
        inn_sub,
        inn_mul,
        inn_div_sx,
        inn_rem_sx,
        inn_and,
        inn_or,
        inn_xor,
        inn_shl,
        inn_shr_sx,
        inn_rotl,
        inn_rotr,
        inn_eq,
        inn_ne,
        inn_lt_sx,
        inn_gt_sx,
        inn_le_sx,
        inn_ge_sx,
        inn_extend8_s,
        inn_extend16_s,
        i64_extend32_s,
        i64_extend_i32_sx,
        i32_wrap_i64,

        fnn_const,
        fnn_eq,
        fnn_ne,
        fnn_lt,
        fnn_gt,
        fnn_le,
        fnn_ge,
        fnn_abs,
        fnn_neg,
        fnn_ceil,
        fnn_floor,
        fnn_trunc,
        fnn_nearest,
        fnn_sqrt,
        fnn_add,
        fnn_sub,
        fnn_mul,
        fnn_div,
        fnn_min,
        fnn_max,
        fnn_copysign,

        f32_convert_i32_s,
        f32_convert_i32_u,
        f32_convert_i64_s,
        f32_convert_i64_u,
        f32_demote_f64,
        f64_convert_i32_s,
        f64_convert_i32_u,
        f64_convert_i64_s,
        f64_convert_i64_u,
        f64_promote_f32,

        i32_reinterpret_f32,
        i64_reinterpret_f64,
        f32_reinterpret_i32,
        f64_reinterpret_i64,

        i32_trunc_f32_s,
        i32_trunc_f32_u,
        i32_trunc_f64_s,
        i32_trunc_f64_u,
        i64_trunc_f32_s,
        i64_trunc_f32_u,
        i64_trunc_f64_s,
        i64_trunc_f64_u,

        i32_trunc_sat_f32_s,
        i32_trunc_sat_f32_u,
        i32_trunc_sat_f64_s,
        i32_trunc_sat_f64_u,
        i64_trunc_sat_f32_s,
        i64_trunc_sat_f32_u,
        i64_trunc_sat_f64_s,
        i64_trunc_sat_f64_u,

        inn_load,
        inn_store,
        inn_load8_sx,
        inn_load16_sx,
        i64_load32_sx,
        inn_store8,
        inn_store16,
        i64_store32,

        fnn_load,
        fnn_store,

        // Reference
        ref_null,
        ref_is_null,
        ref_func,

        // Parametric
        drop,
        select,

        // Variable
        local_get,
        local_set,
        local_tee,
        global_get,
        global_set,

        // Table
        table_get,
        table_set,
        table_size,
        table_grow,
        table_fill,
        table_copy,
        table_init,
        elem_drop,

        // Memory
        memory_size,
        memory_grow,
        memory_fill,
        memory_copy,
        memory_init,
        data_drop,

        unreachable,
        total_size
    };

    template <typename... Args>
    opcode(kind k, Args&&... args)
        : tag(k), args{ static_cast<uint64_t>(args)... } { }

    static constexpr std::string_view to_string(kind);

    kind tag;
    uint64_t args[4];
};

struct structured_instr;

using instr_ptr = std::unique_ptr<structured_instr>;

struct structured_instr {
    enum tag {
        basic_block,
        scoped_block,
        loop,
        if_then_else,
        br,
        br_if,
        br_table,
        call,
        call_indirect,
        ret
    };

    explicit structured_instr(tag t) : kind(t) { }
    virtual ~structured_instr() = default;

    virtual std::string name() const = 0;

    tag kind;
};

struct basic_block : structured_instr {
    basic_block() : structured_instr(structured_instr::basic_block) { }

    std::string name() const override {
        return "BasicBlock id="s + std::to_string(id);
    }

    size_t id;
    std::vector<opcode> body;
};

struct scoped_block : structured_instr {
    scoped_block() : structured_instr(structured_instr::scoped_block) { }

    std::string name() const override {
        return "ScopedBlock";
    }

    std::string label;
    std::variant<index_t, block_kind> type;
    std::vector<instr_ptr> body;
};

struct loop : structured_instr {
    loop() : structured_instr(structured_instr::loop) { }

    std::string name() const override {
        return "Loop";
    }

    std::string label;
    std::variant<index_t, block_kind> type;
    std::vector<instr_ptr> body;
};

struct if_then_else : structured_instr {
    if_then_else() : structured_instr(structured_instr::if_then_else) { }

    std::string name() const override {
        return "IfThenElse";
    }

    std::string label;
    std::variant<index_t, block_kind> type;
    std::vector<instr_ptr> then_body;
    std::vector<instr_ptr> else_body;
};

struct br : structured_instr {
    br(index_t l) : structured_instr(structured_instr::br), label(l) { }

    std::string name() const override {
        return "Br";
    }

    index_t label;
};

struct br_if : structured_instr {
    br_if(index_t l) : structured_instr(structured_instr::br_if), label(l) { }

    std::string name() const override {
        return "BrIf";
    }

    index_t label;
};

struct br_table : structured_instr {
    br_table(std::vector<index_t> bs, index_t t)
        : structured_instr(structured_instr::br_table),
          branches(std::move(bs)),
          default_(t)
        { }

    std::string name() const override {
        return "BrTable";
    }

    std::vector<index_t> branches;
    index_t default_;
};

struct call : structured_instr {
    call(index_t f) : structured_instr(structured_instr::call), func(f) { }

    std::string name() const override {
        return "Call";
    }

    index_t func;
};

struct call_indirect : structured_instr {
    call_indirect(index_t tab, index_t type)
        : structured_instr(structured_instr::call_indirect),
          table_index(tab),
          type_index(type)
        { }

    std::string name() const override {
        return "CallIndirect";
    }

    index_t table_index;
    index_t type_index;
};

struct ret : structured_instr {
    ret() : structured_instr(structured_instr::ret) { }

    std::string name() const override {
        return "Return";
    }
};

constexpr std::string_view opcode::to_string(kind tag) {
    switch (tag) {
        case nop: return "nop";

        case inn_const: return "inn_const";
        case inn_clz: return "inn_clz";
        case inn_ctz: return "inn_ctz";
        case inn_popcnt: return "inn_popcnt";
        case inn_eqz: return "inn_eqz";
        case inn_add: return "inn_add";
        case inn_sub: return "inn_sub";
        case inn_mul: return "inn_mul";
        case inn_div_sx: return "inn_div_sx";
        case inn_rem_sx: return "inn_rem_sx";
        case inn_and: return "inn_and";
        case inn_or: return "inn_or";
        case inn_xor: return "inn_xor";
        case inn_shl: return "inn_shl";
        case inn_shr_sx: return "inn_shr_sx";
        case inn_rotl: return "inn_rotl";
        case inn_rotr: return "inn_rotr";
        case inn_eq: return "inn_eq";
        case inn_ne: return "inn_ne";
        case inn_lt_sx: return "inn_lt_sx";
        case inn_gt_sx: return "inn_gt_sx";
        case inn_le_sx: return "inn_le_sx";
        case inn_ge_sx: return "inn_ge_sx";
        case inn_extend8_s: return "inn_extend8_s";
        case inn_extend16_s: return "inn_extend16_s";
        case i64_extend32_s: return "i64_extend32_s";
        case i64_extend_i32_sx: return "i64_extend_i32_sx";
        case i32_wrap_i64: return "i32_wrap_i64";

        case fnn_const: return "fnn_const";
        case fnn_eq: return "fnn_eq";
        case fnn_ne: return "fnn_ne";
        case fnn_lt: return "fnn_lt";
        case fnn_gt: return "fnn_gt";
        case fnn_le: return "fnn_le";
        case fnn_ge: return "fnn_ge";
        case fnn_abs: return "fnn_abs";
        case fnn_neg: return "fnn_neg";
        case fnn_ceil: return "fnn_ceil";
        case fnn_floor: return "fnn_floor";
        case fnn_trunc: return "fnn_trunc";
        case fnn_nearest: return "fnn_nearest";
        case fnn_sqrt: return "fnn_sqrt";
        case fnn_add: return "fnn_add";
        case fnn_sub: return "fnn_sub";
        case fnn_mul: return "fnn_mul";
        case fnn_div: return "fnn_div";
        case fnn_min: return "fnn_min";
        case fnn_max: return "fnn_max";
        case fnn_copysign: return "fnn_copysign";

        case f32_convert_i32_s: return "f32_convert_i32_s";
        case f32_convert_i32_u: return "f32_convert_i32_u";
        case f32_convert_i64_s: return "f32_convert_i64_s";
        case f32_convert_i64_u: return "f32_convert_i64_u";
        case f32_demote_f64:    return "f32_demote_f64";
        case f64_convert_i32_s: return "f64_convert_i32_s";
        case f64_convert_i32_u: return "f64_convert_i32_u";
        case f64_convert_i64_s: return "f64_convert_i64_s";
        case f64_convert_i64_u: return "f64_convert_i64_u";
        case f64_promote_f32:   return "f64_promote_f32";

        case i32_reinterpret_f32: return "i32_reinterpret_f32";
        case i64_reinterpret_f64: return "i64_reinterpret_f64";
        case f32_reinterpret_i32: return "f32_reinterpret_i32";
        case f64_reinterpret_i64: return "f64_reinterpret_i64";

        case i32_trunc_f32_s: return "i32_trunc_f32_s";
        case i32_trunc_f32_u: return "i32_trunc_f32_u";
        case i32_trunc_f64_s: return "i32_trunc_f64_s";
        case i32_trunc_f64_u: return "i32_trunc_f64_u";
        case i64_trunc_f32_s: return "i64_trunc_f32_s";
        case i64_trunc_f32_u: return "i64_trunc_f32_u";
        case i64_trunc_f64_s: return "i64_trunc_f64_s";
        case i64_trunc_f64_u: return "i64_trunc_f64_u";

        case i32_trunc_sat_f32_s: return "i32_trunc_sat_f32_s";
        case i32_trunc_sat_f32_u: return "i32_trunc_sat_f32_u";
        case i32_trunc_sat_f64_s: return "i32_trunc_sat_f64_s";
        case i32_trunc_sat_f64_u: return "i32_trunc_sat_f64_u";
        case i64_trunc_sat_f32_s: return "i64_trunc_sat_f32_s";
        case i64_trunc_sat_f32_u: return "i64_trunc_sat_f32_u";
        case i64_trunc_sat_f64_s: return "i64_trunc_sat_f64_s";
        case i64_trunc_sat_f64_u: return "i64_trunc_sat_f64_u";

        case inn_load: return "inn_load";
        case inn_store: return "inn_store";
        case inn_load8_sx: return "inn_load8_sx";
        case inn_load16_sx: return "inn_load16_sx";
        case i64_load32_sx: return "i64_load32_sx";
        case inn_store8: return "inn_store8";
        case inn_store16: return "inn_store16";
        case i64_store32: return "i64_store32";

        case fnn_load: return "fnn_load";
        case fnn_store: return "fnn_store";

        case ref_null: return "ref_null";
        case ref_is_null: return "ref_is_null";
        case ref_func: return "ref_func";

        case drop: return "drop";
        case select: return "select";

        case local_get: return "local_get";
        case local_set: return "local_set";
        case local_tee: return "local_tee";
        case global_get: return "global_get";
        case global_set: return "global_set";

        case table_get: return "table_get";
        case table_set: return "table_set";
        case table_size: return "table_size";
        case table_grow: return "table_grow";
        case table_fill: return "table_fill";
        case table_copy: return "table_copy";
        case table_init: return "table_init";
        case elem_drop: return "elem_drop";

        case memory_size: return "memory_size";
        case memory_grow: return "memory_grow";
        case memory_fill: return "memory_fill";
        case memory_copy: return "memory_copy";
        case memory_init: return "memory_init";
        case data_drop: return "data_drop";

        case unreachable: return "unreachable";
        case total_size: return "total_size";

        default: return "unknown";
    }
}

}  // namespace ligero::vm
