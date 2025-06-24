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

#include <types.hpp>
#include <opcode.hpp>
#include <wabt/ir.h>

#include <tuple>
#include <exception>
#include <iostream>
#include <optional>

namespace ligero::vm {

template <typename Iter>
std::vector<instr_ptr> transpile(Iter begin, Iter end);

template <typename T, typename... Args>
instr_ptr make_instr(Args&&... args) {
    return std::make_unique<T>(std::forward<Args>(args)...);
}

value_kind transpile_wabt_type(const wabt::Type& type) {
    const wabt::Type::Enum t = type;
    switch(t) {
    case wabt::Type::Enum::I32:
        return value_kind::i32;
    case wabt::Type::Enum::I64:
        return value_kind::i64;
    case wabt::Type::Enum::F32:
        return value_kind::f32;
    case wabt::Type::Enum::F64:
        return value_kind::f64;
    case wabt::Type::Reference:
        return value_kind::reference;
    case wabt::Type::FuncRef:
        return value_kind::funcref;
    case wabt::Type::ExternRef:
        return value_kind::externref;
    default:
        return value_kind::unit;
    }
}

// ------------------------------------------------------------

/** Set args[0] = type, args[1] = k */
opcode transpile_const(const wabt::ConstExpr& expr) {
    const wabt::Const& k = expr.const_;

    switch(k.type()) {
    case wabt::Type::Enum::I32:
        return opcode(opcode::inn_const, value_kind::i32, k.u32());
    case wabt::Type::Enum::I64:
        return opcode(opcode::inn_const, value_kind::i64, k.u64());
    case wabt::Type::Enum::F32:
            return opcode(opcode::fnn_const, value_kind::f32, k.f32_bits());
    case wabt::Type::Enum::F64:
            return opcode(opcode::fnn_const, value_kind::f64, k.f64_bits());
    default:
        throw wasm_trap("Unexpected const expr");
    }
}

opcode transpile_unary(const wabt::UnaryExpr& expr) {
    const wabt::Opcode::Enum op = expr.opcode;

    switch(op) {
        case wabt::Opcode::I32Clz:
            return opcode(opcode::inn_clz, value_kind::i32);
        case wabt::Opcode::I64Clz:
            return opcode(opcode::inn_clz, value_kind::i64);

        case wabt::Opcode::I32Ctz:
            return opcode(opcode::inn_ctz, value_kind::i32);
        case wabt::Opcode::I64Ctz:
            return opcode(opcode::inn_ctz, value_kind::i64);

        case wabt::Opcode::I32Popcnt:
            return opcode(opcode::inn_popcnt, value_kind::i32);
        case wabt::Opcode::I64Popcnt:
            return opcode(opcode::inn_popcnt, value_kind::i64);

        case wabt::Opcode::I32Extend8S:
            return opcode(opcode::inn_extend8_s, value_kind::i32);
        case wabt::Opcode::I64Extend8S:
            return opcode(opcode::inn_extend8_s, value_kind::i64);

        case wabt::Opcode::I32Extend16S:
            return opcode(opcode::inn_extend16_s, value_kind::i32);
        case wabt::Opcode::I64Extend16S:
            return opcode(opcode::inn_extend16_s, value_kind::i64);

        case wabt::Opcode::I64Extend32S:
            return opcode(opcode::i64_extend32_s);

        // Floating-Point Unary Ops
        case wabt::Opcode::F32Abs:
            return opcode(opcode::fnn_abs, value_kind::f32);
        case wabt::Opcode::F64Abs:
            return opcode(opcode::fnn_abs, value_kind::f64);

        case wabt::Opcode::F32Neg:
            return opcode(opcode::fnn_neg, value_kind::f32);
        case wabt::Opcode::F64Neg:
            return opcode(opcode::fnn_neg, value_kind::f64);

        case wabt::Opcode::F32Ceil:
            return opcode(opcode::fnn_ceil, value_kind::f32);
        case wabt::Opcode::F64Ceil:
            return opcode(opcode::fnn_ceil, value_kind::f64);

        case wabt::Opcode::F32Floor:
            return opcode(opcode::fnn_floor, value_kind::f32);
        case wabt::Opcode::F64Floor:
            return opcode(opcode::fnn_floor, value_kind::f64);

        case wabt::Opcode::F32Trunc:
            return opcode(opcode::fnn_trunc, value_kind::f32);
        case wabt::Opcode::F64Trunc:
            return opcode(opcode::fnn_trunc, value_kind::f64);

        case wabt::Opcode::F32Nearest:
            return opcode(opcode::fnn_nearest, value_kind::f32);
        case wabt::Opcode::F64Nearest:
            return opcode(opcode::fnn_nearest, value_kind::f64);

        case wabt::Opcode::F32Sqrt:
            return opcode(opcode::fnn_sqrt, value_kind::f32);
        case wabt::Opcode::F64Sqrt:
            return opcode(opcode::fnn_sqrt, value_kind::f64);


        default:
            std::cerr << "ERROR: Expect Unary expr, get: " << expr.opcode.GetName() << std::endl;
            std::abort();
    }
}

opcode transpile_binary(const wabt::BinaryExpr& expr) {
    const wabt::Opcode::Enum op = expr.opcode;

    switch (op) {
        case wabt::Opcode::I32Add:
            return opcode(opcode::inn_add, value_kind::i32);
        case wabt::Opcode::I32Sub:
            return opcode(opcode::inn_sub, value_kind::i32);
        case wabt::Opcode::I32Mul:
            return opcode(opcode::inn_mul, value_kind::i32);
        case wabt::Opcode::I32DivS:
            return opcode(opcode::inn_div_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32DivU:
            return opcode(opcode::inn_div_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32RemS:
            return opcode(opcode::inn_rem_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32RemU:
            return opcode(opcode::inn_rem_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32And:
            return opcode(opcode::inn_and, value_kind::i32);
        case wabt::Opcode::I32Or:
            return opcode(opcode::inn_or, value_kind::i32);
        case wabt::Opcode::I32Xor:
            return opcode(opcode::inn_xor, value_kind::i32);
        case wabt::Opcode::I32Shl:
            return opcode(opcode::inn_shl, value_kind::i32);
        case wabt::Opcode::I32ShrS:
            return opcode(opcode::inn_shr_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32ShrU:
            return opcode(opcode::inn_shr_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32Rotl:
            return opcode(opcode::inn_rotl, value_kind::i32);
        case wabt::Opcode::I32Rotr:
            return opcode(opcode::inn_rotr, value_kind::i32);

        case wabt::Opcode::I64Add:
            return opcode(opcode::inn_add, value_kind::i64);
        case wabt::Opcode::I64Sub:
            return opcode(opcode::inn_sub, value_kind::i64);
        case wabt::Opcode::I64Mul:
            return opcode(opcode::inn_mul, value_kind::i64);
        case wabt::Opcode::I64DivS:
            return opcode(opcode::inn_div_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64DivU:
            return opcode(opcode::inn_div_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64RemS:
            return opcode(opcode::inn_rem_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64RemU:
            return opcode(opcode::inn_rem_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64And:
            return opcode(opcode::inn_and, value_kind::i64);
        case wabt::Opcode::I64Or:
            return opcode(opcode::inn_or, value_kind::i64);
        case wabt::Opcode::I64Xor:
            return opcode(opcode::inn_xor, value_kind::i64);
        case wabt::Opcode::I64Shl:
            return opcode(opcode::inn_shl, value_kind::i64);
        case wabt::Opcode::I64ShrS:
            return opcode(opcode::inn_shr_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64ShrU:
            return opcode(opcode::inn_shr_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64Rotl:
            return opcode(opcode::inn_rotl, value_kind::i64);
        case wabt::Opcode::I64Rotr:
            return opcode(opcode::inn_rotr, value_kind::i64);

        // Float ops
        case wabt::Opcode::F32Add:
            return opcode(opcode::fnn_add, value_kind::f32);
        case wabt::Opcode::F64Add:
            return opcode(opcode::fnn_add, value_kind::f64);

        case wabt::Opcode::F32Sub:
            return opcode(opcode::fnn_sub, value_kind::f32);
        case wabt::Opcode::F64Sub:
            return opcode(opcode::fnn_sub, value_kind::f64);

        case wabt::Opcode::F32Mul:
            return opcode(opcode::fnn_mul, value_kind::f32);
        case wabt::Opcode::F64Mul:
            return opcode(opcode::fnn_mul, value_kind::f64);

        case wabt::Opcode::F32Div:
            return opcode(opcode::fnn_div, value_kind::f32);
        case wabt::Opcode::F64Div:
            return opcode(opcode::fnn_div, value_kind::f64);

        case wabt::Opcode::F32Min:
            return opcode(opcode::fnn_min, value_kind::f32);
        case wabt::Opcode::F64Min:
            return opcode(opcode::fnn_min, value_kind::f64);

        case wabt::Opcode::F32Max:
            return opcode(opcode::fnn_max, value_kind::f32);
        case wabt::Opcode::F64Max:
            return opcode(opcode::fnn_max, value_kind::f64);

        case wabt::Opcode::F32Copysign:
            return opcode(opcode::fnn_copysign, value_kind::f32);
        case wabt::Opcode::F64Copysign:
            return opcode(opcode::fnn_copysign, value_kind::f64);

        default:
            std::cerr << "ERROR: Expect Binary expr, get: " << expr.opcode.GetName() << std::endl;
            std::abort();
    }
}

opcode transpile_comparison(const wabt::CompareExpr& expr) {
    const wabt::Opcode::Enum op = expr.opcode;

    switch(op) {
        /**  Comparisons  */
        case wabt::Opcode::I32Eq:
            return opcode(opcode::inn_eq, value_kind::i32);
        case wabt::Opcode::I32Ne:
            return opcode(opcode::inn_ne, value_kind::i32);
        case wabt::Opcode::I32LtS:
            return opcode(opcode::inn_lt_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32LtU:
            return opcode(opcode::inn_lt_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32GtS:
            return opcode(opcode::inn_gt_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32GtU:
            return opcode(opcode::inn_gt_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32LeS:
            return opcode(opcode::inn_le_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32LeU:
            return opcode(opcode::inn_le_sx, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32GeS:
            return opcode(opcode::inn_ge_sx, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32GeU:
            return opcode(opcode::inn_ge_sx, value_kind::i32, sign_kind::unsign);

        case wabt::Opcode::I64Eq:
            return opcode(opcode::inn_eq, value_kind::i64);
        case wabt::Opcode::I64Ne:
            return opcode(opcode::inn_ne, value_kind::i64);
        case wabt::Opcode::I64LtS:
            return opcode(opcode::inn_lt_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64LtU:
            return opcode(opcode::inn_lt_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64GtS:
            return opcode(opcode::inn_gt_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64GtU:
            return opcode(opcode::inn_gt_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64LeS:
            return opcode(opcode::inn_le_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64LeU:
            return opcode(opcode::inn_le_sx, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64GeS:
            return opcode(opcode::inn_ge_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64GeU:
            return opcode(opcode::inn_ge_sx, value_kind::i64, sign_kind::unsign);

        case wabt::Opcode::F32Eq:
            return opcode(opcode::fnn_eq, value_kind::f32);
        case wabt::Opcode::F32Ne:
            return opcode(opcode::fnn_ne, value_kind::f32);
        case wabt::Opcode::F32Lt:
            return opcode(opcode::fnn_lt, value_kind::f32);
        case wabt::Opcode::F32Gt:
            return opcode(opcode::fnn_gt, value_kind::f32);
        case wabt::Opcode::F32Le:
            return opcode(opcode::fnn_le, value_kind::f32);
        case wabt::Opcode::F32Ge:
            return opcode(opcode::fnn_ge, value_kind::f32);

        case wabt::Opcode::F64Eq:
            return opcode(opcode::fnn_eq, value_kind::f64);
        case wabt::Opcode::F64Ne:
            return opcode(opcode::fnn_ne, value_kind::f64);
        case wabt::Opcode::F64Lt:
            return opcode(opcode::fnn_lt, value_kind::f64);
        case wabt::Opcode::F64Gt:
            return opcode(opcode::fnn_gt, value_kind::f64);
        case wabt::Opcode::F64Le:
            return opcode(opcode::fnn_le, value_kind::f64);
        case wabt::Opcode::F64Ge:
            return opcode(opcode::fnn_ge, value_kind::f64);

        default:
            std::cerr << "ERROR: Expect Comparison expr, get: " << expr.opcode.GetName() << std::endl;
            std::abort();
    }
}

opcode transpile_conversion(const wabt::ConvertExpr& expr) {
    const wabt::Opcode::Enum op = expr.opcode;

    switch(op) {
        case wabt::Opcode::I32Eqz:
            return opcode(opcode::inn_eqz, value_kind::i32);
        case wabt::Opcode::I64Eqz:
            return opcode(opcode::inn_eqz, value_kind::i64);
        case wabt::Opcode::I32WrapI64:
            return opcode(opcode::i32_wrap_i64);
        case wabt::Opcode::I64ExtendI32S:
            return opcode(opcode::i64_extend_i32_sx, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64ExtendI32U:
            return opcode(opcode::i64_extend_i32_sx, value_kind::i64, sign_kind::unsign);

        /// Float conversions
        case wabt::Opcode::F32ConvertI32S:
            return opcode(opcode::f32_convert_i32_s, value_kind::f32, sign_kind::sign);
        case wabt::Opcode::F32ConvertI32U:
            return opcode(opcode::f32_convert_i32_u, value_kind::f32, sign_kind::unsign);
        case wabt::Opcode::F32ConvertI64S:
            return opcode(opcode::f32_convert_i64_s, value_kind::f32, sign_kind::sign);
        case wabt::Opcode::F32ConvertI64U:
            return opcode(opcode::f32_convert_i64_u, value_kind::f32, sign_kind::unsign);
        case wabt::Opcode::F32DemoteF64:
            return opcode(opcode::f32_demote_f64);

        case wabt::Opcode::F64ConvertI32S:
            return opcode(opcode::f64_convert_i32_s, value_kind::f64, sign_kind::sign);
        case wabt::Opcode::F64ConvertI32U:
            return opcode(opcode::f64_convert_i32_u, value_kind::f64, sign_kind::unsign);
        case wabt::Opcode::F64ConvertI64S:
            return opcode(opcode::f64_convert_i64_s, value_kind::f64, sign_kind::sign);
        case wabt::Opcode::F64ConvertI64U:
            return opcode(opcode::f64_convert_i64_u, value_kind::f64, sign_kind::unsign);
        case wabt::Opcode::F64PromoteF32:
            return opcode(opcode::f64_promote_f32);

            // Reinterpret
        case wabt::Opcode::I32ReinterpretF32:
            return opcode(opcode::i32_reinterpret_f32);
        case wabt::Opcode::I64ReinterpretF64:
            return opcode(opcode::i64_reinterpret_f64);
        case wabt::Opcode::F32ReinterpretI32:
            return opcode(opcode::f32_reinterpret_i32);
        case wabt::Opcode::F64ReinterpretI64:
            return opcode(opcode::f64_reinterpret_i64);

        /// Trunc
        case wabt::Opcode::I32TruncF32S:
            return opcode(opcode::i32_trunc_f32_s, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32TruncF32U:
            return opcode(opcode::i32_trunc_f32_u, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32TruncF64S:
            return opcode(opcode::i32_trunc_f64_s, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32TruncF64U:
            return opcode(opcode::i32_trunc_f64_u, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I64TruncF32S:
            return opcode(opcode::i64_trunc_f32_s, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64TruncF32U:
            return opcode(opcode::i64_trunc_f32_u, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64TruncF64S:
            return opcode(opcode::i64_trunc_f64_s, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64TruncF64U:
            return opcode(opcode::i64_trunc_f64_u, value_kind::i64, sign_kind::unsign);

        /// TruncSat
        case wabt::Opcode::I32TruncSatF32S:
            return opcode(opcode::i32_trunc_sat_f32_s, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32TruncSatF32U:
            return opcode(opcode::i32_trunc_sat_f32_u, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I32TruncSatF64S:
            return opcode(opcode::i32_trunc_sat_f64_s, value_kind::i32, sign_kind::sign);
        case wabt::Opcode::I32TruncSatF64U:
            return opcode(opcode::i32_trunc_sat_f64_u, value_kind::i32, sign_kind::unsign);
        case wabt::Opcode::I64TruncSatF32S:
            return opcode(opcode::i64_trunc_sat_f32_s, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64TruncSatF32U:
            return opcode(opcode::i64_trunc_sat_f32_u, value_kind::i64, sign_kind::unsign);
        case wabt::Opcode::I64TruncSatF64S:
            return opcode(opcode::i64_trunc_sat_f64_s, value_kind::i64, sign_kind::sign);
        case wabt::Opcode::I64TruncSatF64U:
            return opcode(opcode::i64_trunc_sat_f64_u, value_kind::i64, sign_kind::unsign);


        default:
            std::cerr << "ERROR: Expect Convert expr, get: "
                      << expr.opcode.GetName()
                      << std::endl;
            std::abort();
    }
}

opcode transpile_ternary(const wabt::TernaryExpr& expr) {
    std::cerr << "ERROR: Expect ternary expr, get: " << expr.opcode.GetName() << std::endl;
    std::abort();
}

opcode transpile_load(const wabt::LoadExpr& expr) {
    wabt::Opcode::Enum op = expr.opcode;

    switch(op) {
        case wabt::Opcode::I32Load:
            return opcode(opcode::inn_load, value_kind::i32, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I32Load8S:
            return opcode(opcode::inn_load8_sx, value_kind::i32, sign_kind::sign, expr.align, expr.offset);
        case wabt::Opcode::I32Load8U:
            return opcode(opcode::inn_load8_sx, value_kind::i32, sign_kind::unsign, expr.align, expr.offset);
        case wabt::Opcode::I32Load16S:
            return opcode(opcode::inn_load16_sx, value_kind::i32, sign_kind::sign, expr.align, expr.offset);
        case wabt::Opcode::I32Load16U:
            return opcode(opcode::inn_load16_sx, value_kind::i32, sign_kind::unsign, expr.align, expr.offset);

        case wabt::Opcode::F32Load:
            return opcode(opcode::fnn_load, value_kind::f32, sign_kind::unspecified, expr.align, expr.offset);

        case wabt::Opcode::I64Load:
            return opcode(opcode::inn_load, value_kind::i64, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I64Load8S:
            return opcode(opcode::inn_load8_sx, value_kind::i64, sign_kind::sign, expr.align, expr.offset);
        case wabt::Opcode::I64Load8U:
            return opcode(opcode::inn_load8_sx, value_kind::i64, sign_kind::unsign, expr.align, expr.offset);
        case wabt::Opcode::I64Load16S:
            return opcode(opcode::inn_load16_sx, value_kind::i64, sign_kind::sign, expr.align, expr.offset);
        case wabt::Opcode::I64Load16U:
            return opcode(opcode::inn_load16_sx, value_kind::i64, sign_kind::unsign, expr.align, expr.offset);
        case wabt::Opcode::I64Load32S:
            return opcode(opcode::i64_load32_sx, value_kind::i64, sign_kind::sign, expr.align, expr.offset);
        case wabt::Opcode::I64Load32U:
            return opcode(opcode::i64_load32_sx, value_kind::i64, sign_kind::unsign, expr.align, expr.offset);

        case wabt::Opcode::F64Load:
            return opcode(opcode::fnn_load, value_kind::f64, sign_kind::unspecified, expr.align, expr.offset);
        default:
            std::cerr << "Unexpected opcode: " << expr.opcode.GetName() << std::endl;
            return opcode(opcode::unreachable);
    }
}

opcode transpile_store(const wabt::StoreExpr& expr) {
    wabt::Opcode::Enum op = expr.opcode;

    switch(op) {
        case wabt::Opcode::I32Store:
            return opcode(opcode::inn_store, value_kind::i32, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I32Store8:
            return opcode(opcode::inn_store8, value_kind::i32, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I32Store16:
            return opcode(opcode::inn_store16, value_kind::i32, sign_kind::unspecified, expr.align, expr.offset);

        case wabt::Opcode::F32Store:
            return opcode(opcode::fnn_store, value_kind::f32, sign_kind::unspecified, expr.align, expr.offset);

        case wabt::Opcode::I64Store:
            return opcode(opcode::inn_store, value_kind::i64, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I64Store8:
            return opcode(opcode::inn_store8, value_kind::i64, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I64Store16:
            return opcode(opcode::inn_store16, value_kind::i64, sign_kind::unspecified, expr.align, expr.offset);
        case wabt::Opcode::I64Store32:
            return opcode(opcode::i64_store32, value_kind::i64, sign_kind::unspecified, expr.align, expr.offset);

        case wabt::Opcode::F64Store:
            return opcode(opcode::fnn_store, value_kind::f64, sign_kind::unspecified, expr.align, expr.offset);

        default:
            std::cerr << "Unexpected opcode: " << expr.opcode.GetName() << std::endl;
            return opcode(opcode::unreachable);
    }
}

std::optional<opcode> transpile_opcode(const wabt::Expr& expr) {
    switch(expr.type()) {
        case wabt::ExprType::Unreachable:
            return opcode(opcode::unreachable);
        case wabt::ExprType::Nop:
            return opcode(opcode::nop);
        case wabt::ExprType::Const:
            return transpile_const(static_cast<const wabt::ConstExpr&>(expr));
        case wabt::ExprType::Unary:
            return transpile_unary(static_cast<const wabt::UnaryExpr&>(expr));
        case wabt::ExprType::Binary:
            return transpile_binary(static_cast<const wabt::BinaryExpr&>(expr));
        case wabt::ExprType::Compare:
            return transpile_comparison(static_cast<const wabt::CompareExpr&>(expr));
        case wabt::ExprType::Ternary:
            return transpile_ternary(static_cast<const wabt::TernaryExpr&>(expr));
        case wabt::ExprType::Convert:
            return transpile_conversion(static_cast<const wabt::ConvertExpr&>(expr));
        case wabt::ExprType::RefIsNull:
            return opcode(opcode::ref_is_null);
        case wabt::ExprType::RefNull:
            return opcode(opcode::ref_null,
                          transpile_wabt_type(static_cast<const wabt::RefNullExpr&>(expr).type));
        case wabt::ExprType::RefFunc:
            return opcode(opcode::ref_func,
                          static_cast<const wabt::RefFuncExpr&>(expr).var.index());
        case wabt::ExprType::Drop:
            return opcode(opcode::drop);
        case wabt::ExprType::Select: {
            const auto& e = static_cast<const wabt::SelectExpr&>(expr);
            std::vector<value_kind> kinds;
            size_t i = 0;
            for (; i < e.result_type.size(); i++) {
                kinds.push_back(transpile_wabt_type(e.result_type[i]));
            }
            for (; i < 2; i++) {
                kinds.push_back(value_kind::unit);
            }
            return opcode(opcode::select, kinds[0], kinds[1]);
        }
        case wabt::ExprType::LocalGet:
            return opcode(opcode::local_get,
                          static_cast<const wabt::LocalGetExpr&>(expr).var.index());
        case wabt::ExprType::LocalSet:
            return opcode(opcode::local_set,
                          static_cast<const wabt::LocalSetExpr&>(expr).var.index());
        case wabt::ExprType::LocalTee:
            return opcode(opcode::local_tee,
                          static_cast<const wabt::LocalTeeExpr&>(expr).var.index());
        case wabt::ExprType::GlobalGet:
            return opcode(opcode::global_get,
                          static_cast<const wabt::GlobalGetExpr&>(expr).var.index());
        case wabt::ExprType::GlobalSet:
            return opcode(opcode::global_set,
                          static_cast<const wabt::GlobalSetExpr&>(expr).var.index());

        case wabt::ExprType::Load:
            return transpile_load(static_cast<const wabt::LoadExpr&>(expr));
        case wabt::ExprType::Store:
            return transpile_store(static_cast<const wabt::StoreExpr&>(expr));

        case wabt::ExprType::MemoryCopy: {
            auto& e = static_cast<const wabt::MemoryCopyExpr&>(expr);
            return opcode(opcode::memory_copy,
                          static_cast<index_t>(e.destmemidx.index()),
                          static_cast<index_t>(e.srcmemidx.index()));
        }
        case wabt::ExprType::DataDrop:
            return opcode(opcode::data_drop,
                          static_cast<const wabt::DataDropExpr&>(expr).var.index());
        case wabt::ExprType::MemorySize:
            return opcode(opcode::memory_size,
                          static_cast<const wabt::MemorySizeExpr&>(expr).memidx.index());
        case wabt::ExprType::MemoryGrow:
            return opcode(opcode::memory_grow,
                          static_cast<const wabt::MemoryGrowExpr&>(expr).memidx.index());
        case wabt::ExprType::MemoryFill:
            return opcode(opcode::memory_fill,
                          static_cast<const wabt::MemoryFillExpr&>(expr).memidx.index());

        case wabt::ExprType::MemoryInit:
            return opcode(opcode::memory_init,
                          static_cast<const wabt::MemoryInitExpr&>(expr).var.index());

        case wabt::ExprType::TableCopy: {
            auto& e = static_cast<const wabt::TableCopyExpr&>(expr);
            return opcode(opcode::table_copy,
                          static_cast<index_t>(e.dst_table.index()),
                          static_cast<index_t>(e.src_table.index()));
        }
        case wabt::ExprType::ElemDrop:
            return opcode(opcode::elem_drop,
                          static_cast<const wabt::ElemDropExpr&>(expr).var.index());
        case wabt::ExprType::TableInit: {
            auto& e = static_cast<const wabt::TableInitExpr&>(expr);
            return opcode(opcode::table_init,
                          static_cast<index_t>(e.segment_index.index()),
                          static_cast<index_t>(e.table_index.index()));
        }
        case wabt::ExprType::TableGet:
            return opcode(opcode::table_get,
                          static_cast<const wabt::TableGetExpr&>(expr).var.index());
        case wabt::ExprType::TableGrow:
            return opcode(opcode::table_grow,
                          static_cast<const wabt::TableGrowExpr&>(expr).var.index());
        case wabt::ExprType::TableSize:
            return opcode(opcode::table_size,
                          static_cast<const wabt::TableSizeExpr&>(expr).var.index());
        case wabt::ExprType::TableSet:
            return opcode(opcode::table_set,
                          static_cast<const wabt::TableSetExpr&>(expr).var.index());
        case wabt::ExprType::TableFill:
            return opcode(opcode::table_fill,
                          static_cast<const wabt::TableFillExpr&>(expr).var.index());

        default:
            return std::nullopt;
    }
}


template <typename WabtType, typename Type>
instr_ptr transpile_scope(const WabtType& expr) {
    Type block;
    block.label = expr.block.label;
    if (expr.block.decl.has_func_type) {
        // Block has function-like type, use type index
        block.type = expr.block.decl.type_var.index();
    }
    else {
        // Block may have optional valtype declaration
        block_kind k;
        for (size_t i = 0; i < expr.block.decl.GetNumParams(); i++) {
            k.params.emplace_back(transpile_wabt_type(expr.block.decl.GetParamType(i)));
        }
        for (size_t i = 0; i < expr.block.decl.GetNumResults(); i++) {
            k.returns.emplace_back(transpile_wabt_type(expr.block.decl.GetResultType(i)));
        }
        block.type = k;
    }

    block.body = transpile(expr.block.exprs.begin(), expr.block.exprs.end());
    // for (const auto& ins : expr.block.exprs) {
    //     block.body.push_back(translate(ins));
    // }
    return make_instr<Type>(std::move(block));
}

instr_ptr transpile_if(const wabt::IfExpr& expr) {
    if_then_else branch;
    branch.label = expr.true_.label;
    if (expr.true_.decl.has_func_type) {
        branch.type = expr.true_.decl.type_var.index();
    }
    else {
        // Block may have optional valtype declaration
        block_kind k;
        for (size_t i = 0; i < expr.true_.decl.GetNumParams(); i++) {
            k.params.emplace_back(transpile_wabt_type(expr.true_.decl.GetParamType(i)));
        }
        for (size_t i = 0; i < expr.true_.decl.GetNumResults(); i++) {
            k.returns.emplace_back(transpile_wabt_type(expr.true_.decl.GetResultType(i)));
        }
        branch.type = k;
    }

    branch.then_body = transpile(expr.true_.exprs.begin(), expr.true_.exprs.end());
    branch.else_body = transpile(expr.false_.begin(), expr.false_.end());
    // for (const auto& ins : expr.true_.exprs) {
    //     branch.then_body.push_back(transpile(ins));
    // }
    // for (const auto& ins : expr.false_) {
    //     branch.else_body.push_back(transpile(ins));
    // }
    return make_instr<if_then_else>(std::move(branch));
}

std::optional<instr_ptr> transpile_struct(const wabt::Expr& expr) {
    switch(expr.type()) {
        case wabt::ExprType::Block:
            return transpile_scope<wabt::BlockExpr, scoped_block>(
                static_cast<const wabt::BlockExpr&>(expr));
        case wabt::ExprType::Loop:
            return transpile_scope<wabt::LoopExpr, loop>(
                static_cast<const wabt::LoopExpr&>(expr));
        case wabt::ExprType::If:
            return transpile_if(static_cast<const wabt::IfExpr&>(expr));
        case wabt::ExprType::Br:
            return make_instr<br>(static_cast<const wabt::BrExpr&>(expr).var.index());
        case wabt::ExprType::BrIf:
            return make_instr<br_if>(static_cast<const wabt::BrIfExpr&>(expr).var.index());
        case wabt::ExprType::BrTable: {
            const auto& e = static_cast<const wabt::BrTableExpr&>(expr);
            std::vector<index_t> branches;
            for (const auto& var : e.targets) {
                branches.push_back(var.index());
            }
            return make_instr<br_table>(std::move(branches), e.default_target.index());
        }
        case wabt::ExprType::Call:
            return make_instr<call>(static_cast<const wabt::CallExpr&>(expr).var.index());
        case wabt::ExprType::CallIndirect: {
            const auto& e = static_cast<const wabt::CallIndirectExpr&>(expr);
            return make_instr<call_indirect>(e.table.index(), e.decl.type_var.index());
        }
        case wabt::ExprType::Return:
            return make_instr<ret>();
        default:
            return std::nullopt;
    }
}

template <typename Iter>
std::vector<instr_ptr> transpile(Iter begin, Iter end) {
    static size_t id = 0;

    std::vector<instr_ptr> result;
    std::optional<basic_block> b;

    for (auto it = begin; it != end; ++it) {
        if (auto r = transpile_struct(*it)) {
            if (b) {
                result.push_back(make_instr<basic_block>(std::move(*b)));
                b = std::nullopt;
            }

            result.push_back(std::move(*r));
        }
        else {
            auto op = transpile_opcode(*it);

            if (!op) {
                std::cerr << "Unexpected expr" << std::endl;
                std::abort();
            }

            if (!b) {
                b = basic_block{};
                (*b).id = id++;
            }
            (*b).body.push_back(std::move(*op));
        }
    }

    if (b) {
        result.push_back(make_instr<basic_block>(std::move(*b)));
    }
    return result;
}

std::tuple<value_kind, u64> decode_constop(opcode i) {
    return std::make_tuple(static_cast<value_kind>(i.args[0]), i.args[1]);
}

std::tuple<index_t> decode_index(opcode i) {
    return std::make_tuple(static_cast<index_t>(i.args[0]));
}

std::tuple<index_t, index_t> decode_index2(opcode i) {
    return std::make_tuple(static_cast<index_t>(i.args[0]),
                           static_cast<index_t>(i.args[1]));
}

/**  Decode an opcode to <int type, sign type, align, offset> format */
std::tuple<value_kind, sign_kind, u64, u64> decode_opcode(opcode i) {
    return std::make_tuple(static_cast<value_kind>(i.args[0]),
                           static_cast<sign_kind>(i.args[1]),
                           i.args[2],
                           i.args[3]);
}

}  // namespace ligero::vm
