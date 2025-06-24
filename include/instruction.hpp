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

// #pragma once

// #include <type.hpp>
// #include <iostream>
// #include <variant>
// #include <memory>

// namespace ligero::vm {

// // Base of all instructions
// struct instr;
// using instr_ptr = std::unique_ptr<instr>;
// using instr_vec = std::vector<instr_ptr>;

// // Forward declration all instructions
// namespace op {

// // Numeric Instructions
// /* ------------------------------------------------------------ */
// // Constants
// struct inn_const;

// // Unary Op
// struct inn_clz;
// struct inn_ctz;
// struct inn_popcnt;

// // Binary Op
// struct inn_add;
// struct inn_sub;
// struct inn_mul;
// struct inn_div_sx;
// struct inn_rem_sx;
// struct inn_and;
// struct inn_or;
// struct inn_xor;
// struct inn_shl;
// struct inn_shr_sx;
// struct inn_rotl;
// struct inn_rotr;

// // Test Op
// struct inn_eqz;

// // Relation Op
// struct inn_eq;
// struct inn_ne;
// struct inn_lt_sx;
// struct inn_gt_sx;
// struct inn_le_sx;
// struct inn_ge_sx;

// // Extension
// struct inn_extend8_s;
// struct inn_extend16_s;
// struct i64_extend32_s;
// struct i64_extend_i32_sx;
// struct i32_wrap_i64;


// // Reference
// /* ------------------------------------------------------------ */
// struct ref_null;
// struct ref_is_null;
// struct ref_func;


// // Parametric
// /* ------------------------------------------------------------ */
// struct drop;
// struct select;

// // Variable
// /* ------------------------------------------------------------ */
// struct local_get;
// struct local_set;
// struct local_tee;
// struct global_get;
// struct global_set;


// // Table
// /* ------------------------------------------------------------ */
// struct table_get;
// struct table_set;
// struct table_size;
// struct table_grow;
// struct table_fill;
// struct table_copy;
// struct table_init;
// struct elem_drop;


// // Memory
// /* ------------------------------------------------------------ */
// struct memory_size;
// struct memory_grow;
// struct memory_fill;
// struct memory_copy;
// struct memory_init;
// struct data_drop;

// struct inn_load;
// struct inn_store;
// struct inn_load8_sx;
// struct inn_load16_sx;
// struct i64_load32_sx;
// struct inn_store8;
// struct inn_store16;
// struct i64_store32;


// // Control
// /* ------------------------------------------------------------ */
// struct nop;
// struct unreachable;
// struct block;
// struct loop;
// struct if_then_else;
// struct br;
// struct br_if;
// struct br_table;
// struct ret;
// struct call;
// struct call_indirect;


// // Everything else - treat them all as undefined instructions
// struct undefined_instruction;

// }  // namespace instr


// // Executor
// /* ------------------------------------------------------------ */
// struct Executor {
//     virtual ~Executor() = default;
// };

// struct UndefinedExecutor : virtual Executor {
//     virtual result_t run(const op::undefined_instruction&) = 0;
// };

// struct NumericExecutor : virtual Executor {
//     virtual result_t run(const op::inn_const&) = 0;
//     virtual result_t run(const op::inn_clz&) = 0;
//     virtual result_t run(const op::inn_ctz&) = 0;
//     virtual result_t run(const op::inn_popcnt&) = 0;
//     virtual result_t run(const op::inn_add&) = 0;
//     virtual result_t run(const op::inn_sub&) = 0;
//     virtual result_t run(const op::inn_mul&) = 0;
//     virtual result_t run(const op::inn_div_sx&) = 0;
//     virtual result_t run(const op::inn_rem_sx&) = 0;
//     virtual result_t run(const op::inn_and&) = 0;
//     virtual result_t run(const op::inn_or&) = 0;
//     virtual result_t run(const op::inn_xor&) = 0;
//     virtual result_t run(const op::inn_shl&) = 0;
//     virtual result_t run(const op::inn_shr_sx&) = 0;
//     virtual result_t run(const op::inn_rotl&) = 0;
//     virtual result_t run(const op::inn_rotr&) = 0;
//     virtual result_t run(const op::inn_eqz&) = 0;
//     virtual result_t run(const op::inn_eq&) = 0;
//     virtual result_t run(const op::inn_ne&) = 0;
//     virtual result_t run(const op::inn_lt_sx&) = 0;
//     virtual result_t run(const op::inn_gt_sx&) = 0;
//     virtual result_t run(const op::inn_le_sx&) = 0;
//     virtual result_t run(const op::inn_ge_sx&) = 0;
//     virtual result_t run(const op::inn_extend8_s&) = 0;
//     virtual result_t run(const op::inn_extend16_s&) = 0;
//     virtual result_t run(const op::i64_extend32_s&) = 0;
//     virtual result_t run(const op::i64_extend_i32_sx&) = 0;
//     virtual result_t run(const op::i32_wrap_i64&) = 0;
// };

// template <typename T, typename V>
// struct combined_numeric_executor : public T, public V {
//     result_t run(const op::inn_const& i)   { T::run(i); return V::run(i); }
//     result_t run(const op::inn_clz& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_ctz& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_popcnt& i)  { T::run(i); return V::run(i); }
//     result_t run(const op::inn_add& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_sub& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_mul& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_div_sx& i)  { T::run(i); return V::run(i); }
//     result_t run(const op::inn_rem_sx& i)  { T::run(i); return V::run(i); }
//     result_t run(const op::inn_and& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_or& i)      { T::run(i); return V::run(i); }
//     result_t run(const op::inn_xor& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_shl& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_shr_sx& i)  { T::run(i); return V::run(i); }
//     result_t run(const op::inn_rotl& i)    { T::run(i); return V::run(i); }
//     result_t run(const op::inn_rotr& i)    { T::run(i); return V::run(i); }
//     result_t run(const op::inn_eqz& i)     { T::run(i); return V::run(i); }
//     result_t run(const op::inn_eq& i)      { T::run(i); return V::run(i); }
//     result_t run(const op::inn_ne& i)      { T::run(i); return V::run(i); }
//     result_t run(const op::inn_lt_sx& i)   { T::run(i); return V::run(i); }
//     result_t run(const op::inn_gt_sx& i)   { T::run(i); return V::run(i); }
//     result_t run(const op::inn_le_sx& i)   { T::run(i); return V::run(i); }
//     result_t run(const op::inn_ge_sx& i)   { T::run(i); return V::run(i); }
//     result_t run(const op::inn_extend8_s& i) { T::run(i); return V::run(i); }
//     result_t run(const op::inn_extend16_s& i) { T::run(i); return V::run(i); }
//     result_t run(const op::i64_extend32_s& i) { T::run(i); return V::run(i); }
//     result_t run(const op::i64_extend_i32_sx& i) { T::run(i); return V::run(i); }
//     result_t run(const op::i32_wrap_i64& i) { T::run(i); return V::run(i); }
// };

// struct RefExecutor : virtual Executor {
//     virtual result_t run(const op::ref_null&) = 0;
//     virtual result_t run(const op::ref_is_null&) = 0;
//     virtual result_t run(const op::ref_func&) = 0;
// };


// struct ParametricExecutor : virtual Executor {
//     virtual result_t run(const op::drop&) = 0;
//     virtual result_t run(const op::select&) = 0;
// };


// struct VariableExecutor : virtual Executor {
//     virtual result_t run(const op::local_get&) = 0;
//     virtual result_t run(const op::local_set&) = 0;
//     virtual result_t run(const op::local_tee&) = 0;
//     virtual result_t run(const op::global_get&) = 0;
//     virtual result_t run(const op::global_set&) = 0;
// };


// struct TableExecutor : virtual Executor {
//     virtual result_t run(const op::table_get&) = 0;
//     virtual result_t run(const op::table_set&) = 0;
//     virtual result_t run(const op::table_size&) = 0;
//     virtual result_t run(const op::table_grow&) = 0;
//     virtual result_t run(const op::table_fill&) = 0;
//     virtual result_t run(const op::table_copy&) = 0;
//     virtual result_t run(const op::table_init&) = 0;
//     virtual result_t run(const op::elem_drop&) = 0;
// };


// struct MemoryExecutor : virtual Executor {
//     virtual result_t run(const op::memory_size&) = 0;
//     virtual result_t run(const op::memory_grow&) = 0;
//     virtual result_t run(const op::memory_fill&) = 0;
//     virtual result_t run(const op::memory_copy&) = 0;
//     virtual result_t run(const op::memory_init&) = 0;
//     virtual result_t run(const op::data_drop&) = 0;
//     virtual result_t run(const op::inn_load&) = 0;
//     virtual result_t run(const op::inn_store&) = 0;
//     virtual result_t run(const op::inn_load8_sx&) = 0;
//     virtual result_t run(const op::inn_load16_sx&) = 0;
//     virtual result_t run(const op::i64_load32_sx&) = 0;
//     virtual result_t run(const op::inn_store8&) = 0;
//     virtual result_t run(const op::inn_store16&) = 0;
//     virtual result_t run(const op::i64_store32&) = 0;
// };


// struct ControlExecutor : virtual Executor {
//     virtual result_t run(const op::nop&) = 0;
//     virtual result_t run(const op::unreachable&) = 0;
//     virtual result_t run(const op::block&) = 0;
//     virtual result_t run(const op::loop&) = 0;
//     virtual result_t run(const op::if_then_else&) = 0;
//     virtual result_t run(const op::br&) = 0;
//     virtual result_t run(const op::br_if&) = 0;
//     virtual result_t run(const op::br_table&) = 0;
//     virtual result_t run(const op::ret&) = 0;
//     virtual result_t run(const op::call&) = 0;
//     virtual result_t run(const op::call_indirect&) = 0;
// };


// /* ------------------------------------------------------------ */
// struct instr {
//     virtual ~instr() = default;
//     virtual result_t run(Executor& exe) const = 0;
//     virtual std::string name() const = 0;
// };

// namespace op {

// template <typename Derive>
// struct enable_undefined : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << "WARNING: undefined instruction: " << this->name() << std::endl;
//         return dynamic_cast<UndefinedExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_numeric : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<NumericExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_ref : virtual public instr {
//     result_t run(Executor& exe) const override {
//         return dynamic_cast<RefExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_parametric : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<ParametricExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_variable : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<VariableExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_table : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<TableExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_memory : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<MemoryExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// template <typename Derive>
// struct enable_control : virtual public instr {
//     result_t run(Executor& exe) const override {
//         // std::cout << this->name() << std::endl;
//         return dynamic_cast<ControlExecutor&>(exe).run(static_cast<const Derive&>(*this));
//     }
// };

// /* ------------------------------------------------------------ */

// struct undefined_instruction : virtual instr, enable_undefined<undefined_instruction> {
//     undefined_instruction(const std::string& name) : name_(name) { }
//     std::string name() const override { return name_; }
//     std::string name_;
// };

// // Numeric
// /* ------------------------------------------------------------ */
// #define DECLARE_NUMERIC(NAME)                                           \
//     struct NAME : virtual instr, enable_numeric<NAME> {                 \
//         NAME(int_kind k) : type(k) { }                                  \
//         int_kind type;                                                  \
//         std::string name() const override { return to_string(type) + "." + #NAME; } \
//     };
// #define DECLARE_NUMERIC_SX(NAME)                                        \
//     struct NAME : virtual instr, enable_numeric<NAME> {                 \
//         NAME(int_kind ik, sign_kind sk) : type(ik), sign(sk) { }        \
//         int_kind type;                                                  \
//         sign_kind sign;                                                 \
//         std::string name() const override {                             \
//             return to_string(type) + "." + #NAME + "_" + to_string(sign); \
//         }                                                               \
//     };


// struct inn_const : virtual instr, enable_numeric<inn_const> {
//     inn_const(u64 val, int_kind k) : val(val), type(k) { }

//     std::string name() const override {
//         return to_string(type) + ".const " + std::to_string(val);
//     }

//     u64 val;
//     int_kind type;
// };

// DECLARE_NUMERIC(inn_clz)
// DECLARE_NUMERIC(inn_ctz)
// DECLARE_NUMERIC(inn_popcnt)

// DECLARE_NUMERIC(inn_add)
// DECLARE_NUMERIC(inn_sub)
// DECLARE_NUMERIC(inn_mul)
// DECLARE_NUMERIC_SX(inn_div_sx)
// DECLARE_NUMERIC_SX(inn_rem_sx)
// DECLARE_NUMERIC(inn_and)
// DECLARE_NUMERIC(inn_or)
// DECLARE_NUMERIC(inn_xor)
// DECLARE_NUMERIC(inn_shl)
// DECLARE_NUMERIC_SX(inn_shr_sx)
// DECLARE_NUMERIC(inn_rotl)
// DECLARE_NUMERIC(inn_rotr)

// DECLARE_NUMERIC(inn_eqz)
// DECLARE_NUMERIC(inn_eq)
// DECLARE_NUMERIC(inn_ne)
// DECLARE_NUMERIC_SX(inn_lt_sx)
// DECLARE_NUMERIC_SX(inn_gt_sx)
// DECLARE_NUMERIC_SX(inn_le_sx)
// DECLARE_NUMERIC_SX(inn_ge_sx)

// DECLARE_NUMERIC(inn_extend8_s)
// DECLARE_NUMERIC(inn_extend16_s)

// struct i64_extend32_s : virtual instr, enable_numeric<i64_extend32_s> {
//     std::string name() const override { return "i64.extend32_s"; }
// };

// struct i64_extend_i32_sx : virtual instr, enable_numeric<i64_extend_i32_sx> {
//     i64_extend_i32_sx(sign_kind sx) : sign(sx) { }
//     std::string name() const override { return "i64.extend_i32_" + to_string(sign); }

//     sign_kind sign;
// };

// struct i32_wrap_i64 : virtual instr, enable_numeric<i32_wrap_i64> {
//     std::string name() const override { return "i32.wrap_i64"; }
// };


// // Reference
// /* ------------------------------------------------------------ */
// struct ref_null    : virtual instr, enable_ref<ref_null> {
//     ref_null(value_kind k) : type(k) { }

//     std::string name() const override { return "ref.null"; }
//     value_kind type;
// };
// struct ref_is_null : virtual instr, enable_ref<ref_is_null> {
//     ref_is_null() = default;

//     std::string name() const override { return "ref.is_null"; }
// };
// struct ref_func    : virtual instr, enable_ref<ref_func> {
//     ref_func(index_t i) : func(i) { }

//     std::string name() const override { return "ref.func"; }
//     index_t func;
// };


// // Parametric
// /* ------------------------------------------------------------ */
// struct drop : virtual instr, enable_parametric<drop> {
//     std::string name() const override { return "drop"; }
// };
// struct select : virtual instr, enable_parametric<select> {
//     select(std::vector<value_kind>&& type) : types(std::move(type)) { }
//     std::string name() const override { return "select"; }
//     std::vector<value_kind> types;
// };


// // Variable
// /* ------------------------------------------------------------ */
// #define DECLARE_OP_VARIABLE(NAME)                           \
//     struct NAME : virtual instr, enable_variable<NAME> {    \
//         NAME(index_t i) : local(i) { }                      \
//         std::string name() const override { return #NAME; } \
//         index_t local;                                      \
//     };

// DECLARE_OP_VARIABLE(local_get)
// DECLARE_OP_VARIABLE(local_set)
// DECLARE_OP_VARIABLE(local_tee)
// DECLARE_OP_VARIABLE(global_get)
// DECLARE_OP_VARIABLE(global_set)


// // Table
// /* ------------------------------------------------------------ */
// #define DECLARE_OP_TABLE(NAME)                              \
//     struct NAME : virtual instr, enable_table<NAME> {       \
//         NAME(index_t i) : x(i) { }                          \
//         std::string name() const override { return #NAME; } \
//         index_t x;                                          \
//     };

// #define DECLARE_OP_TABLE2(NAME)                             \
//     struct NAME : virtual instr, enable_table<NAME> {       \
//         NAME(index_t x, index_t y) : x(x), y(y) { }         \
//         std::string name() const override { return #NAME; } \
//         index_t x, y;                                       \
//     };

// DECLARE_OP_TABLE(table_get)
// DECLARE_OP_TABLE(table_set)
// DECLARE_OP_TABLE(table_size)
// DECLARE_OP_TABLE(table_grow)
// DECLARE_OP_TABLE(table_fill)
// DECLARE_OP_TABLE(elem_drop)

// DECLARE_OP_TABLE2(table_copy)
// DECLARE_OP_TABLE2(table_init)

// // Memory
// /* ------------------------------------------------------------ */
// #define DECLARE_MEM(NAME)                                               \
//     struct NAME : virtual instr, enable_memory<NAME> {                  \
//         NAME(int_kind k, u32 align, u32 offset)                         \
//             : type(k), align(align), offset(offset) { }                 \
//         std::string name() const override { return to_string(type) + "." + #NAME; } \
//         int_kind type;                                                  \
//         u32 align;                                                      \
//         u32 offset;                                                     \
//     };

// #define DECLARE_MEM_SX(NAME)\
//     struct NAME : virtual instr, enable_memory<NAME> {                  \
//         NAME(int_kind k, sign_kind sx, u32 align, u32 offset)           \
//             : type(k), sign(sx), align(align), offset(offset) { }       \
//         std::string name() const override { return to_string(type) + "." + #NAME; } \
//         int_kind type;                                                  \
//         sign_kind sign;                                                 \
//         u32 align;                                                      \
//         u32 offset;                                                     \
//     };

// struct memory_size : virtual instr, enable_memory<memory_size> {
//     std::string name() const override { return "memory_size"; }
// };
// struct memory_grow : virtual instr, enable_memory<memory_grow> {
//     std::string name() const override { return "memory_grow"; }
// };
// struct memory_fill : virtual instr, enable_memory<memory_fill> {
//     std::string name() const override { return "memory_fill"; }
// };
// struct memory_copy : virtual instr, enable_memory<memory_copy> {
//     std::string name() const override { return "memory_copy"; }
// };
// struct memory_init : virtual instr, enable_memory<memory_init> {
//     memory_init(index_t i) : data_index(i) { }

//     std::string name() const override { return "memory_init"; }
//     index_t data_index;
// };
// struct data_drop : virtual instr, enable_memory<data_drop> {
//     data_drop(index_t i) : data_index(i) { }
//     std::string name() const override { return "data_drop"; }
//     index_t data_index;
// };

// DECLARE_MEM(inn_load)
// DECLARE_MEM(inn_store)
// DECLARE_MEM_SX(inn_load8_sx)
// DECLARE_MEM_SX(inn_load16_sx)
// DECLARE_MEM(inn_store8)
// DECLARE_MEM(inn_store16)

// struct i64_load32_sx : virtual instr, enable_memory<i64_load32_sx> {
//     i64_load32_sx(sign_kind sign, u32 align, u32 offset) : sign(sign), align(align), offset(offset) { }
//     std::string name() const override { return "i64.load32_sx"; }
//     sign_kind sign;
//     u32 align;
//     u32 offset;
// };

// struct i64_store32 : virtual instr, enable_memory<i64_store32> {
//     i64_store32(u32 align, u32 offset) : align(align), offset(offset) { }
//     std::string name() const override { return "i64_store32"; }
//     u32 align;
//     u32 offset;
// };


// // Control
// /* ------------------------------------------------------------ */
// struct nop : virtual instr, enable_control<nop> {
//     std::string name() const override { return "nop"; }
// };
// struct unreachable : virtual instr, enable_control<unreachable> {
//     std::string name() const override { return "unreachable"; }
// };

// struct block : virtual instr, enable_control<block> {
//     block() = default;
//     // block(index_t block_type) : type(block_type) { }
//     std::string name() const override { return "block"; }

//     name_t label;
//     // std::optional<index_t> type;
//     std::variant<index_t, block_kind> type;
//     instr_vec body;
// };

// struct loop : virtual instr, enable_control<loop> {
//     loop() = default;
//     // loop(index_t block_type) : type(block_type) { }
//     std::string name() const override { return "loop"; }

//     name_t label;
//     // std::optional<index_t> type;
//     std::variant<index_t, block_kind> type;
//     instr_vec body;
// };

// struct if_then_else : virtual instr, enable_control<if_then_else> {
//     if_then_else() = default;
//     std::string name() const override { return "if_then_else"; }
//     name_t label;
//     std::variant<index_t, block_kind> type;
//     instr_vec then_body;
//     instr_vec else_body;
// };

// struct br : virtual instr, enable_control<br> {
//     br(index_t i) : label(i) { }
//     std::string name() const override { return "br"; }
//     index_t label;
// };

// struct br_if : virtual instr, enable_control<br_if> {
//     br_if(index_t i) : label(i) { }
//     std::string name() const override { return "br_if"; }
//     index_t label;
// };

// struct br_table : virtual instr, enable_control<br_table> {
//     br_table(std::vector<index_t> brs, index_t def) : branches(brs), default_(def) { }

//     std::string name() const override { return "br_table"; }
//     std::vector<index_t> branches;
//     index_t default_;
// };

// struct ret : virtual instr, enable_control<ret> {
//     std::string name() const override { return "return"; }
// };
// struct call : virtual instr, enable_control<call> {
//     call(index_t i) : func(i) { }
//     std::string name() const override { return "call"; }
//     index_t func;
// };

// struct call_indirect : virtual instr, enable_control<call_indirect> {
//     call_indirect(index_t x, index_t y) : table_index(x), type_index(y) { }
//     std::string name() const override { return "call_indirect"; }
//     index_t table_index;
//     index_t type_index;
// };

// }// namespace instr

// } // namespace ligero::vm::instr
