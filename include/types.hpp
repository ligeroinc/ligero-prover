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

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace ligero {

// Name
/* ------------------------------------------------------------ */
using name_t = std::string;

// Numeric Types
/* ------------------------------------------------------------ */
using u8  = uint8_t;
using s8  = int8_t;
using u16 = uint16_t;
using s16 = int16_t;
using u32 = uint32_t;
using s32 = int32_t;
using u64 = uint64_t;
using s64 = int64_t;

using index_t = u32;
using address_t = u64;

using reference_t = std::optional<index_t>;

struct exec_ok { };
struct exec_return { };
struct exec_exit { int exit_code = 0; };
struct exec_jump { int label = 0; };

struct exec_result {
    exec_result() : data_(exec_ok{}) { }
    exec_result(exec_ok ok) : data_(ok) { }
    exec_result(exec_return ret) : data_(ret) { }
    exec_result(exec_jump j) : data_(j) { }
    exec_result(exec_exit e) : data_(e) { }

    bool ok() const        { return std::holds_alternative<exec_ok>(data_);     }
    bool is_exit() const   { return std::holds_alternative<exec_exit>(data_);   }
    bool is_jump() const   { return std::holds_alternative<exec_jump>(data_);   }
    bool is_return() const { return std::holds_alternative<exec_return>(data_); }

    int exit_code() const { return std::get<exec_exit>(data_).exit_code; }

    bool has_unresolved_jump() const {
        if (auto* j = std::get_if<exec_jump>(&data_))
            return j->label > 0;
        return false;
    }

    bool unwind() {
        if (auto* j = std::get_if<exec_jump>(&data_)) {
            if (j->label == 0) {
                data_ = exec_ok{};
                return true; // jump resolved
            }
            --j->label;
        }
        return false; // still jumping or not a jump
    }

private:
    std::variant<exec_ok, exec_return, exec_jump, exec_exit> data_;
};

struct wasm_trap : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Numeric Types
/* ------------------------------------------------------------ */

enum class sign_kind : uint8_t {
    unspecified = 0,
    sign,
    unsign
};

std::string to_string(sign_kind k) {
    switch(k) {
    case sign_kind::sign:
        return "s";
    case sign_kind::unsign:
        return "u";
    default:
        return "<error>";
    }
}

// Vector Type
/* ------------------------------------------------------------ */
enum class vec_kind : uint8_t {
    v128 = 0x7B
};

// Value Type
/* ------------------------------------------------------------ */
enum class value_kind : int32_t {
    unit      = 0,            // Void
    i32       = -0x01,        // 0x7f
    i64       = -0x02,        // 0x7e
    f32       = -0x03,        // 0x7d
    f64       = -0x04,        // 0x7c
    funcref   = -0x10,        // 0x70,
    externref = -0x11,        // 0x6f
    reference = -0x15,        // 0x6b
};

size_t num_bits_of_kind(value_kind k) {
    switch (k) {
        case value_kind::unit: return 0;
        case value_kind::i32:  return 32;
        case value_kind::i64:  return 64;
        case value_kind::f32:  return 32;
        case value_kind::f64:  return 64;
        default:
            return -1;
    }
}

// Function Type
/* ------------------------------------------------------------ */
struct function_kind {
    function_kind() = default;
    function_kind(std::vector<value_kind> param, std::vector<value_kind> ret)
        : params(std::move(param)), returns(std::move(ret)) { }
    
    std::vector<value_kind> params;
    std::vector<value_kind> returns;
};

using block_kind = function_kind;

// Limits
/* ------------------------------------------------------------ */
struct limits {
    limits() : min(0), max(std::nullopt) { }
    limits(u64 init) : min(init), max(std::nullopt) { }
    limits(u64 init, u64 max) : min(init), max(max) { }
    
    u64 min;
    std::optional<u64> max;
};


// Memory Type
/* ------------------------------------------------------------ */
struct memory_kind {
    memory_kind(limits l) : limit(l) { }
    
    limits limit;
};


// Table Type
/* ------------------------------------------------------------ */
struct table_kind {
    value_kind kind;
    limits limit;
};


// Global Type
/* ------------------------------------------------------------ */
struct global_kind {
    value_kind kind;
    bool mut = false;
};

// Extern Types
/* ------------------------------------------------------------ */
enum class extern_kind : uint8_t {
    func,
    table,
    mem,
    global
};

}  // namespace ligero
