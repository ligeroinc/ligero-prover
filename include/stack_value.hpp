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

#include <memory>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <prelude.hpp>
#include <types.hpp>
#include <zkp/backend/core.hpp>

using namespace std::string_literals;

namespace ligero::vm {

struct module_instance;
struct stack_value;

struct native_numeric {
    enum numeric_type { i32, i64, f32, f64 };

    native_numeric(int i)      : tag_(i32), data_{} { data_.i32_ = static_cast<uint32_t>(i); }
    native_numeric(uint32_t i) : tag_(i32), data_{} { data_.i32_ = i; }
    native_numeric(uint64_t i) : tag_(i64), data_{} { data_.i64_ = i; }
    native_numeric(float f)    : tag_(f32), data_{} { data_.f32_ = f; }
    native_numeric(double f)   : tag_(f64), data_{} { data_.f64_ = f; }

    numeric_type type() const { return tag_; }

    uint32_t as_u32() const { return data_.i32_; }
    uint64_t as_u64() const { return data_.i64_; }
    float    as_f32() const { return data_.f32_; }
    double   as_f64() const { return data_.f64_; }

    std::string to_string() const {
        switch (tag_) {
            case i32: return std::to_string(as_u32());
            case i64: return std::to_string(as_u64());
            case f32: return std::to_string(as_f32());
            case f64: return std::to_string(as_f64());
            default: return "<unknown numeric>";
        }
    }

private:
    numeric_type tag_;
    union {
        uint32_t i32_;
        uint64_t i64_;
        float    f32_;
        double   f64_;
    } data_{};
};

struct stack_value;
struct label_t { u32 arity; };

struct wasm_frame {
    u32 arity;
    std::vector<stack_value> locals;
    module_instance *module;

    wasm_frame();
    ~wasm_frame();
};

struct stack_value {
    using value_type = std::variant<native_numeric,
                                    reference_t,
                                    label_t,
                                    std::unique_ptr<wasm_frame>,
                                    zkp::managed_witness,
                                    zkp::decomposed_bits>;

    stack_value()         : data_(native_numeric{ 0 }) { }
    stack_value(int i)    : data_(native_numeric{ i }) { }
    stack_value(u32 i)    : data_(native_numeric{ i }) { }
    stack_value(u64 i)    : data_(native_numeric{ i }) { }
    stack_value(float i)  : data_(native_numeric{ i }) { }
    stack_value(double i) : data_(native_numeric{ i }) { }

    stack_value(native_numeric n) : data_(n) { }
    stack_value(reference_t ref)  : data_(ref) { }
    stack_value(label_t l)        : data_(l) { }
    stack_value(std::unique_ptr<wasm_frame> f) : data_(std::move(f)) { }

    stack_value(zkp::managed_witness w) : data_(std::move(w)) { }
    stack_value(zkp::decomposed_bits b) : data_(std::move(b)) { }

    stack_value(const stack_value&) = delete;
    stack_value(stack_value&& other) = default;

    stack_value& operator=(const stack_value&) = delete;
    stack_value& operator=(stack_value&& other) = default;
    // {
    //     data_ = std::move(other.data_);
    //     return *this;
    // }

    const auto& data() const { return data_; }
    auto&       data()       { return data_; }

    bool is_val() const {
        return std::holds_alternative<native_numeric>(data_);
    }

    bool is_ref() const {
        return std::holds_alternative<reference_t>(data_);
    }

    bool is_label() const {
        return std::holds_alternative<label_t>(data_);
    }

    bool is_frame() const {
        return std::holds_alternative<std::unique_ptr<wasm_frame>>(data_);
    }

    bool is_witness() const {
        return std::holds_alternative<zkp::managed_witness>(data_);
    }

    bool is_decomposed_bits() const {
        return std::holds_alternative<zkp::decomposed_bits>(data_);
    }

    native_numeric&       as_numeric()       { return std::get<native_numeric>(data_); }
    const native_numeric& as_numeric() const { return std::get<native_numeric>(data_); }

    native_numeric*       get_if_numeric()       { return std::get_if<native_numeric>(&data_); }
    const native_numeric* get_if_numeric() const { return std::get_if<native_numeric>(&data_); }

    uint32_t as_u32() const { return as_numeric().as_u32(); }
    uint64_t as_u64() const { return as_numeric().as_u64(); }
    float    as_f32() const { return as_numeric().as_f32(); }
    double   as_f64() const { return as_numeric().as_f64(); }

    reference_t&       as_ref()       { return std::get<reference_t>(data_); }
    const reference_t& as_ref() const { return std::get<reference_t>(data_); }

    reference_t*       get_if_ref()       { return std::get_if<reference_t>(&data_); }
    const reference_t* get_if_ref() const { return std::get_if<reference_t>(&data_); }

    label_t&       as_label()       { return std::get<label_t>(data_); }
    const label_t& as_label() const { return std::get<label_t>(data_); }

    label_t*       get_if_label()       { return std::get_if<label_t>(&data_); }
    const label_t* get_if_label() const { return std::get_if<label_t>(&data_); }

    wasm_frame& as_frame() {
        return *std::get<std::unique_ptr<wasm_frame>>(data_);
    }

    const wasm_frame& as_frame() const {
        return *std::get<std::unique_ptr<wasm_frame>>(data_);
    }

    wasm_frame* get_if_frame() {
        if (auto *p = std::get_if<std::unique_ptr<wasm_frame>>(&data_)) {
            return p->get();
        }
        return nullptr;
    }

    const wasm_frame* get_if_frame() const {
        if (auto *p = std::get_if<std::unique_ptr<wasm_frame>>(&data_)) {
            return p->get();
        }
        return nullptr;
    }

    zkp::managed_witness& as_witness() {
        return std::get<zkp::managed_witness>(data_);
    }
    const zkp::managed_witness& as_witness() const {
        return std::get<zkp::managed_witness>(data_);
    }

    zkp::managed_witness* get_if_witness() {
        return std::get_if<zkp::managed_witness>(&data_);
    }
    const zkp::managed_witness* get_if_witness() const {
        return std::get_if<zkp::managed_witness>(&data_);
    }

    zkp::decomposed_bits& as_decomposed_bits() {
        return std::get<zkp::decomposed_bits>(data_);
    }
    const zkp::decomposed_bits& as_decomposed_bits() const {
        return std::get<zkp::decomposed_bits>(data_);
    }

    zkp::decomposed_bits* get_if_decomposed_bits() {
        return std::get_if<zkp::decomposed_bits>(&data_);
    }
    const zkp::decomposed_bits* get_if_decomposed_bits() const {
        return std::get_if<zkp::decomposed_bits>(&data_);
    }

    std::string to_string() const;

protected:
    value_type data_;
};

std::string stack_value::to_string() const {
    return std::visit(
        prelude::overloaded {
            [](const native_numeric& n) {
                return n.to_string();
            },
                [](const label_t& label) {
                    return std::format("Label{{ {} }}", label.arity);
                },
                [](const reference_t& ref) -> std::string {
                    if (ref) {
                        return std::format("Ref{{ {} }}", *ref);
                    }
                    else {
                        return "Null";
                    }
                },
                [](const std::unique_ptr<wasm_frame>& f) {
                    return std::format("Frame{{ .arity={}, .locals={} }}", f->arity, f->locals.size());
                },
                [](const zkp::managed_witness& wit) {
                    std::stringstream ss;
                    ss << "Wit{ " << wit.val() << " }";
                    return ss.str();
                },
                [](const zkp::decomposed_bits& bits) {
                    std::stringstream ss;
                    ss << "Bits{ ";
                    for (size_t i = 0; i < bits.size(); i++) {
                        ss << bits[i].val() << ", ";
                    }
                    ss << " }";
                    return ss.str();
                }
                }, data_);
}

wasm_frame:: wasm_frame() : arity(0), locals(), module(nullptr) { }
wasm_frame::~wasm_frame() {
        // Enforce reverse-order destruction of elements
        while (!locals.empty()) {
            locals.pop_back();
        }
    }

}  // namespace ligero::vm
