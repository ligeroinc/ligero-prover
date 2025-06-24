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

#include <bit>
#include <vector>
#include <string>

namespace ligero::prelude {

/// Helper function for std::visit
template <typename... Ts>
struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;  // deduction guide

template <typename InputIt, typename UnaryPredicate>
InputIt find_if_n(InputIt first, InputIt last, size_t n, UnaryPredicate p) {
    assert(n > 0);
    auto it = std::find_if(first, last, p);
    if (n == 1) {
        return it;
    }
    else {
        return find_if_n(++it, last, n-1, p);
    }
}

#define PRELUDE_DECLARE_HELPER(NAME)                                    \
    template <>                                                         \
    struct NAME<void> {                                                 \
        template <typename T>                                           \
        constexpr T operator()(const T& x, const T& y) const { return NAME<T>{}(x, y); } \
    };

template <typename T = void>
struct shiftl {
    constexpr T operator()(const T& num, const T& by) const { return num << by; }
};

PRELUDE_DECLARE_HELPER(shiftl)

template <typename T = void>
struct shiftr {
    constexpr T operator()(const T& num, const T& by) const { return num >> by; }
};

PRELUDE_DECLARE_HELPER(shiftr)

template <typename T = void>
struct rotatel {
    constexpr T operator()(const T& num, const T& by) const { return std::rotl(num, by); }
};

PRELUDE_DECLARE_HELPER(rotatel)

template <typename T = void>
struct rotater {
    constexpr T operator()(const T& num, const T& by) const { return std::rotr(num, by); }
};

PRELUDE_DECLARE_HELPER(rotater)

template <typename T>
std::string to_string(const T& v) {
    if constexpr (std::is_fundamental_v<T>) {
        return std::to_string(v);
    }
    else {
        std::string str = "[";
        for (size_t i = 0; i < 2; i++) {
            str += prelude::to_string(v[i]);
            str += ", ";
        }
        str += "... ,";
        str += prelude::to_string(v[T::size - 2]);
        str += ", ";
        str += prelude::to_string(v[T::size - 1]);
        // for (const auto& x : v) {
        //     str += prelude::to_string(x);
        //     str += ", ";
        // }
        str += "]";
        return str;
    }
}

template <typename T, typename UnaryFunc>
void transform(T& v, UnaryFunc&& func) {
    if constexpr (requires { {v.begin()}; {v.end()}; }) {
        std::transform(v.begin(), v.end(), v.begin(), func);
    }
    else {
        v = func(v);
    }
}

template <typename T, typename UnaryFunc>
void for_each(T& v, UnaryFunc&& func) {
    if constexpr (requires { {v.begin()}; {v.end()}; }) {
        std::transform(v.begin(), v.end(), func);
    }
    else {
        func(v);
    }
}

constexpr auto to_signed = [](auto& x) {
    return static_cast<std::make_signed_t<decltype(x)>>(x);
};

template <typename T>
T make_signed(const T& v) {
    if constexpr (requires { {v.begin()}; {v.end()}; }) {
        std::make_signed_t<typename T::value_type> sv;
        std::transform(v.begin(), v.end(), std::back_inserter(sv), to_signed);
        return sv;
    }
    else {
        return to_signed(v);
    }
}

template <typename T, typename UnaryFunc>
auto all_of(UnaryFunc&& func, T& v) {
    if constexpr (requires { {v.begin() }; {v.end()}; }) {
        return std::all_of(v.begin(), v.end(), func);
    }
    else {
        return func(v);
    }
}

template <typename T, typename UnaryFunc>
auto any_of(UnaryFunc&& func, T& v) {
    if constexpr (requires { {v.begin() }; {v.end()}; }) {
        return std::any_of(v.begin(), v.end(), func);
    }
    else {
        return func(v);
    }
}

}  // namespace ligero::prelude
