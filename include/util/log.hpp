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

#if defined(__EMSCRIPTEN__)
#include <iostream>
#include <ostream>
#include <utility>

namespace ligero::detail {

// Boost.Log terminates every record with a newline; std::cout does not. The web
// build wrote log statements straight to std::cout, so they all ran together on
// a single line ("...acceleration=HARDWARE)=== Start ==="). Terminating in the
// destructor makes one log statement equal one line, matching the native build,
// without touching any call site.
class log_line {
public:
    log_line() = default;
    log_line(const log_line&) = delete;
    log_line& operator=(const log_line&) = delete;

    ~log_line() { std::cout << '\n'; }

    template <typename T>
    log_line& operator<<(T&& value) {
        std::cout << std::forward<T>(value);
        return *this;
    }

    // Manipulators such as std::endl cannot be deduced by the template above.
    log_line& operator<<(std::ostream& (*manip)(std::ostream&)) {
        std::cout << manip;
        return *this;
    }
};

}  // namespace ligero::detail

#define LIGERO_LOG_TRACE   ::ligero::detail::log_line{}
#define LIGERO_LOG_DEBUG   ::ligero::detail::log_line{}
#define LIGERO_LOG_INFO    ::ligero::detail::log_line{}
#define LIGERO_LOG_WARNING ::ligero::detail::log_line{}
#define LIGERO_LOG_ERROR   ::ligero::detail::log_line{}
#define LIGERO_LOG_FATAL   ::ligero::detail::log_line{}
#else
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>

#define LIGERO_LOG_TRACE   BOOST_LOG_TRIVIAL(trace)
#define LIGERO_LOG_DEBUG   BOOST_LOG_TRIVIAL(debug)
#define LIGERO_LOG_INFO    BOOST_LOG_TRIVIAL(info)
#define LIGERO_LOG_WARNING BOOST_LOG_TRIVIAL(warning)
#define LIGERO_LOG_ERROR   BOOST_LOG_TRIVIAL(error)
#define LIGERO_LOG_FATAL   BOOST_LOG_TRIVIAL(fatal)

namespace logging = boost::log;
#endif



enum class log_level : unsigned char {
    disabled,
    debug_only,
    info_only,
    full,
};

void enable_logging();
void disable_logging();
void set_logging_level(log_level level);
