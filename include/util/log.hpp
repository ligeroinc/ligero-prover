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

#if defined(__EMSCRIPTEN__)
#include <iostream>

#define LIGERO_LOG_TRACE   std::cout
#define LIGERO_LOG_DEBUG   std::cout
#define LIGERO_LOG_INFO    std::cout
#define LIGERO_LOG_WARNING std::cout
#define LIGERO_LOG_ERROR   std::cout
#define LIGERO_LOG_FATAL   std::cout
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
