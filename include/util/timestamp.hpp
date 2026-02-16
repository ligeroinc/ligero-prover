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

#include <chrono>
#include <common.hpp>
#include <message.hpp>
#include <params.hpp>

namespace ligero::aya {

/************************************************************
 * Struct where we store global timestamp configurations.
 ************************************************************/
struct timestamp_config {
    const bool& enabled() const noexcept { return enabled_; }
    void enable()  noexcept { enabled_ = true; }
    void disable() noexcept { enabled_ = false; }

protected:
    bool enabled_ = true;  /**< whether enable sending timestamps */
};


/************************************************************
 * Define a global accessable config object.
 *
 * Example usage: timestamp_config_t::instance().enable()
 ************************************************************/
using timestamp_config_t = singleton<timestamp_config>;


/************************************************************
 * Return unix-like seconds since UTC 1970-1-1
 *
 * @return  Seconds count since UTC 1970-1-1
 ************************************************************/
template <typename Resolution = std::chrono::milliseconds>
size_t tick_since_epoch() {
    const auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<Resolution>(now.time_since_epoch()).count();
}


/************************************************************
 * Send current time as a timestamp to remote server
 *
 * Note: configurations in `timestamp_config_t` will affect
 *       behaviour of this function
 *
 * @param t     Generalized transport
 * @param name  Name of the event
 ************************************************************/
template <typename Transport>
void send_timestamp(Transport&& t, std::string name) {
    if (timestamp_config_t::instance().enabled()) {
        t.send(header_t::DIAG_STOPWATCH_SPLIT, name);
        t.template receive<header_t>(params::generic_receive_timeout);
    }
}

} // namespace ligero::aya

