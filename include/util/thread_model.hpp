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

#include <thread>
#include <mutex>

namespace ligero::thread_model {

struct single_thread {
    using lock_t = int;
    using lock_guard_t = int;
    const unsigned int available_threads = 1;
    
    constexpr inline auto& get_lock() noexcept { return mutex_; }
protected:
    int mutex_;
};

struct max_hardware_threads {
    using lock_t = std::mutex;
    using lock_guard_t = std::scoped_lock<std::mutex>;
    const unsigned int available_threads = std::thread::hardware_concurrency();
    
    inline auto& get_lock() noexcept { return mutex_; }
protected:
    std::mutex mutex_;
};

}  // namespace ligero::thread_model
