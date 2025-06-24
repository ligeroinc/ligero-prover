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

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <memory>
#include <numeric>
#include <list>
#include <vector>

namespace ligero::vm {

template<typename Policy, typename T>
concept CanRecycle =
   std::invocable<Policy, T&> &&
   std::same_as<std::invoke_result_t<Policy, T&>, void>;

template <typename T, typename RecyclePolicy> requires CanRecycle<RecyclePolicy, T>
struct recycle_pool {
    static constexpr size_t default_chunk_size = 8192;

    recycle_pool() : top_(0) { }

    recycle_pool(size_t capacity)
        : recycle_pool(capacity, RecyclePolicy{}) { }

    recycle_pool(size_t capacity, RecyclePolicy policy)
        : top_(0), policy_(std::move(policy))
        {
            allocate_chunk(capacity);
        }

    recycle_pool(const recycle_pool&) = delete;
    recycle_pool& operator=(const recycle_pool&) = delete;

    recycle_pool(recycle_pool&&) noexcept = default;
    recycle_pool& operator=(recycle_pool&&) noexcept = default;

    T* acquire() {
        if (top_ >= free_list_.size()) {
            allocate_chunk(default_chunk_size);
        }

        assert(top_ < free_list_.size());
        return free_list_[top_++];
    }

    void recycle(T *ptr) {
        if (ptr != nullptr) {
            assert(top_ > 0);
            policy_(*ptr);
            free_list_[--top_] = ptr;
        }
    }

    size_t in_use_size()    const noexcept { return top_; }
    size_t available_size() const noexcept { return free_list_.size() - top_; }
    size_t capacity()       const noexcept { return free_list_.size(); }
    bool   available()      const noexcept { return top_ < free_list_.size(); }

private:
    void allocate_chunk(size_t chunk_size) {
        auto ptr = std::make_unique<T[]>(chunk_size);
        free_list_.reserve(free_list_.size() + chunk_size);
        for (size_t i = 0; i < chunk_size; i++) {
            free_list_.push_back(ptr.get() + i);
        }
        storage_.push_back(std::move(ptr));
    }

protected:
    std::list<std::unique_ptr<T[]>> storage_;
    std::vector<T*> free_list_;
    size_t top_;
    RecyclePolicy policy_;
};

}  // namespace ligero::vm
