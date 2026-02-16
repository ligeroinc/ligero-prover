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

#include <optional>
#include <stdexcept>
#include <vector>

template <typename T>
struct tree {
    tree() : val_(std::nullopt) { }
    tree(const T& val) : val_(val) { }
    tree(T&& val) : val_(std::forward<T>(val)) { }
    tree& operator=(T&& val) { val_.emplace(std::forward<T>(val)); return *this; }
    tree& operator=(const T& val) { val_ = val; return *this; }

    inline operator bool() const noexcept { return static_cast<bool>(val_); }
    inline bool has_child() const noexcept { return !children_.empty(); }

    /**************************************************************
     *   Insert/Emplace a node into the tree
     *   @return: reference to the newly inserted node
     **************************************************************/
    auto insert(const T& val) { return insert(tree(val)); }
    auto insert(const tree<T>& val) {
        children_.emplace_back(val);
        return std::prev(children_.end());
    }
    auto emplace(T&& val) { return emplace(tree(std::forward<T>(val))); }
    auto emplace(tree<T>&& val) {
        children_.emplace_back(std::forward<tree<T>>(val));
        return std::prev(children_.end());
    }

    template <class Iterator>
    tree& erase(Iterator it) { children_.erase(it); return *this; }
    
    void clear() { val_ = std::nullopt; children_.clear(); }

    tree& operator[](T&& key) const {
        auto ptr = dfs_find(std::forward<T>(key));
        if (ptr) { return *ptr; }
        else {
            throw std::runtime_error("tree search failed");
        }
    }
    
    tree* dfs_find(T&& key) const noexcept {
        if (val_ && val_.value() == key) { return this; }
        
        if (!has_child()) { return nullptr; }
        
        for (const auto& x : children_) {
            if (auto ptr = x.dfs(std::forward<T>(key))) { return ptr; }
        }
        return nullptr;
    }

    inline auto& data() noexcept { return val_; }
    inline auto& value() { return val_.value(); }
    inline const auto& value() const { return val_.value(); }
    inline auto& children() noexcept { return children_; }
    inline const auto& children() const noexcept { return children_; }
    
    // inline auto begin() { return children_.begin(); }
    // inline auto end() { return children_.end(); }

protected:
    std::optional<T> val_;
    std::vector<tree<T>> children_;
};
