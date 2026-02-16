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

#include <util/thread_model.hpp>
#include <chrono>
#include <numeric>
#include <optional>
#include <string_view>
#include <util/tree.hpp>
#include <util/log.hpp>
#include <util/color.hpp>
#include <vector>

namespace ligero::vm {

template <class T>
class singleton : private T {
private:
    singleton() = default;
    ~singleton() = default;
public:
    static T& instance() {
        static singleton<T> s;  // compiler with c++11 will ensure thread safety
        return s;
    }
};

struct nano {
    // using resolution = std::chrono::nanoseconds;
    using duration_t = std::chrono::duration<double, std::nano>;
    constexpr static auto time_unit = "ns";
};

struct micro {
    // using resolution = std::chrono::microseconds;
    using duration_t = std::chrono::duration<double, std::micro>;
    constexpr static auto time_unit = "us";
};

struct milli {
    // using resolution = std::chrono::milliseconds;
    using duration_t = std::chrono::duration<double, std::milli>;
    constexpr static auto time_unit = "ms";
};

template <class Resolution = milli>
struct high_resolution_timer {
    using timepoint_t = std::chrono::high_resolution_clock::time_point;
    using duration_t = typename Resolution::duration_t;
    
    auto now() const { return std::chrono::high_resolution_clock::now(); }
    typename Resolution::duration_t duration(const timepoint_t& start, const timepoint_t& end) const {
        return std::chrono::duration_cast<typename Resolution::duration_t>(end - start);
    }
};


template <typename T, typename Name, typename... Args>
auto find_timer(tree<T>& current, Name&& name, Args&&... args) {
    auto it = std::find_if(current.children().begin(), current.children().end(),
                           [&name](auto&& child) {
                               return child.value().first == name;
                           });
        
    // not found - create new node
    if (it == current.children().end()) {
        it = current.emplace({name, {}});
    }
        
    if constexpr (sizeof...(args) == 0) {
        return it;
    }
    else {
        return find_timer(*it, std::forward<Args>(args)...);
    }
}

template <class Resolution, class ThreadModel = thread_model::max_hardware_threads>
struct timer_t : public ThreadModel
{
    using lock_t = typename ThreadModel::lock_t;
    using lock_guard_t = typename ThreadModel::lock_guard_t;
    using timepoint_t = typename high_resolution_timer<Resolution>::timepoint_t;
    using duration_seq = std::vector<double>;
    using timer_rep = std::pair<std::string_view, duration_seq>;

    using sumtree_node_t = std::tuple<std::string_view, double, double, double, double, size_t>;  // <name, sum_of_current, sum_of_child, min, max, avg>

    template <typename Name, typename... Args>
    struct timer_guard : public high_resolution_timer<Resolution> {
        timer_guard(tree<timer_rep>& root, lock_t& lock, Name&& name, Args&&... args)
            : stopped_(false),
              start_time_(this->now()),
              root_(root),
              args_(std::make_tuple(std::move(name), std::move(args)...))
            , lock_(lock) { }
        
        ~timer_guard() { stop(); }
        
        auto stop() {
            if (stopped_) return typename Resolution::duration_t(0);
            
            [[maybe_unused]] lock_guard_t lock_guard(lock_);
            auto lap = this->duration(start_time_, this->now());

            // Note: we have get latest reference every time we want
            //       to insert, because allocation might invalidate
            //       existing references.
            auto it = std::apply(
                [this](auto&&... args){
                    return find_timer(root_, std::forward<decltype(args)>(args)...);
                }, args_);
            it->value().second.emplace_back(lap.count());
            
            stopped_ = true;
            return lap;
        }
        
    private:
        bool stopped_;
        timepoint_t start_time_;
        tree<timer_rep>& root_;
        std::tuple<Name, Args...> args_;
        lock_t& lock_;
    };

    template <typename... Args>
    auto make_timer(Args... args) {
        return timer_guard<Args...>(timers_, this->get_lock(), std::forward<Args>(args)...);
    }

    auto sum_of_timer(const tree<timer_rep>& root) const {
        auto go =
            [](const tree<timer_rep>& node,
               tree<sumtree_node_t>& sum,
               auto&& self)
                {
                    bool seq_empty = false;
                    double sum_of_current = 0;
                    double min = 0, max = 0;
                    size_t count = 0;

                    if (node) {
                        auto& seq = node.value().second;
                        seq_empty = seq.empty();
                        sum_of_current = std::reduce(seq.begin(), seq.end(), sum_of_current);
                        if (!seq.empty()) {
                            min = *std::min_element(seq.begin(), seq.end());
                            max = *std::max_element(seq.begin(), seq.end());
                            count = seq.size();
                        }
                    }
                    // base case: node doesn't have child
                    if (!node.has_child()) {
                        sum.data() = node
                            ? std::make_optional(
                                std::make_tuple(node.value().first,
                                                sum_of_current,
                                                0,
                                                min, max, count))
                            : std::nullopt;
                        return sum_of_current;
                    }
                    // has child node: run DFS
                    else {
                        double sum_of_children = 0;
                        for (auto& child : node.children()) {
                            auto sum_child = sum.emplace({"", 0, 0, 0, 0, 0});
                            sum_of_children += self(child, *sum_child, self);
                        }

                        if (node) {
                            sum.data() = {
                                node.value().first, sum_of_current, sum_of_children,
                                min, max, count
                            };
                        }
                        return seq_empty ? sum_of_children : sum_of_current;
                    }
                };
        tree<sumtree_node_t> sumtree;
        go(root, sumtree, go);
        return sumtree;
    }

    template <typename Stream>
    Stream& __format(Stream& os,
                     const tree<sumtree_node_t>& st,
                     std::vector<std::string>& prefix,
                     int level) const
    {
        if (st) {
            for (size_t i = 0; i < prefix.size(); i++) { os << "    "; }
            for (auto pref : prefix) { os << pref << "."; }
        
            os << std::get<0>(st.value()) << ": ";

            auto [name, self, child, min, max, count] = st.value();

            // Show current and children timer:
            // 1. current  = 0: show sum of child timer
            // 2. current != 0: show current timer
            if (self) {
                os << ANSI_GREEN << static_cast<size_t>(self) << Resolution::time_unit << ANSI_RESET
                   << "    (min: "
                   << ANSI_GREEN << static_cast<size_t>(min) << ANSI_RESET
                   << ", max: "
                   << ANSI_GREEN << static_cast<size_t>(max) << ANSI_RESET
                   << ", count: "
                   << ANSI_GREEN << count << ANSI_RESET
                   << ")";
            }
            else {
                os << ANSI_GREEN << static_cast<size_t>(child) << Resolution::time_unit << ANSI_RESET;
            }
            os << std::endl;

            prefix.emplace_back(name);
        }

        if (level > 0) {
            for (const auto& child : st.children()) {
                __format(os, child, prefix, level - 1);
            }
        }
        if (st && !prefix.empty()) { prefix.pop_back(); }
        return os;
    }

    template <typename Stream>
    Stream& format(Stream& os, const tree<timer_rep>& t, int level) const {
        std::vector<std::string> prefix;
        auto sumtree = sum_of_timer(t);
        __format(os, sumtree, prefix, level);
        return os;
    }

    void print(int level = std::numeric_limits<int>::max()) const {
        std::cout << std::endl
                  << "========== Timing Info ==========" << std::endl;
        
        format(std::cout, timers_, level);
    }

    void clear_timers() {
        timers_.clear();
    }

public:
    tree<timer_rep> timers_;
};

using timer = singleton<timer_t<milli, thread_model::single_thread>>;
using threadsafe_timer = singleton<timer_t<milli, thread_model::max_hardware_threads>>;

template <typename... Args>
auto make_timer(Args... args) {
    return threadsafe_timer::instance().make_timer(std::forward<Args>(args)...);
}

// struct dummy_timer { void stop() { } };

// template <typename... Args>
// auto make_timer(Args&&... args) {
//     return dummy_timer{};
// }

void show_timer(int level = std::numeric_limits<int>::max()) {
    return threadsafe_timer::instance().print(level);
}

void clear_timers() {
    return threadsafe_timer::instance().clear_timers();
}

}  // namespace ligero::vm
