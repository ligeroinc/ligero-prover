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
// #include <relation.hpp>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <zkp/hash.hpp>
#include <util/timer.hpp>

namespace ligero::vm::zkp {

template <typename Hash> requires IsHashScheme<Hash>
struct merkle_tree {
    using hasher_type = Hash;
    using digest_type = typename Hash::digest;

    template <typename Element>
    struct builder {
        explicit builder() = default;
        explicit builder(size_t n) : hashers_(n) { }
        
        builder(const builder&) = delete;
        builder& operator=(const builder&) = delete;
        builder(builder&&) = default;
        builder& operator=(builder&&) = default;

        bool empty() const { return hashers_.empty(); }
        size_t size() const { return hashers_.size(); }
        hasher_type& operator[](size_t idx) { return hashers_[idx]; }

        builder& add_empty_node() { hashers_.emplace_back(); }

        template <typename T> requires requires(T t, size_t i) {
            { t.size() } -> std::convertible_to<size_t>;
            { t[i] };
        }
        builder& operator<<(const T& val) {
            assert(val.size() == hashers_.size());
            
            #pragma omp parallel for schedule(static, 256)
            for (size_t i = 0; i < hashers_.size(); i++) {
                hashers_[i] << val[i];
            }
            
            return *this;
        }

        void finalize() {

        }

        auto begin() { return hashers_.begin(); }
        auto end()   { return hashers_.end();   }
        const auto& data() const { return hashers_; }

    protected:
        std::vector<hasher_type> hashers_;
    };

    struct decommitment {
        decommitment() = default;
        decommitment(size_t count, const std::vector<size_t>& index)
            : total_count_(count), known_index_(index) { }

        void insert(size_t pos, const digest_type& node) {
            nodes_.emplace(pos, node);
        }

        size_t size() const { return total_count_; }
        size_t leaf_size() const { return total_count_ / 2 + 1; }

        const auto& known_index() const { return known_index_; }
        const auto& nodes() const { return nodes_; }

        const auto& operator[](size_t i) const { return nodes_.at(i); }

        template <typename Archive>
        void serialize(Archive& ar, const unsigned int) {
            ar & total_count_;
            ar & known_index_;
            ar & nodes_;
        }
        
    protected:
        size_t total_count_;
        std::vector<size_t> known_index_;
        std::unordered_map<size_t, digest_type> nodes_;
    };

    explicit merkle_tree() : nodes_() { }
    explicit merkle_tree(size_t n) : nodes_(std::bit_ceil(n) * 2 - 1) { }

    template <typename T>
    merkle_tree(builder<T>&& b) : nodes_() { initialize_from_builder(std::move(b)); }

    template <typename T>
    merkle_tree(builder<T>&& b, const decommitment& d) : nodes_() { from_decommitment(b, d); }
    merkle_tree(const merkle_tree& o) : nodes_(o.nodes_) { }
    merkle_tree(merkle_tree&& o) : nodes_(std::move(o.nodes_)) { }

    merkle_tree& operator=(const merkle_tree& o) {
        nodes_ = o.nodes_;
        return *this;
    }

    merkle_tree& operator=(merkle_tree&& o) {
        nodes_ = std::move(o.nodes_);
        return *this;
    }

    template <typename T>
    merkle_tree& operator=(builder<T>&& b) {
        initialize_from_builder(std::move(b));
        return *this;
    }

    merkle_tree& operator=(const std::vector<typename Hash::digest>& digests) {
        initialize_from_digest(digests);
        return *this;
    }

    size_t parent_index(size_t curr) const { return curr ? (curr - 1) / 2 : curr; }
    
    size_t sibling_index(size_t curr) const {
        if (size_t parent = parent_index(curr); parent == curr) {
            return curr;
        }
        else {
            const size_t left = 2 * parent + 1, right = 2 * (parent + 1);
            return curr == left ? right : left;
        }
    }

    size_t size() const { return nodes_.size(); }
    size_t leaf_size() const { return size() / 2 + 1; }

    auto leaf_begin() { return nodes_.begin() + (nodes_.size() / 2); }
    auto leaf_end() { return nodes_.end(); }
    
    const digest_type& operator[](size_t n) const { return nodes_[n]; }
    const digest_type& root() const { return nodes_[0]; }
    const digest_type& node(size_t n) const { return nodes_[nodes_.size() / 2 + n]; }

    decommitment decommit(const std::vector<size_t>& known_index) {
        size_t node_size = nodes_.size();
        decommitment d{ node_size, known_index };

        std::unordered_set<size_t> known(known_index.begin(), known_index.end());
        decommit_helper(d, known, nodes_.size() / 2, nodes_.size());

        return d;
    }

    void decommit_helper(decommitment& d, const std::unordered_set<size_t>& known, size_t start, size_t end) {
        if (start == 0)
            return;

        // std::cout << "start: " << start << " end: " << end << std::endl;

        std::unordered_set<size_t> upper_level;
        for (size_t i = start; i < end; i += 2) {
            size_t left = i, right = i + 1;
            size_t local_left = left - start, local_right = right - start;
            size_t local_parent = local_left / 2;
            bool kl = known.contains(local_left);
            bool kr = known.contains(local_right);

            // std::cout << local_left << " " << local_right << " " << kl << " " << kr << std::endl;

            if (kl && kr) {
                upper_level.insert(local_parent);
            }
            else if (kr) {
                assert(!d.nodes().contains(left));
                // std::cout << "insert left " << left << std::endl;
                // std::cout << std::hex;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)nodes_[left].data[j];
                // std::cout << std::endl << "parent: ";
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)nodes_[left / 2].data[j];
                // std::cout << std::endl << std::dec;
                
                d.insert(left, nodes_[left]);
                upper_level.insert(local_parent);
            }
            else if (kl) {
                assert(!d.nodes().contains(right));
                // std::cout << "insert right " << right << std::endl;
                // std::cout << std::hex;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)nodes_[right].data[j];
                // std::cout << std::endl << "parent: ";
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)nodes_[left / 2].data[j];
                // std::cout << std::endl << std::dec;
                
                d.insert(right, nodes_[right]);
                upper_level.insert(local_parent);
            }
        }

        decommit_helper(d, upper_level, (start - 1) / 2, (end - 1) / 2);
    }

    template <typename T>
    static digest_type recommit(builder<T>&& b, const decommitment& d) {
        assert(b.size() == d.known_index().size());
        const auto& index = d.known_index();
        std::vector<digest_type> buffer(d.leaf_size());

        for (size_t i = 0; i < index.size(); i++) {
            buffer[index[i]] = b[i].flush_digest();
        }

        std::unordered_set<size_t> known(index.begin(), index.end());
        recommit_helper(buffer, d, known, d.size() / 2, d.size());
        return buffer[0];
    }

    static digest_type recommit(const std::vector<digest_type>& b, const decommitment& d) {
        assert(b.size() == d.known_index().size());
        const auto& index = d.known_index();
        std::vector<digest_type> buffer(d.leaf_size());

        for (size_t i = 0; i < index.size(); i++) {
            buffer[index[i]] = b[i];
        }

        std::unordered_set<size_t> known(index.begin(), index.end());
        recommit_helper(buffer, d, known, d.size() / 2, d.size());
        return buffer[0];
    }

    static void recommit_helper(std::vector<digest_type>& buffer,
                         const decommitment& d,
                         const std::unordered_set<size_t>& known,
                         size_t start, size_t end) {
        if (start == 0)
            return;

        // std::cout << "start: " << start << " end: " << end << std::endl;

        std::unordered_set<size_t> upper_level;
        for (size_t i = start; i < end; i += 2) {
            size_t left = i, right = i + 1;
            size_t parent = left / 2;
            size_t local_left = left - start, local_right = right - start;
            size_t local_parent = local_left / 2;
            bool kl = known.contains(local_left);
            bool kr = known.contains(local_right);

            // std::cout << local_left << " " << local_right << " " << kl << " " << kr << std::endl;

            if (kl && kr) {
                upper_level.insert(local_parent);
                buffer[local_parent] = hash<Hash>(buffer[local_left], buffer[local_right]);
                // std::cout << "buffer[" << parent  << "] = hash(" << left << ", " << right << ")" << std::endl;
                // std::cout << std::hex;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[left].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[right].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[parent].data[j];
                // std::cout << std::endl << std::dec;
            }
            else if (kr) {
                // std::cout << "restore left " << left << std::endl;
                // d.insert(left, nodes_[left]);
                buffer[local_parent] = hash<Hash>(d[left], buffer[local_right]);
                upper_level.insert(local_parent);
                // std::cout << "buffer[" << parent  << "] = hash(saved " << left << ", " << right << ")" << std::endl;
                // std::cout << std::hex;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)d[left].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[right].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[parent].data[j];
                // std::cout << std::endl << std::dec;
            }
            else if (kl) {
                // std::cout << "restore right " << right << std::endl;
                // d.insert(right, nodes_[right]);
                buffer[local_parent] = hash<Hash>(buffer[local_left], d[right]);
                upper_level.insert(local_parent);
                // std::cout << "buffer[" << parent  << "] = hash(" << left << ", saved " << right << ")" << std::endl;
                // std::cout << std::hex;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[left].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)d[right].data[j];
                // std::cout << std::endl;
                // for (size_t j = 0; j < Hash::digest_size; j++)
                //     std::cout << (int)buffer[parent].data[j];
                // std::cout << std::endl << std::dec;
            }
        }

        recommit_helper(buffer, d, upper_level, (start - 1) / 2, (end - 1) / 2);
    }

private:
    template <typename T>
    void initialize_from_builder(builder<T>&& b) {
        if (b.empty()) return;
        /* Make sure the input size is power of 2 */
        const size_t power_of_two = std::bit_ceil(b.size());
        /* Data node has length `power_of_two`, parent nodes have length `power_of_two - 1`,
         * total nodes are `power_of_two * 2 - 1`   */
        const size_t leaf_size = power_of_two;
        const size_t parent_size = power_of_two - 1;
        const size_t node_size = parent_size + leaf_size;
        nodes_.resize(node_size);

        std::transform(b.begin(), b.end(),
                       nodes_.begin() + parent_size,
                       [](auto& h) {
                           return h.flush_digest();
                       });

        if (size_t parent = parent_index(parent_size); parent != parent_size)
            build_tree(parent, parent_size);
    }

    template <typename T>
    void initialize_from_digest(const std::vector<T>& b) {
        if (b.empty()) return;
        /* Make sure the input size is power of 2 */
        const size_t power_of_two = std::bit_ceil(b.size());
        /* Data node has length `power_of_two`, parent nodes have length `power_of_two - 1`,
         * total nodes are `power_of_two * 2 - 1`   */
        const size_t leaf_size = power_of_two;
        const size_t parent_size = power_of_two - 1;
        const size_t node_size = parent_size + leaf_size;
        nodes_.resize(node_size);

        std::copy(b.begin(), b.end(), nodes_.begin() + parent_size);

        if (size_t parent = parent_index(parent_size); parent != parent_size)
            build_tree(parent, parent_size);
    }

    void build_tree(size_t curr_start, size_t curr_end) {
        /* Recursively build each layer in the tree */
        for (size_t i = curr_start; i < curr_end; i++) {
            const size_t left_child = 2 * i + 1;
            const size_t right_child = left_child + 1;

            nodes_[i] = hash<Hash>(nodes_[left_child], nodes_[right_child]);
            // hasher_type hasher;
            // hasher << nodes_[left_child] << nodes_[right_child];
            // nodes_[i] = hasher.flush_digest();
        }

        if (curr_start > 0)
            build_tree(parent_index(curr_start), curr_start);
    }

    // merkle_tree& from_decommitment(builder& b, const decommitment& d) {
    //     nodes_.clear();
    //     nodes_.resize(d.size());
        
    //     const auto& cm = d.commitment();
    //     size_t ki = 0;
    //     for (size_t i = d.size() / 2; i < d.size(); i++) {
    //         if (cm.contains(i)) {
    //             nodes_[i] = cm.at(i);
    //         }
    //         else {
    //             auto& hasher = b[ki++];
    //             nodes_[i] = hasher.flush_digest();
    //         }
    //     }

    //     build_tree(d.size() / 2, d.size());
    //     return *this;
    // }

protected:
    std::vector<digest_type> nodes_;
};

}  // namespace ligero::zkp
