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

#include <algorithm>
#include <bit>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#include <params.hpp>
#include <zkp/hash.hpp>
#include <zkp/merkle_tree.hpp>

#include <common.pb.h>
#include <ligero_proof.pb.h>

namespace ligero::vm::zkp {

struct ProofData {
    params::hasher::digest merkle_root;
    std::vector<uint32_t> encoded_code_limbs;
    std::vector<uint32_t> encoded_linear_limbs;
    std::vector<uint32_t> encoded_quad_limbs;
    merkle_tree<params::hasher>::decommitment decommit;
    std::vector<uint32_t> host_samplings;
};

/* ---- Digest conversion ---- */

inline void digest_to_proto(ligero::common::v1::HashDigest *out,
                            const params::hasher::digest& d) {
    out->set_value(d.data, params::hasher::digest_size);
}

inline void proto_to_digest(params::hasher::digest& out,
                            const ligero::common::v1::HashDigest& pb) {
    if (pb.value().size() != params::hasher::digest_size)
        throw std::runtime_error("Invalid digest size in proof: expected " +
                                 std::to_string(params::hasher::digest_size) +
                                 ", got " + std::to_string(pb.value().size()));
    std::memcpy(out.data, pb.value().data(), params::hasher::digest_size);
}

/* ---- FixedU32Vector conversion ---- */

inline void u32_vec_to_fixed32(ligero::v1::FixedU32Vector *out,
                               const std::vector<uint32_t>& v) {
    out->mutable_values()->Reserve(v.size());
    for (uint32_t val : v)
        out->add_values(val);
}

inline void fixed32_to_u32_vec(std::vector<uint32_t>& out,
                               const ligero::v1::FixedU32Vector& pb) {
    out.resize(pb.values_size());
    for (int i = 0; i < pb.values_size(); ++i)
        out[i] = pb.values(i);
}

/* ---- MerkleDecommitment: canonical sibling ordering ---- */

// Compute the tree positions of sibling hashes in canonical order
// (bottom-up, left-to-right at each level), mirroring the traversal
// in merkle_tree::decommit_helper.
inline std::vector<size_t>
compute_sibling_positions(const std::vector<size_t>& leaf_indices,
                          size_t total_count) {
    std::vector<size_t> positions;
    std::unordered_set<size_t> known(leaf_indices.begin(), leaf_indices.end());

    size_t start = total_count / 2;
    size_t end   = total_count;

    while (start > 0) {
        std::unordered_set<size_t> upper_level;
        for (size_t i = start; i < end; i += 2) {
            size_t local_left   = i - start;
            size_t local_right  = local_left + 1;
            size_t local_parent = local_left / 2;
            bool kl             = known.contains(local_left);
            bool kr             = known.contains(local_right);

            if (kl && kr) {
                upper_level.insert(local_parent);
            } else if (kr) {
                positions.push_back(i); // left sibling needed
                upper_level.insert(local_parent);
            } else if (kl) {
                positions.push_back(i + 1); // right sibling needed
                upper_level.insert(local_parent);
            }
        }

        known = upper_level;
        start = (start - 1) / 2;
        end   = (end - 1) / 2;
    }

    return positions;
}

inline void
decommitment_to_proto(ligero::common::v1::MerkleDecommitment *out,
                      const merkle_tree<params::hasher>::decommitment& d,
                      const params::hasher::digest& root) {
    out->set_algorithm(ligero::common::v1::HASH_ALGORITHM_SHA256);
    digest_to_proto(out->mutable_root(), root);

    for (size_t idx : d.known_index())
        out->add_leaf_indices(static_cast<uint32_t>(idx));

    auto positions = compute_sibling_positions(d.known_index(), d.size());
    for (size_t pos : positions) {
        auto *h          = out->add_sibling_hashes();
        const auto& node = d[pos];
        h->set_value(node.data, params::hasher::digest_size);
    }
}

inline void
proto_to_decommitment(merkle_tree<params::hasher>::decommitment& out,
                      params::hasher::digest& root_out,
                      const ligero::common::v1::MerkleDecommitment& pb,
                      size_t total_count) {
    proto_to_digest(root_out, pb.root());

    std::vector<size_t> known_indices;
    known_indices.reserve(pb.leaf_indices_size());
    for (int i = 0; i < pb.leaf_indices_size(); ++i)
        known_indices.push_back(pb.leaf_indices(i));

    out = merkle_tree<params::hasher>::decommitment(total_count, known_indices);

    auto positions = compute_sibling_positions(known_indices, total_count);
    if (positions.size() != static_cast<size_t>(pb.sibling_hashes_size()))
        throw std::runtime_error("Sibling hash count mismatch: expected " +
                                 std::to_string(positions.size()) + ", got " +
                                 std::to_string(pb.sibling_hashes_size()));

    for (size_t i = 0; i < positions.size(); ++i) {
        params::hasher::digest digest;
        proto_to_digest(digest, pb.sibling_hashes(i));
        out.insert(positions[i], digest);
    }
}

/* ---- Top-level serialize / deserialize ---- */

inline std::string
serialize_proof(const params::hasher::digest& merkle_root,
                const std::vector<uint32_t>& encoded_code_limbs,
                const std::vector<uint32_t>& encoded_linear_limbs,
                const std::vector<uint32_t>& encoded_quad_limbs,
                const merkle_tree<params::hasher>::decommitment& decommit,
                const std::vector<uint32_t>& host_samplings,
                ligero::v1::ProofMetadata *metadata = nullptr) {

    ligero::v1::LigeroProofEnvelope envelope;

    if (metadata)
        *envelope.mutable_metadata() = *metadata;

    auto *proof = envelope.mutable_ligero_proof();

    decommitment_to_proto(proof->mutable_merkle_tree(), decommit, merkle_root);

    u32_vec_to_fixed32(proof->mutable_encoded_code(), encoded_code_limbs);
    u32_vec_to_fixed32(proof->mutable_encoded_linear(), encoded_linear_limbs);
    u32_vec_to_fixed32(proof->mutable_encoded_quadratic(), encoded_quad_limbs);

    u32_vec_to_fixed32(proof->mutable_sampled_data(), host_samplings);

    return envelope.SerializeAsString();
}

inline ProofData deserialize_proof(const std::string& data) {
    ligero::v1::LigeroProofEnvelope envelope;
    if (!envelope.ParseFromString(data))
        throw std::runtime_error("Failed to parse protobuf proof envelope");

    if (!envelope.has_ligero_proof())
        throw std::runtime_error(
            "Proof envelope does not contain a LigeroProof payload");

    const auto& metadata = envelope.metadata();
    const auto& proof    = envelope.ligero_proof();

    ProofData result;

    // Derive tree size from codeword_size in metadata
    size_t codeword_size = metadata.codeword_size();
    if (codeword_size == 0)
        throw std::runtime_error("Proof metadata missing codeword_size");
    size_t tree_leaves = std::bit_ceil(codeword_size);
    size_t total_count = tree_leaves * 2 - 1;

    proto_to_decommitment(
        result.decommit, result.merkle_root, proof.merkle_tree(), total_count);

    fixed32_to_u32_vec(result.encoded_code_limbs, proof.encoded_code());
    fixed32_to_u32_vec(result.encoded_linear_limbs, proof.encoded_linear());
    fixed32_to_u32_vec(result.encoded_quad_limbs, proof.encoded_quadratic());

    fixed32_to_u32_vec(result.host_samplings, proof.sampled_data());

    return result;
}

} // namespace ligero::vm::zkp
