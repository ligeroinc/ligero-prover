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

/*
 * 2-to-1 Poseidon-S hash (compatible with Solana's `sol_poseidon`,
 * width t=3, two inputs, one output). This is the form
 * used inside ZK proofs for Merkle-tree internal nodes.
 *
 * Built-in test vector (matches light-poseidon README):
 *   in0 = 0x0101010101010101010101010101010101010101010101010101010101010101
 *   in1 = 0x0202020202020202020202020202020202020202020202020202020202020202
 *   out = 0x0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990
 *
 * To regenerate / cross-check from Solana's side:
 *
 *   // Cargo.toml: solana-poseidon = "*"
 *   use solana_poseidon::{hashv, Endianness, Parameters};
 *   let h = hashv(Parameters::Bn254X5, Endianness::BigEndian,
 *                 &[&[1u8; 32], &[2u8; 32]]).unwrap();
 *   println!("0x{}", hex::encode(h.to_bytes()));
 */

#include <ligetron/api.h>
#include <ligetron/poseidon_s.h>

using namespace ligetron;

int main(int argc, char *argv[]) {
    const char* in0_str = (argc > 1)
        ? argv[1]
        : "0x0101010101010101010101010101010101010101010101010101010101010101";
    const char* in1_str = (argc > 2)
        ? argv[2]
        : "0x0202020202020202020202020202020202020202020202020202020202020202";
    const char* ref_str = (argc > 3)
        ? argv[3]
        : "0x0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990";

    bn254fr_class in0(in0_str), in1(in1_str), ref(ref_str);

    poseidon_s_context<poseidon_permx5_254bit_3>::global_init();
    poseidon_s_context<poseidon_permx5_254bit_3> ctx;

    ctx.digest_update(in0);
    ctx.digest_update(in1);
    ctx.digest_final();

    ctx.state[0].print_hex();

    bn254fr_class::assert_equal(ctx.state[0], ref);
}
