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
 * Vectorized 2-to-1 Poseidon hash (compatible with Solana's
 * `sol_poseidon`, width t=3, two inputs, one output).
 *
 * Pass two inputs + the expected reference output as argv:
 *   ./poseidon_batch_2to1.wasm <in0> <in1> <ref>
 * 
 * Built-in test vector:
 *   in0 = 0x0101010101010101010101010101010101010101010101010101010101010101
 *   in1 = 0x0202020202020202020202020202020202020202020202020202020202020202
 *   out = 0x0d54e1938f8a8c1c7deb5e0355f26319207b84fe9ca2ce1b26e735c829821990
 */

#include <ligetron/poseidon.h>

using namespace ligetron;
using poseidon_context_fast_t =
    poseidon_vec_context<poseidon_permx5_254bit_3, true>;

int main(int argc, char *argv[]) {
    const char* in0_str = argv[1];
    const char* in1_str = argv[2];
    const char* ref_str = argv[3];

    vbn254fr_class in0(in0_str), in1(in1_str), ref(ref_str);

    poseidon_context_fast_t::global_init();
    poseidon_context_fast_t ctx;

    ctx.digest_update(in0);
    ctx.digest_update(in1);
    ctx.digest_final();

    ctx.state[0].print_hex();

    vbn254fr_class::assert_equal(ctx.state[0], ref);
}
