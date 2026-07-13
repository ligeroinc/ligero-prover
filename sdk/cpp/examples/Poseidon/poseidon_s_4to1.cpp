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
 * 4-to-1 Poseidon-S hash (compatible with Solana's `sol_poseidon`,
 * width t=5, four inputs, one output).
 *
 * Pass four input field elements + the expected reference output as argv:
 *   ./poseidon_s_4to1.wasm <in0> <in1> <in2> <in3> <ref>
 *
 * Example arguments:
 *   in0 = 1
 *   in1 = 2
 *   in3 = 3
 *   in4 = 4
 *   out = 0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465
 *
 * To generate a reference value from Solana's side:
 *
 *   // Cargo.toml: solana-poseidon = "*"
 *   use solana_poseidon::{hashv, Endianness, Parameters};
 *   let h = hashv(Parameters::Bn254X5, Endianness::BigEndian,
 *                 &[&in0_bytes, &in1_bytes, &in2_bytes, &in3_bytes]).unwrap();
 *   println!("0x{}", hex::encode(h.to_bytes()));
 */

#include <ligetron/api.h>
#include <ligetron/poseidon_s.h>

using namespace ligetron;

int main(int argc, char *argv[]) {
    if (argc < 6) {
        print_str("Usage: poseidon_s_4to1 <in0> <in1> <in2> <in3> <ref>", 53);
        assert_one(0);
        return 1;
    }

    bn254fr_class in0(argv[1]), in1(argv[2]), in2(argv[3]), in3(argv[4]),
                  ref(argv[5]);

    poseidon_s_context<poseidon_permx5_254bit_5>::global_init();
    poseidon_s_context<poseidon_permx5_254bit_5> ctx;

    ctx.digest_update(in0);
    ctx.digest_update(in1);
    ctx.digest_update(in2);
    ctx.digest_update(in3);
    ctx.digest_final();

    bn254fr_class::assert_equal(ctx.state[0], ref);
}
