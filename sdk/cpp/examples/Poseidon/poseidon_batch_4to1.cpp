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

#include <ligetron/poseidon.h>

using namespace ligetron;
using poseidon_context_fast_t = poseidon_vec_context<poseidon_permx5_254bit_3, true>;

int main(int argc, char *argv[]) {
    const char* input_num = argv[1];
    const char* ref_num   = argv[2];

    vbn254fr_class input(input_num), ref(ref_num);

    poseidon_context_fast_t::global_init();
    poseidon_context_fast_t ctx;

    ctx.digest_update(input);
    ctx.digest_final();

    ctx.state[0].print_hex();

    vbn254fr_class::assert_equal(ctx.state[0], ref);
}