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

#include <ligetron/api.h>
#include <ligetron/poseidon.h>

using namespace ligetron;

/* Poseidon Hash
 * Test vectors:
 * In  = 42
 * Out = 11900205294312547303566650979164934562713672929231722670359450569937552281134
 */

int main(int argc, char *argv[]) {
    const char* input_num = argv[1];
    const char* ref_num   = argv[2];

    bn254fr_class input(input_num), ref(ref_num);

    poseidon_context<poseidon_permx5_254bit_5>::global_init();
    poseidon_context<poseidon_permx5_254bit_5> ctx;

    ctx.digest_update(input);
    ctx.digest_final();

    assert_equal(ctx.state[0], ref);
}