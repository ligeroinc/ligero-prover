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

#include <ligetron/poseidon2.h>
#include <memory>

using namespace ligetron;

int main(int argc, const char *argv[]) {
    const unsigned char *in = reinterpret_cast<const unsigned char*>(argv[1]);
    uint64_t len = *reinterpret_cast<const uint64_t*>(argv[2]);
    const char *ref_str = argv[3];

    bn254fr_class digest, ref;
    ref.set_str(ref_str);

    auto *ctx = poseidon2_bn254_context_new();
    poseidon2_bn254_digest_init(ctx);
    poseidon2_bn254_digest_update_bytes(ctx, in, len);
    poseidon2_bn254_digest_final(ctx, digest);
    poseidon2_bn254_context_free(ctx);

    digest.print_hex();

    bn254fr_class::assert_equal(digest, ref);

    return 0;
}