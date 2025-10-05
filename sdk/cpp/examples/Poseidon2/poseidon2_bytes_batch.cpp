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

int main() {
    const char *ref_str = "20d0a48cbc645db12d09c441d41e6d5975d2f115f32b2e01d4a9bc6d87070bbc";
    unsigned char input[32];
    std::memset(input, 0xff, 32);
    vbn254fr_class digest, ref;

    auto *ctx = poseidon2_vbn254_context_new();
    poseidon2_vbn254_digest_init(ctx);
    poseidon2_vbn254_digest_update_bytes(ctx, input, 32);
    poseidon2_vbn254_digest_final(ctx, digest);
    poseidon2_vbn254_context_free(ctx);

    ref.set_str_scalar(ref_str, 16);

    digest.print_hex();

    vbn254fr_class::assert_equal(digest, ref);

    return 0;
}
