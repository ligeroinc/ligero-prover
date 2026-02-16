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

#ifndef __LIGETRON_POSEIDON2__
#define __LIGETRON_POSEIDON2__

#include <ligetron/bn254fr_class.h>
#include <ligetron/vbn254fr_class.h>



#define POSEIDON2_BN254_Rf 8
#define POSEIDON2_BN254_Rp 56
#define POSEIDON2_BN254_T2_RC_LEN (POSEIDON2_BN254_Rf + POSEIDON2_BN254_Rp) * 2

namespace ligetron {

extern const char *poseidon2_t2_rc_str[POSEIDON2_BN254_T2_RC_LEN];

struct poseidon2_bn254_context {
    bn254fr_class state[2];
    bn254fr_class rc[POSEIDON2_BN254_T2_RC_LEN];
    bn254fr_class _tmp;
    unsigned char buf[31];
    uint32_t len;
};

struct poseidon2_vbn254_context {
    vbn254fr_class state[2];
    vbn254fr_class rc[POSEIDON2_BN254_T2_RC_LEN];
    vbn254fr_class _tmp;
    unsigned char buf[31];
    uint32_t len;
};

poseidon2_bn254_context *poseidon2_bn254_context_new();
void poseidon2_bn254_context_free(poseidon2_bn254_context *ctx);
void poseidon2_bn254_digest_init(poseidon2_bn254_context *ctx);
void poseidon2_bn254_digest_update(poseidon2_bn254_context *ctx, bn254fr_class& msg);
void poseidon2_bn254_digest_update_bytes(poseidon2_bn254_context *ctx, const unsigned char *in, uint32_t len);
void poseidon2_bn254_digest_final(poseidon2_bn254_context *ctx, bn254fr_class& out);

poseidon2_vbn254_context *poseidon2_vbn254_context_new();
void poseidon2_vbn254_context_free(poseidon2_vbn254_context *ctx);
void poseidon2_vbn254_digest_init(poseidon2_vbn254_context *ctx);
void poseidon2_vbn254_digest_update(poseidon2_vbn254_context *ctx, const vbn254fr_class& msg);
void poseidon2_vbn254_digest_update_bytes(poseidon2_vbn254_context *ctx, const unsigned char *in, uint32_t len);
void poseidon2_vbn254_digest_final(poseidon2_vbn254_context *ctx, vbn254fr_class& out);

} // namespace ligetron

#endif
