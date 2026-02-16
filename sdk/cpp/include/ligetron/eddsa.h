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

#ifndef __LIGETRON_EDDSA__
#define __LIGETRON_EDDSA__

#include <ligetron/babyjubjub.h>

namespace ligetron {

struct eddsa_signature {
    jubjub_point R;
    bn254fr_class s;
};

struct eddsa_signature_vec {
    jubjub_point_vec R;
    vbn254fr_class s;
};

void eddsa_verify(eddsa_signature& sig,
                  jubjub_point& pk,
                  bn254fr_class& hash);

void eddsa_verify(const eddsa_signature_vec& sig,
                  const jubjub_point_vec& pk,
                  const vbn254fr_class& hash);

} // namespace ligetron;

#endif
