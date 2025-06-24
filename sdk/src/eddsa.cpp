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

#include <ligetron/eddsa.h>

namespace ligetron {

static const char *jubjub_generator_str[2] = {
    "995203441582195749578291179787384436505546430278305826713579947235728471134",
    "5472060717959818805561601436314318772137091100104008585924551046643952123905"
};


void eddsa_verify(eddsa_signature& sig, jubjub_point& pk, bn254fr_class& hash) {
    jubjub_point G {
        jubjub_generator_str[0],
        jubjub_generator_str[1]
    };

    jubjub_point S = G.scalar_mul(sig.s);
    jubjub_point P = pk.scalar_mul(hash);
    P = jubjub_point::twisted_edward_add(sig.R, P);
    jubjub_point::assert_equal(S, P);
}


void eddsa_verify(const eddsa_signature_vec& sig, const jubjub_point_vec& pk, const vbn254fr_class& hash)
{
    jubjub_point_vec G {
        jubjub_generator_str[0],
        jubjub_generator_str[1]
    };

    jubjub_point_vec S = G.scalar_mul(sig.s.data());
    jubjub_point_vec P = pk.scalar_mul(hash);
    P = jubjub_point_vec::twisted_edward_add(sig.R, P);

    jubjub_point_vec::assert_equal(S, P);
}

} // namespace ligetron
