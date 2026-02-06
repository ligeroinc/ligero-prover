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

#include <ligetron/ec/p256.hpp>
#include <ligetron/ec/ecdsa.hpp>
#include <ligetron/sha2.h>
#include <ligetron/api.h>


using namespace ligetron;


int main(int argc, char *argv[]) {
    int args_len[argc];
    args_len_get(argv, args_len);

    // arg 1 is message string
    const char *msg_str =                   (const char *)argv[1];

    // arg 2 is 64-byte signature (r and s pair in big endian)
    const unsigned char *signature =        (const unsigned char *)argv[2];

    // arg 3 is 64-byte public key (x and y coordinates in big endian) 
    const unsigned char *pubkey =           (const unsigned char *)argv[3];

    // caclulate message hash
    unsigned char msg_hash[32];
    ligetron_sha2_256(msg_hash, (const unsigned char*)msg_str, args_len[1] - 1);

    // read signature r and s values
    ec::p256_curve::scalar_field_element r;
    ec::p256_curve::scalar_field_element s;
    r.import_bytes_big({signature, 32});
    s.import_bytes_big({signature + 32, 32});

    // read public key
    ec::p256_curve::base_field_element pubkey_x;
    ec::p256_curve::base_field_element pubkey_y;
    pubkey_x.import_bytes_big({pubkey, 32});
    pubkey_y.import_bytes_big({pubkey + 32, 32});
    ec::p256_curve::point pub_key{pubkey_x, pubkey_y};

    ecdsa_verify<ec::p256_curve>(msg_hash, r, s, pub_key);

    return 0;
}
