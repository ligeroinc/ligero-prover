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
#include <ligetron/sha512.h>

#include <cstdio>

/************************************************************
 * Arguments:
 *     [1]: <str> Input text
 *     [2]: <hex> Reference SHA256 to compare
 ************************************************************/

int main(int argc, char *argv[]) {
    int args_len[argc];
    args_len_get(argv, args_len);

    unsigned char out[64];

    const unsigned char* ref = reinterpret_cast<const unsigned char*>(argv[2]);
    
    ligetron_sha512(out, (const unsigned char*)argv[1], args_len[1] - 1);

    for (int i = 0; i < 64; i++) {
        assert_one(out[i] == ref[i]);
    }
}
