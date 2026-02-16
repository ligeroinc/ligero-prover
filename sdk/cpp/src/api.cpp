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

#include <ligetron/api.h>

int oblivious_if(bool cond, int t, int f) {
    return cond * t + !cond * f;
}

int oblivious_min(int a, int b) {
    return oblivious_if(a < b, a, b);
}

int oblivious_max(int a, int b) {
    return oblivious_if(a > b, a, b);
}

void println_str(const void* str_ptr, int len) {
    print_str(str_ptr, len);
    print_str("\n", 1);
}

int args_len_get(char **argv, int* len_buf) {
    int argc = 0;
    int total_args_len = 0;
    int res = 0;

    res = args_sizes_get(&argc, &total_args_len);
    if (res == 0) {
        for (int i = 0; i < argc; i++) {
            if (i == argc - 1) {
                len_buf[i] = (argv[0] + total_args_len) - argv[i];
            } else {
                len_buf[i] = argv[i + 1] - argv[i];
            }
        }
    }
    return res;
}
