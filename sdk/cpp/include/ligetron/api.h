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

#ifndef __LIGETRON_API__
#define __LIGETRON_API__

#include <ligetron/apidef.h>
#include <stdint.h>

/* WASI preview1 */
LIGETRON_API(wasi_snapshot_preview1, args_sizes_get)
int args_sizes_get(int *argc, int *buf);
LIGETRON_API(wasi_snapshot_preview1, args_get)
int args_get(char **argv, char *buf);

/* Assertion */
LIGETRON_API(env, assert_one)      void assert_one(int);
LIGETRON_API(env, assert_zero)     void assert_zero(int);
LIGETRON_API(env, assert_constant) void assert_constant(int);

/* Witness promotion */
LIGETRON_API(env, witness_cast_u32) uint32_t witness_cast_u32(uint32_t x);
LIGETRON_API(env, witness_cast_u64) uint32_t witness_cast_u64(uint64_t x);

/* Debug */
LIGETRON_API(env, print_str)       void print_str(const void*, int);
LIGETRON_API(env, dump_memory)     void dump_memory(const void*, int);

LIGETRON_API(env, file_size_get)   int file_size_get(const char *);
LIGETRON_API(env, file_get)        int file_get(char *, const char *);

/* Helpers */
extern int args_len_get(char **argv, int* arg_len_buf);
extern void println_str(const void*, int);
extern int oblivious_if(bool cond, int t, int f);
extern int oblivious_min(int a, int b);
extern int oblivious_max(int a, int b);

#endif
