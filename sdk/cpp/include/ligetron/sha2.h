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

#ifndef __LIGETRON_SHA2__
#define __LIGETRON_SHA2__

/*
lonesha256.h - Portable, endian-proof, single-file, single-function sha256 implementation, originally based on LibTomCrypt

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring
rights to this software to the public domain worldwide. This software is distributed without any warranty.
You should have received a copy of the CC0 Public Domain Dedication along with this software.
If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/

#include <stdint.h>
#include <ligetron/apidef.h>
/* Hashes the first "len" bytes of "in" into "out",
 * which is 32 bytes for sha2_256, 64 for sha2_512.
 *
 * Limits: ligetron_sha2_256 tracks the message bit count in a 32-bit word,
 * so an input of 512 MiB or more wraps it and yields a digest that is not FIPS 180-4.
 * ligetron_sha2_512 counts in 64 bits and has no comparable limit. */
extern "C" void ligetron_sha2_256 (unsigned char *out, const unsigned char* in, uint32_t len);

extern "C" void ligetron_sha2_512 (unsigned char *out, const unsigned char* in, uint32_t len);

#endif
