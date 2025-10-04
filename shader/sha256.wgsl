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

const num_instances     : u32 = #INSTANCES;
const num_limbs         : u32 = 8;
const sha256_block_size : u32 = 8;

const thread_block_size : u32 = 256;

struct sha256_batch_context {
    data    : array<array<u32, num_instances>, 64>,
    datalen : array<u32, num_instances>,
    bitlen  : array<array<u32, num_instances>, 2>,
    state   : array<array<u32, num_instances>, 8>,
};

struct sha256_digest { data : array<u32, sha256_block_size> };

@group(0) @binding(0) var<storage, read_write> ctx    : sha256_batch_context;
@group(0) @binding(1) var<storage, read_write> digest : array<sha256_digest>;
@group(1) @binding(0) var<storage, read>       input  : array<u32>;


var<private> k : array<u32, 64> = array<u32, 64>(
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
);

fn ROTLEFT(a : u32, b : u32) -> u32{return (((a) << (b)) | ((a) >> (32-(b))));}
fn ROTRIGHT(a : u32, b : u32) -> u32{return (((a) >> (b)) | ((a) << (32-(b))));}

fn CH(x : u32, y : u32, z : u32) -> u32{return (((x) & (y)) ^ (~(x) & (z)));}
fn MAJ(x : u32, y : u32, z : u32) -> u32{return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));}
fn EP0(x : u32) -> u32{return (ROTRIGHT(x,2u) ^ ROTRIGHT(x,13u) ^ ROTRIGHT(x,22u));}
fn EP1(x : u32) -> u32{return (ROTRIGHT(x,6u) ^ ROTRIGHT(x,11u) ^ ROTRIGHT(x,25u));}
fn SIG0(x : u32) -> u32{return (ROTRIGHT(x,7u) ^ ROTRIGHT(x,18u) ^ ((x) >> 3u));}
fn SIG1(x : u32) -> u32{return (ROTRIGHT(x,17u) ^ ROTRIGHT(x,19u) ^ ((x) >> 10u));}

// fn swap_endian(x: u32) -> u32 {
//     return ((x & 0x000000FFu) << 24) |
//            ((x & 0x0000FF00u) << 8)  |
//            ((x & 0x00FF0000u) >> 8)  |
//            ((x & 0xFF000000u) >> 24);
// }

fn sha256_transform(idx : u32) {
    var a : u32;
    var b : u32;
    var c : u32;
    var d : u32;
    var e : u32;
    var f : u32;
    var g : u32;
    var h : u32;
    var i : u32 = 0;
    var j : u32 = 0;
    var t1 : u32;
    var t2 : u32;
    var m : array<u32, 64> ;

    while(i < 16) {
        m[i] = (ctx.data[j][idx] << 24) 
            | (ctx.data[j + 1][idx] << 16) 
            | (ctx.data[j + 2][idx] << 8) 
            | (ctx.data[j + 3][idx]);
        i++;
        j += 4u;
    }

    while(i < 64) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
        i++;
    }

    a = ctx.state[0][idx];
    b = ctx.state[1][idx];
    c = ctx.state[2][idx];
    d = ctx.state[3][idx];
    e = ctx.state[4][idx];
    f = ctx.state[5][idx];
    g = ctx.state[6][idx];
    h = ctx.state[7][idx];

    i = 0u;
    for (; i < 64; i++) {
    	t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
    }

    ctx.state[0][idx] += a;
    ctx.state[1][idx] += b;
    ctx.state[2][idx] += c;
    ctx.state[3][idx] += d;
    ctx.state[4][idx] += e;
    ctx.state[5][idx] += f;
    ctx.state[6][idx] += g;
    ctx.state[7][idx] += h;
}

@compute @workgroup_size(thread_block_size)
fn sha256_init(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < num_instances; idx += workgroups.x * thread_block_size) {
        ctx.datalen[idx]   = 0u;
        ctx.bitlen[0][idx] = 0u;
        ctx.bitlen[1][idx] = 0u;
        ctx.state[0][idx]  = 0x6a09e667u;
        ctx.state[1][idx]  = 0xbb67ae85u;
        ctx.state[2][idx]  = 0x3c6ef372u;
        ctx.state[3][idx]  = 0xa54ff53au;
        ctx.state[4][idx]  = 0x510e527fu;
        ctx.state[5][idx]  = 0x9b05688cu;
        ctx.state[6][idx]  = 0x1f83d9abu;
        ctx.state[7][idx]  = 0x5be0cd19u;
    }
}

@compute @workgroup_size(thread_block_size)
fn sha256_update(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < num_instances; idx += workgroups.x * thread_block_size) {
        let bignum_idx = idx * num_limbs;

        for (var limb : u32 = 0; limb < num_limbs; limb++) {
            let val : u32 = input[bignum_idx + limb];

            // Assume the input integer is in little-endian, where val[31] is msb
            for (var j : u32 = 0u; j < 32u; j += 8u) {
                let curr = ctx.datalen[idx];
                ctx.data[curr][idx] = (val >> (24u - j)) & 0xff;
                ctx.datalen[idx]++;

                if (ctx.datalen[idx] == 64) {
                    sha256_transform(idx);
                    
                    if (ctx.bitlen[0][idx] > 0xffffffff - (512)){
                        ctx.bitlen[1][idx]++;
                    }
                    ctx.bitlen[0][idx] += 512u;

                    ctx.datalen[idx] = 0u;
                }
            }
        }
    }
}

@compute @workgroup_size(thread_block_size)
fn sha256_final(
    @builtin(global_invocation_id) globalIdx : vec3u,
    @builtin(num_workgroups) workgroups : vec3u)
{
    for (var idx : u32 = globalIdx.x; idx < num_instances; idx += workgroups.x * thread_block_size) {
        var i : u32 = ctx.datalen[idx];

        if (ctx.datalen[idx] < 56) {
            ctx.data[i][idx] = 0x80u;
            i++;
            while (i < 56){
            ctx.data[i][idx] = 0x00u;
            i++;
            }
        }
        else {
            ctx.data[i][idx] = 0x80u;
            i++;
            while (i < 64) {
            ctx.data[i][idx] = 0x00u;
            i++;
            }	  
            sha256_transform(idx);
            for (var i = 0; i < 56 ; i++) {
                ctx.data[i][idx] = 0u;
            }
        }

        if (ctx.bitlen[0][idx] > 0xffffffff - ctx.datalen[idx] * 8) {
            ctx.bitlen[1][idx]++;
        }
        ctx.bitlen[0][idx] += ctx.datalen[idx] * 8;


        ctx.data[63][idx] = ctx.bitlen[0][idx];
        ctx.data[62][idx] = ctx.bitlen[0][idx] >> 8;
        ctx.data[61][idx] = ctx.bitlen[0][idx] >> 16;
        ctx.data[60][idx] = ctx.bitlen[0][idx] >> 24;

        ctx.data[59][idx] = ctx.bitlen[1][idx];
        ctx.data[58][idx] = ctx.bitlen[1][idx] >> 8;
        ctx.data[57][idx] = ctx.bitlen[1][idx] >> 16;
        ctx.data[56][idx] = ctx.bitlen[1][idx] >> 24;
        
        sha256_transform(idx);

        for (var i : u32 = 0; i < 8; i++) {
            digest[idx].data[i] = ctx.state[i][idx];
        }
    }
}
