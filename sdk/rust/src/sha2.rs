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

//! SHA-256 cryptographic hash functions for Ligetron

/// SHA-256 constants (K)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

/// Right rotate function
#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    ((x & 0xFFFFFFFF) >> (n & 31)) | ((x) << ((32 - (n & 31)) & 31)) & 0xFFFFFFFF
}

/// Right shift function
#[inline]
fn shr(x: u32, n: u32) -> u32 {
    (x & 0xFFFFFFFF) >> n
}

/// Gamma0 function for SHA-256
#[inline]
fn gamma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)
}

/// Gamma1 function for SHA-256
#[inline]
fn gamma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)
}

/// Store 32-bit value in big-endian format
#[inline]
fn store32h(x: u32, y: &mut [u8], offset: usize) {
    y[offset] = ((x >> 24) & 0xFF) as u8;
    y[offset + 1] = ((x >> 16) & 0xFF) as u8;
    y[offset + 2] = ((x >> 8) & 0xFF) as u8;
    y[offset + 3] = (x & 0xFF) as u8;
}

/// Load 32-bit value from big-endian format
#[inline]
fn load32h(y: &[u8], offset: usize) -> u32 {
    ((y[offset] as u32 & 0xFF) << 24) |
    ((y[offset + 1] as u32 & 0xFF) << 16) |
    ((y[offset + 2] as u32 & 0xFF) << 8) |
    (y[offset + 3] as u32 & 0xFF)
}

/// SHA-256 compression function
fn sha256_compress(sha256_state: &mut [u32; 8], buff: &[u8]) {
    let mut s = [0u32; 8];
    let mut w = [0u32; 64];
    
    // Copy state
    for i in 0..8 {
        s[i] = sha256_state[i];
    }
    
    // Load message schedule for first 16 words
    for i in 0..16 {
        w[i] = load32h(buff, 4 * i);
    }
    
    // Extend message schedule to 64 words
    for i in 16..64 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    
    // Main compression loop
    for i in 0..64 {
        let t0 = s[7]
            .wrapping_add(rotr(s[4], 6) ^ rotr(s[4], 11) ^ rotr(s[4], 25))
            .wrapping_add(s[6] ^ (s[4] & (s[5] ^ s[6])))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        
        let t1 = (rotr(s[0], 2) ^ rotr(s[0], 13) ^ rotr(s[0], 22))
            .wrapping_add(((s[0] | s[1]) & s[2]) | (s[0] & s[1]));
        
        s[3] = s[3].wrapping_add(t0);
        let temp = t0.wrapping_add(t1);
        
        // Rotate the working variables
        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = s[3];
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = temp;
    }
    
    // Add compressed chunk to current hash value
    for i in 0..8 {
        sha256_state[i] = sha256_state[i].wrapping_add(s[i]);
    }
}

/// Compute SHA2-256 hash of input data
/// 
/// # Arguments
/// * `out` - Output buffer (must be at least 32 bytes)
/// * `input` - Input data
/// * `len` - Length of input data
/// 
/// # Returns
/// 0 on success
pub fn ligetron_sha2_256(out: &mut [u8; 32], input: &[u8], len: u32) -> u32 {
    let mut sha256_length = 0u32;
    
    // Initialize SHA-256 state
    let mut sha256_state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ];
    
    let mut sha256_buf = [0u8; 64];
    let mut input_ptr = 0;
    let mut remaining_len = len;
    
    // Process input in 64-byte chunks
    while remaining_len >= 64 {
        sha256_compress(&mut sha256_state, &input[input_ptr..]);
        sha256_length = sha256_length.wrapping_add(64 * 8);
        input_ptr += 64;
        remaining_len -= 64;
    }
    
    // Copy remaining bytes into buffer
    for i in 0..remaining_len {
        sha256_buf[i as usize] = input[input_ptr + i as usize];
    }
    
    // Finish up (remaining_len now number of bytes in sha256_buf)
    sha256_length = sha256_length.wrapping_add(remaining_len * 8);
    let mut len = remaining_len as usize;
    sha256_buf[len] = 0x80;
    len += 1;
    
    // Pad then compress if length is above 56 bytes
    if len > 60 {
        while len < 64 {
            sha256_buf[len] = 0;
            len += 1;
        }
        sha256_compress(&mut sha256_state, &sha256_buf);
        len = 0;
    }
    
    // Pad up to 56 bytes
    while len < 60 {
        sha256_buf[len] = 0;
        len += 1;
    }
    
    // Store length and compress
    store32h(sha256_length, &mut sha256_buf, 60);
    sha256_compress(&mut sha256_state, &sha256_buf);
    
    // Copy output
    for i in 0..8 {
        store32h(sha256_state[i], out, 4 * i);
    }
    
    0
}

/// Convenience wrapper
/// 
/// # Arguments
/// * `input` - Input data to hash
/// 
/// # Returns
/// SHA-256 hash as 32-byte array
pub fn sha2_256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    ligetron_sha2_256(&mut output, input, input.len() as u32);
    output
}