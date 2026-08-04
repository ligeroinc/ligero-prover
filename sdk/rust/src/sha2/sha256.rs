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

//! SHA-256 (FIPS 180-4).
//!
//! 64-byte blocks, 64 rounds, an 8-byte big-endian length field, and a 32-byte digest.

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

/// Computes the SHA-256 digest of the first `len` bytes of `input` into `out`.
///
/// # Arguments
/// * `out` - Output buffer, exactly 32 bytes
/// * `input` - Input data, at least `len` bytes
/// * `len` - Number of bytes of `input` to hash
///
/// # Panics
/// If `len` exceeds `input.len()`.
///
/// # Limits
/// The bit counter is 32-bit, matching C++, so an input of 512 MiB or more wraps it and the
/// digest is no longer FIPS 180-4.
pub fn ligetron_sha2_256(out: &mut [u8; 32], input: &[u8], len: u32) {
    // Slice up front so an oversized `len` panics here rather than part-way through the
    // compression loop. Mirrors `ligetron_sha2_512`.
    let input = &input[..len as usize];
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
    
    // Pad then compress if the 8-byte length field no longer fits
    if len > 56 {
        while len < 64 {
            sha256_buf[len] = 0;
            len += 1;
        }
        sha256_compress(&mut sha256_state, &sha256_buf);
        len = 0;
    }

    // Pad up to 56 bytes, where the length field starts
    while len < 56 {
        sha256_buf[len] = 0;
        len += 1;
    }

    // Store the length as the 8-byte big-endian bit count FIPS 180-4 requires, written as two
    // 32-bit halves so the counter can stay 32-bit. Zeroing 56..59 explicitly is required, not
    // cosmetic: the loop above stops at 56, and on the two-block path sha256_buf still holds
    // message bytes there -- it is deliberately not reset.
    store32h(0, &mut sha256_buf, 56);
    store32h(sha256_length, &mut sha256_buf, 60);
    sha256_compress(&mut sha256_state, &sha256_buf);

    // Copy output
    for i in 0..8 {
        store32h(sha256_state[i], out, 4 * i);
    }
}

/// Convenience wrapper
/// 
/// # Arguments
/// * `input` - Input data to hash
/// 
/// # Returns
/// SHA-256 hash as 32-byte array
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    ligetron_sha2_256(&mut output, input, input.len() as u32);
    output
}
#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// FIPS 180-4 two-block vector: 56 bytes, so the 8-byte length field no longer fits and a
    /// second block is required.
    ///
    /// This is the exact case the padding used to get wrong. The boundary test was `len > 60`
    /// against a length field written at offset 60, where FIPS reserves bytes 56..63; lengths
    /// congruent to 56..59 (mod 64) were squeezed into one block and hashed to the wrong
    /// digest. It mattered beyond hashing, because `ecdsa_context::verify_sha256` feeds this
    /// straight into signature verification.
    #[test]
    fn two_block_message() {
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// The padding branch flips at 56 bytes: at or below it the 8-byte length field fits in the
    /// current block, above it a whole extra block is compressed.
    ///
    /// 55..64 walks the boundary a byte at a time and 119..129 repeats it one block up, which
    /// is what catches a `len` that is reset wrongly on the two-block path. Expected values are
    /// from FIPS 180-4 (generated with Python `hashlib`), deliberately not from this
    /// implementation or from the C++ one it mirrors.
    #[test]
    fn padding_boundaries() {
        let cases: [(usize, &str); 15] = [
            (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
            (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
            (57, "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"),
            (58, "d5c039b748aa64665782974ec3dc3025c042edf54dcdc2b5de31385b094cb678"),
            (59, "111bb261277afd65f0744b247cd3e47d386d71563d0ed995517807d5ebd4fba3"),
            (60, "11ee391211c6256460b6ed375957fadd8061cafbb31daf967db875aebd5aaad4"),
            (61, "35d5fc17cfbbadd00f5e710ada39f194c5ad7c766ad67072245f1fad45f0f530"),
            (62, "f506898cc7c2e092f9eb9fadae7ba50383f5b46a2a4fe5597dbb553a78981268"),
            (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
            (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
            (119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb"),
            (120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c"),
            (127, "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a"),
            (128, "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e"),
            (129, "c12cb024a2e5551cca0e08fce8f1c5e314555cc3fef6329ee994a3db752166ae"),
        ];
        for (n, expected) in cases {
            assert_eq!(hex(&sha256(&vec![0x61u8; n])), expected, "length {}", n);
        }
    }

    /// `ligetron_sha2_256` hashes a prefix, so a short `len` must ignore the trailing bytes
    /// rather than let them leak into the digest. Exercises the two-block path with the pad
    /// bytes overwriting real data.
    #[test]
    fn honours_len_shorter_than_input() {
        let mut out = [0u8; 32];
        ligetron_sha2_256(&mut out, &[0x61u8; 200], 56);
        assert_eq!(hex(&out), hex(&sha256(&[0x61u8; 56])));
    }
}
