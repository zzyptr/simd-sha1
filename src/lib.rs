//! # simd-sha1
//! SHA1 implementation with simd.
//! 
//! The algorithm of implementation was published in [there](https://www.intel.com/content/www/us/en/developer/articles/technical/improving-the-performance-of-the-secure-hash-algorithm-1.html) by Maxim Loktyukhin

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod arm;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use arm::*;

/// # Examples
///
/// ```
/// let data = "The quick brown fox jumps over the lazy dog".as_bytes();
/// let expect = [
///     0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84,
///     0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
/// ];
/// 
/// let digest = simd_sha1::hash(&data);
/// 
/// assert_eq!(digest, expect);
/// ```
pub fn hash(bytes: &[u8]) -> [u8; 20] {
    let original_length = bytes.len();
    let zero_count = ((original_length + 64) & !63) - original_length - 9;
    
    let mut data = bytes.to_owned();
    data.push(0x80);
    data.extend(vec![0; zero_count]);
    data.extend(((original_length as u64) << 3).to_be_bytes());
    let mut state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    for block in data.chunks(64) {
        unsafe {
            state = hash_block(state, block);
        }
    }
    let mut digest = [0; 20];
    digest[00..04].copy_from_slice(&state[0].to_be_bytes());
    digest[04..08].copy_from_slice(&state[1].to_be_bytes());
    digest[08..12].copy_from_slice(&state[2].to_be_bytes());
    digest[12..16].copy_from_slice(&state[3].to_be_bytes());
    digest[16..20].copy_from_slice(&state[4].to_be_bytes());
    return digest
}

#[inline]
unsafe fn hash_block(state: [u32; 5], bytes: &[u8]) -> [u32; 5] {
    let [wk1x4x5, wk2x4x5, wk3x4x5, wk4x4x5] = w_and_k(bytes);
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for wk1x4 in wk1x4x5 {
        for wk1 in iterate(wk1x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b & c ^ !b & d).wrapping_add(wk1);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk2x4 in wk2x4x5 {
        for wk2 in iterate(wk2x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b ^ c ^ d).wrapping_add(wk2);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk3x4 in wk3x4x5 {
        for wk3 in iterate(wk3x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b & c ^ b & d ^ c & d).wrapping_add(wk3);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk4x4 in wk4x4x5 {
        for wk4 in iterate(wk4x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b ^ c ^ d).wrapping_add(wk4);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }

    a = a.wrapping_add(state[0]);
    b = b.wrapping_add(state[1]);
    c = c.wrapping_add(state[2]);
    d = d.wrapping_add(state[3]);
    e = e.wrapping_add(state[4]);
    return [a, b, c, d, e]
}