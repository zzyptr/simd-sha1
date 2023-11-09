//! # simd-sha1
//! SHA1 implementation with simd.
//! 
//! The algorithm of implementation was published in [there](https://www.intel.com/content/www/us/en/developer/articles/technical/improving-the-performance-of-the-secure-hash-algorithm-1.html) by Maxim Loktyukhin

#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// # Examples
///
/// ```
/// let data = [];
/// 
/// let digest = simd_sha1::hash(&data);
/// let expect = [
///    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 
///    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
/// ];
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

unsafe fn hash_block(state: [u32; 5], bytes: &[u8]) -> [u32; 5] {
    let wx4_00 = load::<00>(bytes);
    let wx4_01 = load::<16>(bytes);
    let wx4_02 = load::<32>(bytes);
    let wx4_03 = load::<48>(bytes);
    let wx4_04 = schedule_v1(wx4_03, wx4_02, wx4_01 ,wx4_00);
    let wx4_05 = schedule_v1(wx4_04, wx4_03, wx4_02 ,wx4_01);
    let wx4_06 = schedule_v1(wx4_05, wx4_04, wx4_03 ,wx4_02);
    let wx4_07 = schedule_v1(wx4_06, wx4_05, wx4_04 ,wx4_03);
    let wx4_08 = schedule_v2(wx4_07, wx4_06, wx4_04, wx4_01, wx4_00);
    let wx4_09 = schedule_v2(wx4_08, wx4_07, wx4_05, wx4_02, wx4_01);
    let wx4_10 = schedule_v2(wx4_09, wx4_08, wx4_06, wx4_03, wx4_02);
    let wx4_11 = schedule_v2(wx4_10, wx4_09, wx4_07, wx4_04, wx4_03);
    let wx4_12 = schedule_v2(wx4_11, wx4_10, wx4_08, wx4_05, wx4_04);
    let wx4_13 = schedule_v2(wx4_12, wx4_11, wx4_09, wx4_06, wx4_05);
    let wx4_14 = schedule_v2(wx4_13, wx4_12, wx4_10, wx4_07, wx4_06);
    let wx4_15 = schedule_v2(wx4_14, wx4_13, wx4_11, wx4_08, wx4_07);
    let wx4_16 = schedule_v3(wx4_13, wx4_08, wx4_02, wx4_00);
    let wx4_17 = schedule_v3(wx4_14, wx4_09, wx4_03, wx4_01);
    let wx4_18 = schedule_v3(wx4_15, wx4_10, wx4_04, wx4_02);
    let wx4_19 = schedule_v3(wx4_16, wx4_11, wx4_05, wx4_03);

    let k1x4 = _mm_set1_epi32(0x5a827999u32 as i32);
    let k2x4 = _mm_set1_epi32(0x6ed9eba1u32 as i32);
    let k3x4 = _mm_set1_epi32(0x8f1bbcdcu32 as i32);
    let k4x4 = _mm_set1_epi32(0xca62c1d6u32 as i32);

    let wk1x4x5 = [
        _mm_add_epi32(wx4_00, k1x4),
        _mm_add_epi32(wx4_01, k1x4),
        _mm_add_epi32(wx4_02, k1x4),
        _mm_add_epi32(wx4_03, k1x4),
        _mm_add_epi32(wx4_04, k1x4)
    ];
    let wk2x4x5 = [
        _mm_add_epi32(wx4_05, k2x4),
        _mm_add_epi32(wx4_06, k2x4),
        _mm_add_epi32(wx4_07, k2x4),
        _mm_add_epi32(wx4_08, k2x4),
        _mm_add_epi32(wx4_09, k2x4)
    ];
    let wk3x4x5 = [
        _mm_add_epi32(wx4_10, k3x4),
        _mm_add_epi32(wx4_11, k3x4),
        _mm_add_epi32(wx4_12, k3x4),
        _mm_add_epi32(wx4_13, k3x4),
        _mm_add_epi32(wx4_14, k3x4)
    ];
    let wk4x4x5 = [
        _mm_add_epi32(wx4_15, k4x4),
        _mm_add_epi32(wx4_16, k4x4),
        _mm_add_epi32(wx4_17, k4x4),
        _mm_add_epi32(wx4_18, k4x4),
        _mm_add_epi32(wx4_19, k4x4)
    ];
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    for wk1x4 in wk1x4x5 {
        for wk1 in destructure(wk1x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b & c ^ !b & d).wrapping_add(wk1);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk2x4 in wk2x4x5 {
        for wk2 in destructure(wk2x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b ^ c ^ d).wrapping_add(wk2);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk3x4 in wk3x4x5 {
        for wk3 in destructure(wk3x4) {
            let f = e.wrapping_add(a.rotate_left(5)).wrapping_add(b & c ^ b & d ^ c & d).wrapping_add(wk3);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = f;
        }
    }
    for wk4x4 in wk4x4x5 {
        for wk4 in destructure(wk4x4) {
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

#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn load<const OFFSET: usize>(bytes: &[u8]) -> __m128i {
    let shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    let result = _mm_loadu_si128(bytes.as_ptr().add(OFFSET).cast());
    return _mm_shuffle_epi8(result, shuffle_mask)
}

#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn load<const OFFSET: usize>(bytes: &[u8]) -> __m128i {
    return _mm_set_epi8(
        bytes[OFFSET+12] as i8, bytes[OFFSET+13] as i8, bytes[OFFSET+14] as i8, bytes[OFFSET+15] as i8,
        bytes[OFFSET+8] as i8, bytes[OFFSET+9] as i8, bytes[OFFSET+10] as i8, bytes[OFFSET+11] as i8,
        bytes[OFFSET+4] as i8, bytes[OFFSET+5] as i8, bytes[OFFSET+6] as i8, bytes[OFFSET+7] as i8,
        bytes[OFFSET+0] as i8, bytes[OFFSET+1] as i8, bytes[OFFSET+2] as i8, bytes[OFFSET+3] as i8
    )
}

/// W[i] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1 where i >= 16
#[inline]
unsafe fn schedule_v1(minus_4: __m128i, minus_8: __m128i, minus_12: __m128i, minus_16: __m128i) -> __m128i {
    let minus_3 = _mm_srli_si128::<4>(minus_4);
    let minus_14 = connection_of(minus_16, minus_12);
    let wx3 = _mm_xor_si128(_mm_xor_si128(minus_3, minus_8), _mm_xor_si128(minus_14 ,minus_16));
    let wx3 = _mm_xor_si128(_mm_slli_epi32::<1>(wx3), _mm_srli_epi32::<31>(wx3));
    let w_3 = _mm_slli_si128::<12>(wx3);
    let w_3 = _mm_xor_si128(_mm_slli_epi32::<1>(w_3), _mm_srli_epi32::<31>(w_3));
    return _mm_xor_si128(wx3, w_3)
}


/// W[i] = (W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32]) rol 2 where i >= 32
#[inline]
unsafe fn schedule_v2(minus_4: __m128i, minus_8: __m128i, minus_16: __m128i, minus_28: __m128i, minus_32: __m128i) -> __m128i {
    let minus_6 = connection_of(minus_8, minus_4);
    let wx4 = _mm_xor_si128(_mm_xor_si128(minus_6, minus_16), _mm_xor_si128(minus_28, minus_32));
    return _mm_xor_si128(_mm_slli_epi32::<2>(wx4), _mm_srli_epi32::<30>(wx4))
}

/// W[i] = (W[i-12] ^ W[i-32] ^ W[i-56] ^ W[i-64]) rol 4 where i >= 64
#[inline]
unsafe fn schedule_v3(minus_12: __m128i, minus_32: __m128i, minus_56: __m128i, minus_64: __m128i) -> __m128i {
    let wx4 = _mm_xor_si128(_mm_xor_si128(minus_12, minus_32), _mm_xor_si128(minus_56 ,minus_64));
    return _mm_xor_si128(_mm_slli_epi32::<4>(wx4), _mm_srli_epi32::<28>(wx4))
}

#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn connection_of(first: __m128i, second: __m128i) -> __m128i {
    return _mm_alignr_epi8::<8>(second, first)
}

#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn connection_of(first: __m128i, second: __m128i) -> __m128i {
    let first = _mm_srli_si128(first, 8);
    let second = _mm_slli_si128(second, 8);
    return _mm_xor_si128(second, first)
}

#[inline]
unsafe fn destructure(pack: __m128i) -> [u32; 4] {
    let mut array = [0; 4];
    _mm_store_si128(array.as_mut_ptr().cast(), pack);
    return array
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sha1() {
        let data = "The quick brown fox jumps over the lazy dog".as_bytes();
        let digest = hash(data);
        let expect = [
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 
            0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12
        ];
        assert_eq!(digest, expect);

        let data = "The quick brown fox jumps over the lazy cog".as_bytes();
        let digest = hash(data);
        let expect = [
            0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 
            0xe8, 0x5a, 0x0b, 0xd1, 0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3
        ];
        assert_eq!(digest, expect);
    }
}