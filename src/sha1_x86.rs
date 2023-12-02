#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const H0: i32 = 0x67452301u32 as i32;
const H1: i32 = 0xEFCDAB89u32 as i32;
const H2: i32 = 0x98BADCFEu32 as i32;
const H3: i32 = 0x10325476u32 as i32;
const H4: i32 = 0xC3D2E1F0u32 as i32;

/// # Examples
///
/// ```
/// let data = "The quick brown fox jumps over the lazy dog".as_bytes();
/// let expect = [
///     0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC, 0xED, 0x84,
///     0x9E, 0xE1, 0xBB, 0x76, 0xE7, 0x39, 0x1B, 0x93, 0xEB, 0x12
/// ];
/// 
/// let digest = simd_sha1::hash(&data);
/// 
/// assert_eq!(digest, expect);
/// ```
pub fn hash(bytes: &[u8]) -> [u8; 20] {
    let message = padding(bytes);
    unsafe {
        let mut hash_value = [_mm_set_epi32(H0, H1, H2, H3), _mm_set_epi32(H4, 0, 0, 0)];
        for block in message.0.chunks(64) {
            hash_value = hash_block(hash_value, block);
        }
        return finalize(hash_value);
    }
}

#[repr(align(16))]
struct Align16<T>(T);

#[inline]
fn padding(bytes: &[u8]) -> Align16<Vec<u8>> {
    let original_length = bytes.len();
    let zero_count = ((original_length + 64) & !63) - original_length - 9;
    let mut message = bytes.to_owned();
    message.push(0x80);
    message.extend(vec![0; zero_count]);
    message.extend(((original_length as u64) << 3).to_be_bytes());
    return Align16(message)
}

#[inline]
unsafe fn hash_block(hash_value: [__m128i; 2], bytes: &[u8]) -> [__m128i; 2] {
    let [w00_w03, w04_w07, w08_w11, w12_w15] = schedule_v0(bytes);
    let w16_w19 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w00_w03, w04_w07), w08_w11), w12_w15);
    let w20_w23 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w04_w07, w08_w11), w12_w15), w16_w19);
    let w24_w27 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w08_w11, w12_w15), w16_w19), w20_w23);
    let w28_w31 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w12_w15, w16_w19), w20_w23), w24_w27);
    let w32_w35 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w16_w19, w20_w23), w24_w27), w28_w31);
    let w36_w39 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w20_w23, w24_w27), w28_w31), w32_w35);
    let w40_w43 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w24_w27, w28_w31), w32_w35), w36_w39);
    let w44_w47 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w28_w31, w32_w35), w36_w39), w40_w43);
    let w48_w51 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w32_w35, w36_w39), w40_w43), w44_w47);
    let w52_w55 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w36_w39, w40_w43), w44_w47), w48_w51);
    let w56_w59 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w40_w43, w44_w47), w48_w51), w52_w55);
    let w60_w63 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w44_w47, w48_w51), w52_w55), w56_w59);
    let w64_w67 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w48_w51, w52_w55), w56_w59), w60_w63);
    let w68_w71 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w52_w55, w56_w59), w60_w63), w64_w67);
    let w72_w75 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w56_w59, w60_w63), w64_w67), w68_w71);
    let w76_w79 = _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32(w60_w63, w64_w67), w68_w71), w72_w75);

    let [abcd, e] = hash_value;
    let abcdew = [abcd, _mm_add_epi32(e, w00_w03)];
    // 1-20
    let abcdew = compute::<0>(abcdew, w04_w07);
    let abcdew = compute::<0>(abcdew, w08_w11);
    let abcdew = compute::<0>(abcdew, w12_w15);
    let abcdew = compute::<0>(abcdew, w16_w19);
    let abcdew = compute::<0>(abcdew, w20_w23);

    // 21-40
    let abcdew = compute::<1>(abcdew, w24_w27);
    let abcdew = compute::<1>(abcdew, w28_w31);
    let abcdew = compute::<1>(abcdew, w32_w35);
    let abcdew = compute::<1>(abcdew, w36_w39);
    let abcdew = compute::<1>(abcdew, w40_w43);

    // 41-60
    let abcdew = compute::<2>(abcdew, w44_w47);
    let abcdew = compute::<2>(abcdew, w48_w51);
    let abcdew = compute::<2>(abcdew, w52_w55);
    let abcdew = compute::<2>(abcdew, w56_w59);
    let abcdew = compute::<2>(abcdew, w60_w63);

    // 61-80
    let abcdew = compute::<3>(abcdew, w64_w67);
    let abcdew = compute::<3>(abcdew, w68_w71);
    let abcdew = compute::<3>(abcdew, w72_w75);
    let abcdew = compute::<3>(abcdew, w76_w79);
    let [h0_3, h4] = hash_value;
    let abcde  = compute::<3>(abcdew, h4);
    
    let [abcd, e] = abcde;
    return [_mm_add_epi32(abcd, h0_3), e]
}

/// |if 0 <= t <= 15|
/// |:-------------:|
/// |    w0 = m0    |
/// |    w1 = m1    |
/// |    w2 = m2    |
/// |    w3 = m3    |
#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn schedule_v0(bytes: &[u8]) -> [__m128i; 4] {
    let mask = _mm_set_epi64x(0x0001020304050607, 0x08090A0B0C0D0E0F);
    let q0 = _mm_load_si128(bytes.as_ptr().cast());
    let q1 = _mm_load_si128(bytes.as_ptr().add(16).cast());
    let q2 = _mm_load_si128(bytes.as_ptr().add(32).cast());
    let q3 = _mm_load_si128(bytes.as_ptr().add(48).cast());
    return [
        _mm_shuffle_epi8(q0, mask), 
        _mm_shuffle_epi8(q1, mask),
        _mm_shuffle_epi8(q2, mask),
        _mm_shuffle_epi8(q3, mask)
    ]
}

/// |if 0 <= t <= 15|
/// |:-------------:|
/// |    w0 = m0    |
/// |    w1 = m1    |
/// |    w2 = m2    |
/// |    w3 = m3    |
#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn schedule_v0(bytes: &[u8]) -> [__m128i; 4] {
    return [
        _mm_set_epi8(
            bytes[00] as i8, bytes[01] as i8, bytes[02] as i8, bytes[03] as i8,
            bytes[04] as i8, bytes[05] as i8, bytes[06] as i8, bytes[07] as i8,
            bytes[08] as i8, bytes[09] as i8, bytes[10] as i8, bytes[11] as i8,
            bytes[12] as i8, bytes[13] as i8, bytes[14] as i8, bytes[15] as i8
        ),
        _mm_set_epi8(
            bytes[16] as i8, bytes[17] as i8, bytes[18] as i8, bytes[19] as i8,
            bytes[20] as i8, bytes[21] as i8, bytes[22] as i8, bytes[23] as i8,
            bytes[24] as i8, bytes[25] as i8, bytes[26] as i8, bytes[27] as i8,
            bytes[28] as i8, bytes[29] as i8, bytes[30] as i8, bytes[31] as i8
        ),
        _mm_set_epi8(
            bytes[32] as i8, bytes[33] as i8, bytes[34] as i8, bytes[35] as i8,
            bytes[36] as i8, bytes[37] as i8, bytes[38] as i8, bytes[39] as i8,
            bytes[40] as i8, bytes[41] as i8, bytes[42] as i8, bytes[43] as i8,
            bytes[44] as i8, bytes[45] as i8, bytes[46] as i8, bytes[47] as i8
        ),
        _mm_set_epi8(
            bytes[48] as i8, bytes[49] as i8, bytes[50] as i8, bytes[51] as i8,
            bytes[52] as i8, bytes[53] as i8, bytes[54] as i8, bytes[55] as i8,
            bytes[56] as i8, bytes[57] as i8, bytes[58] as i8, bytes[59] as i8,
            bytes[60] as i8, bytes[61] as i8, bytes[62] as i8, bytes[63] as i8
        ),
    ]
}

#[inline]
unsafe fn compute<const FUNC: i32>(abcdew: [__m128i; 2], wx4: __m128i) -> [__m128i; 2] {
    let [abcd, ew] = abcdew;
    let tmp = _mm_sha1rnds4_epu32::<FUNC>(abcd, ew);
    let ew = _mm_sha1nexte_epu32(abcd, wx4);
    let abcd = tmp;
    return [abcd, ew]
}

#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn finalize(hash_value: [__m128i; 2]) -> [u8; 20] {
    let mask0 = _mm_set_epi64x(0x0001020304050607, 0x08090A0B0C0D0E0F);
    let mask1 = _mm_set_epi64x(0x0C0D0E0F00000000, 0);
    let [h0_3, h4] = hash_value;
    let h0_3 = _mm_shuffle_epi8(h0_3, mask0);
    let h4 = _mm_shuffle_epi8(h4, mask1);
    let mut digest = Align16([0; 20]);
    _mm_storeu_si128(digest.0.as_mut_ptr().add(4).cast(), h4);
    _mm_store_si128(digest.0.as_mut_ptr().cast(), h0_3);
    return digest.0
}

#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn finalize(hash_value: [__m128i; 2]) -> [u8; 20] {
    let mut buffer = Align16([0u32; 4]);
    let [h0_3, h4] = hash_value;
    _mm_store_si128(buffer.0.as_mut_ptr().cast(), h0_3);
    let [h3, h2, h1, h0] = buffer.0;
    _mm_store_si128(buffer.0.as_mut_ptr().cast(), h4);
    let [_, _, _, h4] = buffer.0;
    
    let mut digest = [0; 20];
    digest[00..04].copy_from_slice(&h0.to_be_bytes());
    digest[04..08].copy_from_slice(&h1.to_be_bytes());
    digest[08..12].copy_from_slice(&h2.to_be_bytes());
    digest[12..16].copy_from_slice(&h3.to_be_bytes());
    digest[16..20].copy_from_slice(&h4.to_be_bytes());
    return digest
}