#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

const HASH_VALUE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

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
    let mut hash_value = HASH_VALUE;
    for block in message.0.chunks(64) {
        unsafe {
            hash_value = hash_block(hash_value, block);
        }
    }

    let [h0, h1, h2, h3, h4] = hash_value;
    
    let mut digest = [0; 20];
    digest[00..04].copy_from_slice(&h0.to_be_bytes());
    digest[04..08].copy_from_slice(&h1.to_be_bytes());
    digest[08..12].copy_from_slice(&h2.to_be_bytes());
    digest[12..16].copy_from_slice(&h3.to_be_bytes());
    digest[16..20].copy_from_slice(&h4.to_be_bytes());
    return digest
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
unsafe fn hash_block(hash_value: [u32; 5], bytes: &[u8]) -> [u32; 5] {
    let [w00_w03, w04_w07, w08_w11, w12_w15] = schedule_v0(bytes);
    let w16_w19 = schedule_v1(w00_w03, w04_w07, w08_w11, w12_w15);
    let w20_w23 = schedule_v1(w04_w07, w08_w11, w12_w15, w16_w19);
    let w24_w27 = schedule_v1(w08_w11, w12_w15, w16_w19, w20_w23);
    let w28_w31 = schedule_v1(w12_w15, w16_w19, w20_w23, w24_w27);
    let w32_w35 = schedule_v2(w00_w03, w04_w07, w16_w19, w24_w27, w28_w31);
    let w36_w39 = schedule_v2(w04_w07, w08_w11, w20_w23, w28_w31, w32_w35);
    let w40_w43 = schedule_v2(w08_w11, w12_w15, w24_w27, w32_w35, w36_w39);
    let w44_w47 = schedule_v2(w12_w15, w16_w19, w28_w31, w36_w39, w40_w43);
    let w48_w51 = schedule_v2(w16_w19, w20_w23, w32_w35, w40_w43, w44_w47);
    let w52_w55 = schedule_v2(w20_w23, w24_w27, w36_w39, w44_w47, w48_w51);
    let w56_w59 = schedule_v2(w24_w27, w28_w31, w40_w43, w48_w51, w52_w55);
    let w60_w63 = schedule_v2(w28_w31, w32_w35, w44_w47, w52_w55, w56_w59);
    let w64_w67 = schedule_v3(w00_w03, w08_w11, w32_w35, w52_w55);
    let w68_w71 = schedule_v3(w04_w07, w12_w15, w36_w39, w56_w59);
    let w72_w75 = schedule_v3(w08_w11, w16_w19, w40_w43, w60_w63);
    let w76_w79 = schedule_v3(w12_w15, w20_w23, w44_w47, w64_w67);

    let abcde = hash_value;
    // rounds 1-20
    let kx4 = _mm_set1_epi32(0x5A827999u32 as i32);
    let abcde = compute(abcde, w00_w03, kx4, choose);
    let abcde = compute(abcde, w04_w07, kx4, choose);
    let abcde = compute(abcde, w08_w11, kx4, choose);
    let abcde = compute(abcde, w12_w15, kx4, choose);
    let abcde = compute(abcde, w16_w19, kx4, choose);

    // rounds 21-40
    let kx4 = _mm_set1_epi32(0x6ED9EBA1u32 as i32);
    let abcde = compute(abcde, w20_w23, kx4, parity);
    let abcde = compute(abcde, w24_w27, kx4, parity);
    let abcde = compute(abcde, w28_w31, kx4, parity);
    let abcde = compute(abcde, w32_w35, kx4, parity);
    let abcde = compute(abcde, w36_w39, kx4, parity);

    // rounds 41-60
    let kx4 = _mm_set1_epi32(0x8F1BBCDCu32 as i32);
    let abcde = compute(abcde, w40_w43, kx4, majority);
    let abcde = compute(abcde, w44_w47, kx4, majority);
    let abcde = compute(abcde, w48_w51, kx4, majority);
    let abcde = compute(abcde, w52_w55, kx4, majority);
    let abcde = compute(abcde, w56_w59, kx4, majority);

    // rounds 61-80
    let kx4 = _mm_set1_epi32(0xCA62C1D6u32 as i32);
    let abcde = compute(abcde, w60_w63, kx4, parity);
    let abcde = compute(abcde, w64_w67, kx4, parity);
    let abcde = compute(abcde, w68_w71, kx4, parity);
    let abcde = compute(abcde, w72_w75, kx4, parity);
    let abcde = compute(abcde, w76_w79, kx4, parity);

    let [a, b, c, d, e] = abcde;
    let [h0, h1, h2, h3, h4] = hash_value;
    return [
        a.wrapping_add(h0),
        b.wrapping_add(h1),
        c.wrapping_add(h2),
        d.wrapping_add(h3),
        e.wrapping_add(h4),
    ]
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
    let mask = _mm_set_epi64x(0x0c0d0e0f08090a0b, 0x0405060700010203);
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
            bytes[12] as i8, bytes[13] as i8, bytes[14] as i8, bytes[15] as i8,
            bytes[08] as i8, bytes[09] as i8, bytes[10] as i8, bytes[11] as i8,
            bytes[04] as i8, bytes[05] as i8, bytes[06] as i8, bytes[07] as i8,
            bytes[00] as i8, bytes[01] as i8, bytes[02] as i8, bytes[03] as i8
        ),
        _mm_set_epi8(
            bytes[28] as i8, bytes[29] as i8, bytes[30] as i8, bytes[31] as i8,
            bytes[24] as i8, bytes[25] as i8, bytes[26] as i8, bytes[27] as i8,
            bytes[20] as i8, bytes[21] as i8, bytes[22] as i8, bytes[23] as i8,
            bytes[16] as i8, bytes[17] as i8, bytes[18] as i8, bytes[19] as i8
        ),
        _mm_set_epi8(
            bytes[44] as i8, bytes[45] as i8, bytes[46] as i8, bytes[47] as i8,
            bytes[40] as i8, bytes[41] as i8, bytes[42] as i8, bytes[43] as i8,
            bytes[36] as i8, bytes[37] as i8, bytes[38] as i8, bytes[39] as i8,
            bytes[32] as i8, bytes[33] as i8, bytes[34] as i8, bytes[35] as i8
        ),
        _mm_set_epi8(
            bytes[60] as i8, bytes[61] as i8, bytes[62] as i8, bytes[63] as i8,
            bytes[56] as i8, bytes[57] as i8, bytes[58] as i8, bytes[59] as i8,
            bytes[52] as i8, bytes[53] as i8, bytes[54] as i8, bytes[55] as i8,
            bytes[48] as i8, bytes[49] as i8, bytes[50] as i8, bytes[51] as i8
        ),
    ]
}

/// |       if 16 <= t <= 79          |
/// |:-------------------------------:|
/// |w16 = (w13 ^ w8  ^ w2 ^ w0) <<< 1|
/// |w17 = (w14 ^ w9  ^ w3 ^ w1) <<< 1|
/// |w18 = (w15 ^ w10 ^ w4 ^ w2) <<< 1|
/// |w19 = (w16 ^ w11 ^ w5 ^ w3) <<< 1|
#[inline]
unsafe fn schedule_v1(w0_3: __m128i, w4_7: __m128i, w8_11: __m128i, w12_15: __m128i) -> __m128i {
    let w13_15 = _mm_srli_si128::<4>(w12_15);
    let w2_5 = half_and_half(w0_3, w4_7);
    let sum = _mm_xor_si128(_mm_xor_si128(w13_15, w8_11), _mm_xor_si128(w2_5 ,w0_3));
    let w16_18 = _mm_xor_si128(_mm_srli_epi32::<31>(sum), _mm_slli_epi32::<1>(sum));
    let w16 = _mm_slli_si128::<12>(w16_18);
    let w16rol1 = _mm_xor_si128(_mm_srli_epi32::<31>(w16), _mm_slli_epi32::<1>(w16));
    let w16_19 = _mm_xor_si128(w16_18, w16rol1);
    return w16_19
}

/// |         if 32 <= t <= 79        |
/// |:-------------------------------:|
/// |w32 = (w26 ^ w16 ^ w4 ^ w0) <<< 2|
/// |w33 = (w27 ^ w17 ^ w5 ^ w1) <<< 2|
/// |w34 = (w28 ^ w18 ^ w6 ^ w2) <<< 2|
/// |w35 = (w29 ^ w19 ^ w7 ^ w3) <<< 2|
#[inline]
unsafe fn schedule_v2(w0_3: __m128i, w4_7: __m128i, w16_19: __m128i, w24_27: __m128i, w28_31: __m128i) -> __m128i {
    let w26_29 = half_and_half(w24_27, w28_31);
    let sum = _mm_xor_si128(_mm_xor_si128(w26_29, w16_19), _mm_xor_si128(w4_7, w0_3));
    let w32_35 = _mm_xor_si128(_mm_srli_epi32::<30>(sum), _mm_slli_epi32::<2>(sum));
    return w32_35
}

/// |         if 64 <= t <= 79         |
/// |:--------------------------------:|
/// |w64 = (w52 ^ w32 ^ w8  ^ w0) <<< 4|
/// |w65 = (w53 ^ w33 ^ w9  ^ w1) <<< 4|
/// |w66 = (w54 ^ w34 ^ w10 ^ w2) <<< 4|
/// |w67 = (w55 ^ w35 ^ w11 ^ w3) <<< 4|
#[inline]
unsafe fn schedule_v3(w0_3: __m128i, w8_11: __m128i, w32_35: __m128i, w52_55: __m128i) -> __m128i {
    let sum = _mm_xor_si128(_mm_xor_si128(w52_55, w32_35), _mm_xor_si128(w8_11 ,w0_3));
    let w64_67 = _mm_xor_si128(_mm_srli_epi32::<28>(sum), _mm_slli_epi32::<4>(sum));
    return w64_67
}

#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn half_and_half(a: __m128i, b: __m128i) -> __m128i {
    return _mm_alignr_epi8::<8>(b, a)
}

#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn half_and_half(a: __m128i, b: __m128i) -> __m128i {
    return _mm_xor_si128(_mm_srli_si128(a, 8), _mm_slli_si128(b, 8))
}

#[inline]
unsafe fn compute(abcde: [u32; 5], wx4: __m128i, kx4: __m128i, function: fn(u32, u32, u32) -> u32) -> [u32; 5] {
    let mut wkx4 = Align16([0u32; 4]);
    _mm_store_si128(wkx4.0.as_mut_ptr().cast(), _mm_add_epi32(wx4, kx4));

    let [mut a, mut b, mut c, mut d, mut e] = abcde;

    for wk in wkx4.0 {
        let tmp = e.wrapping_add(a.rotate_left(5)).wrapping_add(function(b, c, d)).wrapping_add(wk);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = tmp;
    }

    return [a, b, c, d, e]
}

#[inline]
fn choose(b: u32, c: u32, d: u32) -> u32 {
    return b & c ^ !b & d
}

#[inline]
fn majority(b: u32, c: u32, d: u32) -> u32 {
    return b & c ^ b & d ^ c & d
}

#[inline]
fn parity(b: u32, c: u32, d: u32) -> u32 {
    return b ^ c ^ d
}