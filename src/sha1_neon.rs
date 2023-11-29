#[cfg(target_arch = "arm")]
use std::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

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
    for block in message.chunks(64) {
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

#[inline]
fn padding(bytes: &[u8]) -> Vec<u8> {
    let original_length = bytes.len();
    let zero_count = ((original_length + 64) & !63) - original_length - 9;
    let mut message = bytes.to_owned();
    message.push(0x80);
    message.extend(vec![0; zero_count]);
    message.extend(((original_length as u64) << 3).to_be_bytes());
    return message
}

#[inline]
unsafe fn hash_block(hash_value: [u32; 5], bytes: &[u8]) -> [u32; 5] {
    let uint8x16x4_t(q0, q1, q2, q3) = vld1q_u8_x4(bytes.as_ptr());

    let w00_w03 = vreinterpretq_u32_u8(vrev32q_u8(q0));
    let w04_w07 = vreinterpretq_u32_u8(vrev32q_u8(q1));
    let w08_w11 = vreinterpretq_u32_u8(vrev32q_u8(q2));
    let w12_w15 = vreinterpretq_u32_u8(vrev32q_u8(q3));
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
    // 1-20
    let kx4 = vdupq_n_u32(0x5a827999);
    let abcde = compute(abcde, w00_w03, kx4, choose);
    let abcde = compute(abcde, w04_w07, kx4, choose);
    let abcde = compute(abcde, w08_w11, kx4, choose);
    let abcde = compute(abcde, w12_w15, kx4, choose);
    let abcde = compute(abcde, w16_w19, kx4, choose);

    // 21-40
    let kx4 = vdupq_n_u32(0x6ED9EBA1);
    let abcde = compute(abcde, w20_w23, kx4, parity);
    let abcde = compute(abcde, w24_w27, kx4, parity);
    let abcde = compute(abcde, w28_w31, kx4, parity);
    let abcde = compute(abcde, w32_w35, kx4, parity);
    let abcde = compute(abcde, w36_w39, kx4, parity);

    // 41-60
    let kx4 = vdupq_n_u32(0x8F1BBCDC);
    let abcde = compute(abcde, w40_w43, kx4, majority);
    let abcde = compute(abcde, w44_w47, kx4, majority);
    let abcde = compute(abcde, w48_w51, kx4, majority);
    let abcde = compute(abcde, w52_w55, kx4, majority);
    let abcde = compute(abcde, w56_w59, kx4, majority);

    // 61-80
    let kx4 = vdupq_n_u32(0xCA62C1D6);
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

/// |       if 16 <= t <= 79          |
/// |:-------------------------------:|
/// |w16 = (w13 ^ w8  ^ w2 ^ w0) <<< 1|
/// |w17 = (w14 ^ w9  ^ w3 ^ w1) <<< 1|
/// |w18 = (w15 ^ w10 ^ w4 ^ w2) <<< 1|
/// |w19 = (w16 ^ w11 ^ w5 ^ w3) <<< 1|
#[inline]
unsafe fn schedule_v1(w0_3: uint32x4_t, w4_7: uint32x4_t, w8_11: uint32x4_t, w12_15: uint32x4_t) -> uint32x4_t {
    let w13_15 = vextq_u32::<1>(w12_15, vdupq_n_u32(0));
    let w2_5 = vextq_u32::<2>(w0_3, w4_7);
    let sum = veorq_u32(veorq_u32(w13_15, w8_11), veorq_u32(w2_5 ,w0_3));
    let w16_18 = veorq_u32(vshrq_n_u32::<31>(sum), vshlq_n_u32::<1>(sum));
    let w16 = vextq_u32::<1>(vdupq_n_u32(0), w16_18);
    let w16rol1 = veorq_u32(vshrq_n_u32::<31>(w16), vshlq_n_u32::<1>(w16));
    let w16_19 = veorq_u32(w16_18, w16rol1);
    return w16_19
}

/// |         if 32 <= t <= 79        |
/// |:-------------------------------:|
/// |w32 = (w26 ^ w16 ^ w4 ^ w0) <<< 2|
/// |w33 = (w27 ^ w17 ^ w5 ^ w1) <<< 2|
/// |w34 = (w28 ^ w18 ^ w6 ^ w2) <<< 2|
/// |w35 = (w29 ^ w19 ^ w7 ^ w3) <<< 2|
#[inline]
unsafe fn schedule_v2(w0_3: uint32x4_t, w4_7: uint32x4_t, w16_19: uint32x4_t, w24_27: uint32x4_t, w28_31: uint32x4_t) -> uint32x4_t {
    let w26_29 = vextq_u32::<2>(w24_27, w28_31);
    let sum = veorq_u32(veorq_u32(w26_29, w16_19), veorq_u32(w4_7, w0_3));
    let w32_35 = veorq_u32(vshrq_n_u32::<30>(sum), vshlq_n_u32::<2>(sum));
    return w32_35
}

/// |         if 64 <= t <= 79         |
/// |:--------------------------------:|
/// |w64 = (w52 ^ w32 ^ w8  ^ w0) <<< 4|
/// |w65 = (w53 ^ w33 ^ w9  ^ w1) <<< 4|
/// |w66 = (w54 ^ w34 ^ w10 ^ w2) <<< 4|
/// |w67 = (w55 ^ w35 ^ w11 ^ w3) <<< 4|
#[inline]
unsafe fn schedule_v3(w0_3: uint32x4_t, w8_11: uint32x4_t, w32_35: uint32x4_t, w52_55: uint32x4_t) -> uint32x4_t {
    let sum = veorq_u32(veorq_u32(w52_55, w32_35), veorq_u32(w8_11, w0_3));
    let w64_67 = veorq_u32(vshrq_n_u32::<28>(sum), vshlq_n_u32::<4>(sum));
    return w64_67
}

#[inline]
unsafe fn compute(abcde: [u32; 5], wx4: uint32x4_t, kx4: uint32x4_t, func: fn(u32, u32, u32) -> u32) -> [u32; 5] {
    let mut wkx4 = [0u32; 4];
    vst1q_u32(wkx4.as_mut_ptr(), vaddq_u32(wx4, kx4));

    let [mut a, mut b, mut c, mut d, mut e] = abcde;

    for wk in wkx4 {
        let tmp = e.wrapping_add(a.rotate_left(5)).wrapping_add(func(b, c, d)).wrapping_add(wk);
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