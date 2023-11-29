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
    unsafe {
        let mut hash_value = (vld1q_u32(HASH_VALUE.as_ptr()), HASH_VALUE[4]);
        for block in message.chunks(64) {
            hash_value = hash_block(hash_value, block);
        }

        let (h0_3, h4) = hash_value;
        let h0_3 = vrev32q_u8(vreinterpretq_u8_u32(h0_3));

        let mut digest = [0; 20];
        vst1q_u8(digest.as_mut_ptr(), h0_3);
        digest[16..20].copy_from_slice(&h4.to_be_bytes());
        return digest
    }
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
unsafe fn hash_block(hash_value: (uint32x4_t, u32), bytes: &[u8]) -> (uint32x4_t, u32) {
    let uint8x16x4_t(q0, q1, q2, q3) = vld1q_u8_x4(bytes.as_ptr());

    let w00_w03 = vreinterpretq_u32_u8(vrev32q_u8(q0));
    let w04_w07 = vreinterpretq_u32_u8(vrev32q_u8(q1));
    let w08_w11 = vreinterpretq_u32_u8(vrev32q_u8(q2));
    let w12_w15 = vreinterpretq_u32_u8(vrev32q_u8(q3));
    let w16_w19 = vsha1su1q_u32(vsha1su0q_u32(w00_w03, w04_w07, w08_w11), w12_w15);
    let w20_w23 = vsha1su1q_u32(vsha1su0q_u32(w04_w07, w08_w11, w12_w15), w16_w19);
    let w24_w27 = vsha1su1q_u32(vsha1su0q_u32(w08_w11, w12_w15, w16_w19), w20_w23);
    let w28_w31 = vsha1su1q_u32(vsha1su0q_u32(w12_w15, w16_w19, w20_w23), w24_w27);
    let w32_w35 = vsha1su1q_u32(vsha1su0q_u32(w16_w19, w20_w23, w24_w27), w28_w31);
    let w36_w39 = vsha1su1q_u32(vsha1su0q_u32(w20_w23, w24_w27, w28_w31), w32_w35);
    let w40_w43 = vsha1su1q_u32(vsha1su0q_u32(w24_w27, w28_w31, w32_w35), w36_w39);
    let w44_w47 = vsha1su1q_u32(vsha1su0q_u32(w28_w31, w32_w35, w36_w39), w40_w43);
    let w48_w51 = vsha1su1q_u32(vsha1su0q_u32(w32_w35, w36_w39, w40_w43), w44_w47);
    let w52_w55 = vsha1su1q_u32(vsha1su0q_u32(w36_w39, w40_w43, w44_w47), w48_w51);
    let w56_w59 = vsha1su1q_u32(vsha1su0q_u32(w40_w43, w44_w47, w48_w51), w52_w55);
    let w60_w63 = vsha1su1q_u32(vsha1su0q_u32(w44_w47, w48_w51, w52_w55), w56_w59);
    let w64_w67 = vsha1su1q_u32(vsha1su0q_u32(w48_w51, w52_w55, w56_w59), w60_w63);
    let w68_w71 = vsha1su1q_u32(vsha1su0q_u32(w52_w55, w56_w59, w60_w63), w64_w67);
    let w72_w75 = vsha1su1q_u32(vsha1su0q_u32(w56_w59, w60_w63, w64_w67), w68_w71);
    let w76_w79 = vsha1su1q_u32(vsha1su0q_u32(w60_w63, w64_w67, w68_w71), w72_w75);

    let abcde = hash_value;
    // rounds 1-20
    let kx4 = vdupq_n_u32(0x5A827999);
    let abcde = compute(abcde, w00_w03, kx4, choose);
    let abcde = compute(abcde, w04_w07, kx4, choose);
    let abcde = compute(abcde, w08_w11, kx4, choose);
    let abcde = compute(abcde, w12_w15, kx4, choose);
    let abcde = compute(abcde, w16_w19, kx4, choose);
    
    // rounds 21-40
    let kx4 = vdupq_n_u32(0x6ED9EBA1);
    let abcde = compute(abcde, w20_w23, kx4, parity);
    let abcde = compute(abcde, w24_w27, kx4, parity);
    let abcde = compute(abcde, w28_w31, kx4, parity);
    let abcde = compute(abcde, w32_w35, kx4, parity);
    let abcde = compute(abcde, w36_w39, kx4, parity);
    
    // rounds 41-60
    let kx4 = vdupq_n_u32(0x8F1BBCDC);
    let abcde = compute(abcde, w40_w43, kx4, majority);
    let abcde = compute(abcde, w44_w47, kx4, majority);
    let abcde = compute(abcde, w48_w51, kx4, majority);
    let abcde = compute(abcde, w52_w55, kx4, majority);
    let abcde = compute(abcde, w56_w59, kx4, majority);
    
    // rounds 61-80
    let kx4 = vdupq_n_u32(0xCA62C1D6);
    let abcde = compute(abcde, w60_w63, kx4, parity);
    let abcde = compute(abcde, w64_w67, kx4, parity);
    let abcde = compute(abcde, w68_w71, kx4, parity);
    let abcde = compute(abcde, w72_w75, kx4, parity);
    let abcde = compute(abcde, w76_w79, kx4, parity);

    let (abcd, e) = abcde;
    let (h0_3, h4) = hash_value;
    return (vaddq_u32(abcd, h0_3), e.wrapping_add(h4))
}

#[inline]
unsafe fn compute(abcde: (uint32x4_t, u32), wx4: uint32x4_t, kx4: uint32x4_t, function: unsafe fn (uint32x4_t, u32, uint32x4_t) -> uint32x4_t) -> (uint32x4_t, u32) {
    let (abcd, e) = abcde;
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = function(abcd, e, vaddq_u32(wx4, kx4));
    let e = tmp;
    return (abcd, e)
}

use vsha1cq_u32 as choose;
use vsha1pq_u32 as parity;
use vsha1mq_u32 as majority;