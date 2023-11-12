#[cfg(target_arch = "arm")]
use std::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[inline]
pub fn hash_padded(data: Vec<u8>) -> [u8; 20] {
    const INITIAL_STATE: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    unsafe {
        let mut state = (vld1q_u32(INITIAL_STATE.as_ptr()), INITIAL_STATE[4]);
        for block in data.chunks(64) {
            state = hash_block(state, block);
        }

        let abcd = vrev32q_u8(vreinterpretq_u8_u32(state.0));
        let e = state.1;

        let mut digest = [0; 20];
        vst1q_u8(digest.as_mut_ptr(), abcd);
        digest[16..20].copy_from_slice(&e.to_be_bytes());
        return digest
    }
}

#[inline]
unsafe fn hash_block(state: (uint32x4_t, u32), bytes: &[u8]) -> (uint32x4_t, u32) {
    let data64 = vld1q_u8_x4(bytes.as_ptr());

    let k1x4 = vdupq_n_u32(0x5a827999);
    // 1-4
    let wx4_01 = vreinterpretq_u32_u8(vrev32q_u8(data64.0));
    let tmp = vsha1h_u32(vgetq_lane_u32(state.0, 0));
    let abcd = vsha1cq_u32(state.0, state.1, vaddq_u32(wx4_01, k1x4));
    let e = tmp;
    // 5-8
    let wx4_02 = vreinterpretq_u32_u8(vrev32q_u8(data64.1));
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1cq_u32(abcd, e, vaddq_u32(wx4_02, k1x4));
    let e = tmp;
    // 9-12
    let wx4_03 = vreinterpretq_u32_u8(vrev32q_u8(data64.2));
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1cq_u32(abcd, e, vaddq_u32(wx4_03, k1x4));
    let e = tmp;
    // 13-16
    let wx4_04 = vreinterpretq_u32_u8(vrev32q_u8(data64.3));
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1cq_u32(abcd, e, vaddq_u32(wx4_04, k1x4));
    let e = tmp;
    // 17-20
    let wx4_05 = vsha1su1q_u32(vsha1su0q_u32(wx4_01, wx4_02, wx4_03), wx4_04);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1cq_u32(abcd, e, vaddq_u32(wx4_05, k1x4));
    let e = tmp;

    
    let k2x4 = vdupq_n_u32(0x6ed9eba1);
    // 21-24
    let wx4_06 = vsha1su1q_u32(vsha1su0q_u32(wx4_02, wx4_03, wx4_04), wx4_05);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_06, k2x4));
    let e = tmp;
    // 25-28
    let wx4_07 = vsha1su1q_u32(vsha1su0q_u32(wx4_03, wx4_04, wx4_05), wx4_06);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_07, k2x4));
    let e = tmp;
    // 29-32
    let wx4_08 = vsha1su1q_u32(vsha1su0q_u32(wx4_04, wx4_05, wx4_06), wx4_07);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_08, k2x4));
    let e = tmp;
    // 33-36
    let wx4_09 = vsha1su1q_u32(vsha1su0q_u32(wx4_05, wx4_06, wx4_07), wx4_08);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_09, k2x4));
    let e = tmp;
    // 37-40
    let wx4_10 = vsha1su1q_u32(vsha1su0q_u32(wx4_06, wx4_07, wx4_08), wx4_09);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_10, k2x4));
    let e = tmp;

    
    let k3x4 = vdupq_n_u32(0x8f1bbcdc);
    // 41-44
    let wx4_11 = vsha1su1q_u32(vsha1su0q_u32(wx4_07, wx4_08, wx4_09), wx4_10);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1mq_u32(abcd, e, vaddq_u32(wx4_11, k3x4));
    let e = tmp;
    // 45-48
    let wx4_12 = vsha1su1q_u32(vsha1su0q_u32(wx4_08, wx4_09, wx4_10), wx4_11);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1mq_u32(abcd, e, vaddq_u32(wx4_12, k3x4));
    let e = tmp;
    // 49-52
    let wx4_13 = vsha1su1q_u32(vsha1su0q_u32(wx4_09, wx4_10, wx4_11), wx4_12);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1mq_u32(abcd, e, vaddq_u32(wx4_13, k3x4));
    let e = tmp;
    // 53-56
    let wx4_14 = vsha1su1q_u32(vsha1su0q_u32(wx4_10, wx4_11, wx4_12), wx4_13);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1mq_u32(abcd, e, vaddq_u32(wx4_14, k3x4));
    let e = tmp;
    // 57-60
    let wx4_15 = vsha1su1q_u32(vsha1su0q_u32(wx4_11, wx4_12, wx4_13), wx4_14);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1mq_u32(abcd, e, vaddq_u32(wx4_15, k3x4));
    let e = tmp;

    
    let k4x4 = vdupq_n_u32(0xca62c1d6);
    // 61-64
    let wx4_16 = vsha1su1q_u32(vsha1su0q_u32(wx4_12, wx4_13, wx4_14), wx4_15);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_16, k4x4));
    let e = tmp;
    // 65-68
    let wx4_17 = vsha1su1q_u32(vsha1su0q_u32(wx4_13, wx4_14, wx4_15), wx4_16);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_17, k4x4));
    let e = tmp;
    // 69-72
    let wx4_18 = vsha1su1q_u32(vsha1su0q_u32(wx4_14, wx4_15, wx4_16), wx4_17);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_18, k4x4));
    let e = tmp;
    // 73-76
    let wx4_19 = vsha1su1q_u32(vsha1su0q_u32(wx4_15, wx4_16, wx4_17), wx4_18);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_19, k4x4));
    let e = tmp;
    // 77-80
    let wx4_20 = vsha1su1q_u32(vsha1su0q_u32(wx4_16, wx4_17, wx4_18), wx4_19);
    let tmp = vsha1h_u32(vgetq_lane_u32(abcd, 0));
    let abcd = vsha1pq_u32(abcd, e, vaddq_u32(wx4_20, k4x4));
    let e = tmp;

    return (vaddq_u32(abcd, state.0), e.wrapping_add(state.1))
}