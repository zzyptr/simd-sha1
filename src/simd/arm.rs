#[cfg(target_arch = "arm")]
use std::arch::arm::*;
#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[inline]
pub unsafe fn iterate(register: uint32x4_t) -> [u32; 4] {
    let mut memory = [0; 4];
    vst1q_u32(memory.as_mut_ptr(), register);
    return memory
}

#[inline]
pub unsafe fn w_and_k(bytes: &[u8]) -> [[uint32x4_t; 5]; 4] {
    let [wx4_01, wx4_02, wx4_03, wx4_04] = message_schedule_v1(bytes);
    let wx4_05 = message_schedule_v2(wx4_04, wx4_03, wx4_02 ,wx4_01);
    let wx4_06 = message_schedule_v2(wx4_05, wx4_04, wx4_03 ,wx4_02);
    let wx4_07 = message_schedule_v2(wx4_06, wx4_05, wx4_04 ,wx4_03);
    let wx4_08 = message_schedule_v2(wx4_07, wx4_06, wx4_05 ,wx4_04);
    let wx4_09 = message_schedule_v3(wx4_08, wx4_07, wx4_05, wx4_02, wx4_01);
    let wx4_10 = message_schedule_v3(wx4_09, wx4_08, wx4_06, wx4_03, wx4_02);
    let wx4_11 = message_schedule_v3(wx4_10, wx4_09, wx4_07, wx4_04, wx4_03);
    let wx4_12 = message_schedule_v3(wx4_11, wx4_10, wx4_08, wx4_05, wx4_04);
    let wx4_13 = message_schedule_v3(wx4_12, wx4_11, wx4_09, wx4_06, wx4_05);
    let wx4_14 = message_schedule_v3(wx4_13, wx4_12, wx4_10, wx4_07, wx4_06);
    let wx4_15 = message_schedule_v3(wx4_14, wx4_13, wx4_11, wx4_08, wx4_07);
    let wx4_16 = message_schedule_v3(wx4_15, wx4_14, wx4_12, wx4_09, wx4_08);
    let wx4_17 = message_schedule_v4(wx4_14, wx4_09, wx4_03, wx4_01);
    let wx4_18 = message_schedule_v4(wx4_15, wx4_10, wx4_04, wx4_02);
    let wx4_19 = message_schedule_v4(wx4_16, wx4_11, wx4_05, wx4_03);
    let wx4_20 = message_schedule_v4(wx4_17, wx4_12, wx4_06, wx4_04);

    let k1x4 = vdupq_n_u32(0x5a827999);
    let k2x4 = vdupq_n_u32(0x6ed9eba1);
    let k3x4 = vdupq_n_u32(0x8f1bbcdc);
    let k4x4 = vdupq_n_u32(0xca62c1d6);

    return [
        [vaddq_u32(wx4_01, k1x4), vaddq_u32(wx4_02, k1x4), vaddq_u32(wx4_03, k1x4), vaddq_u32(wx4_04, k1x4), vaddq_u32(wx4_05, k1x4)],
        [vaddq_u32(wx4_06, k2x4), vaddq_u32(wx4_07, k2x4), vaddq_u32(wx4_08, k2x4), vaddq_u32(wx4_09, k2x4), vaddq_u32(wx4_10, k2x4)],
        [vaddq_u32(wx4_11, k3x4), vaddq_u32(wx4_12, k3x4), vaddq_u32(wx4_13, k3x4), vaddq_u32(wx4_14, k3x4), vaddq_u32(wx4_15, k3x4)],
        [vaddq_u32(wx4_16, k4x4), vaddq_u32(wx4_17, k4x4), vaddq_u32(wx4_18, k4x4), vaddq_u32(wx4_19, k4x4), vaddq_u32(wx4_20, k4x4)]
    ]
}

/// W[i] = M[i] where i < 16
#[inline]
unsafe fn message_schedule_v1(bytes: &[u8]) -> [uint32x4_t; 4] {
    let registerx4 = vld1q_u8_x4(bytes.as_ptr());
    return [
        vreinterpretq_u32_u8(vrev32q_u8(registerx4.0)),
        vreinterpretq_u32_u8(vrev32q_u8(registerx4.1)),
        vreinterpretq_u32_u8(vrev32q_u8(registerx4.2)),
        vreinterpretq_u32_u8(vrev32q_u8(registerx4.3))
    ]
}

/// W[i] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1 where i >= 16
#[inline]
unsafe fn message_schedule_v2(minus4: uint32x4_t, minus8: uint32x4_t, minus12: uint32x4_t, minus16: uint32x4_t) -> uint32x4_t {
    let minus3 = vextq_u32::<1>(minus4, vdupq_n_u32(0));
    let minus14 = vextq_u32::<2>(minus16, minus12);
    let wx3 = veorq_u32(veorq_u32(minus3, minus8), veorq_u32(minus14 ,minus16));
    let wx3 = veorq_u32(vshlq_n_u32::<1>(wx3), vshrq_n_u32::<31>(wx3));
    let w_3 = vextq_u32::<1>(vdupq_n_u32(0), wx3);
    let w_3 = veorq_u32(vshlq_n_u32::<1>(w_3), vshrq_n_u32::<31>(w_3));
    return veorq_u32(wx3, w_3)
}

/// W[i] = (W[i-6] ^ W[i-16] ^ W[i-28] ^ W[i-32]) rol 2 where i >= 32
#[inline]
unsafe fn message_schedule_v3(minus4: uint32x4_t, minus8: uint32x4_t, minus16: uint32x4_t, minus28: uint32x4_t, minus32: uint32x4_t) -> uint32x4_t {
    let minus6 = vextq_u32::<2>(minus8, minus4);
    let wx4 = veorq_u32(veorq_u32(minus6, minus16), veorq_u32(minus28, minus32));
    return veorq_u32(vshlq_n_u32::<2>(wx4), vshrq_n_u32::<30>(wx4))
}

/// W[i] = (W[i-12] ^ W[i-32] ^ W[i-56] ^ W[i-64]) rol 4 where i >= 64
#[inline]
unsafe fn message_schedule_v4(minus12: uint32x4_t, minus32: uint32x4_t, minus56: uint32x4_t, minus64: uint32x4_t) -> uint32x4_t {
    let wx4 = veorq_u32(veorq_u32(minus12, minus32), veorq_u32(minus56 ,minus64));
    return veorq_u32(vshlq_n_u32::<4>(wx4), vshrq_n_u32::<28>(wx4))
}