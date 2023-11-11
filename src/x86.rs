#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[inline]
pub unsafe fn iterate(register: __m128i) -> [u32; 4] {
    let mut memory = [0; 4];
    _mm_store_si128(memory.as_mut_ptr().cast(), register);
    return memory
}

#[inline]
pub unsafe fn w_and_k(bytes: &[u8]) -> [[__m128i; 5]; 4] {
    let wx4_01 = message_schedule_v1::<00>(bytes);
    let wx4_02 = message_schedule_v1::<16>(bytes);
    let wx4_03 = message_schedule_v1::<32>(bytes);
    let wx4_04 = message_schedule_v1::<48>(bytes);
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

    let k1x4 = _mm_set1_epi32(0x5a827999u32 as i32);
    let k2x4 = _mm_set1_epi32(0x6ed9eba1u32 as i32);
    let k3x4 = _mm_set1_epi32(0x8f1bbcdcu32 as i32);
    let k4x4 = _mm_set1_epi32(0xca62c1d6u32 as i32);

    return [
        [_mm_add_epi32(wx4_01, k1x4), _mm_add_epi32(wx4_02, k1x4), _mm_add_epi32(wx4_03, k1x4), _mm_add_epi32(wx4_04, k1x4), _mm_add_epi32(wx4_05, k1x4)], 
        [_mm_add_epi32(wx4_06, k2x4), _mm_add_epi32(wx4_07, k2x4), _mm_add_epi32(wx4_08, k2x4), _mm_add_epi32(wx4_09, k2x4), _mm_add_epi32(wx4_10, k2x4)], 
        [_mm_add_epi32(wx4_11, k3x4), _mm_add_epi32(wx4_12, k3x4), _mm_add_epi32(wx4_13, k3x4), _mm_add_epi32(wx4_14, k3x4), _mm_add_epi32(wx4_15, k3x4)], 
        [_mm_add_epi32(wx4_16, k4x4), _mm_add_epi32(wx4_17, k4x4), _mm_add_epi32(wx4_18, k4x4), _mm_add_epi32(wx4_19, k4x4), _mm_add_epi32(wx4_20, k4x4)]
    ]
}

/// W[i] = M[i] where i < 16
#[inline]
#[cfg(target_feature = "ssse3")]
pub unsafe fn message_schedule_v1<const OFFSET: usize>(bytes: &[u8]) -> __m128i {
    let shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    let data16 = _mm_loadu_si128(bytes.as_ptr().add(OFFSET).cast());
    return _mm_shuffle_epi8(data16, shuffle_mask)
}

/// W[i] = M[i] where i < 16
#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn message_schedule_v1<const OFFSET: usize>(bytes: &[u8]) -> __m128i {
    return _mm_set_epi8(
        bytes[OFFSET+12] as i8, bytes[OFFSET+13] as i8, bytes[OFFSET+14] as i8, bytes[OFFSET+15] as i8,
        bytes[OFFSET+8] as i8, bytes[OFFSET+9] as i8, bytes[OFFSET+10] as i8, bytes[OFFSET+11] as i8,
        bytes[OFFSET+4] as i8, bytes[OFFSET+5] as i8, bytes[OFFSET+6] as i8, bytes[OFFSET+7] as i8,
        bytes[OFFSET+0] as i8, bytes[OFFSET+1] as i8, bytes[OFFSET+2] as i8, bytes[OFFSET+3] as i8
    )
}

/// W[i] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1 where i >= 16
#[inline]
unsafe fn message_schedule_v2(minus_4: __m128i, minus_8: __m128i, minus_12: __m128i, minus_16: __m128i) -> __m128i {
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
unsafe fn message_schedule_v3(minus_4: __m128i, minus_8: __m128i, minus_16: __m128i, minus_28: __m128i, minus_32: __m128i) -> __m128i {
    let minus_6 = connection_of(minus_8, minus_4);
    let wx4 = _mm_xor_si128(_mm_xor_si128(minus_6, minus_16), _mm_xor_si128(minus_28, minus_32));
    return _mm_xor_si128(_mm_slli_epi32::<2>(wx4), _mm_srli_epi32::<30>(wx4))
}

/// W[i] = (W[i-12] ^ W[i-32] ^ W[i-56] ^ W[i-64]) rol 4 where i >= 64
#[inline]
unsafe fn message_schedule_v4(minus_12: __m128i, minus_32: __m128i, minus_56: __m128i, minus_64: __m128i) -> __m128i {
    let wx4 = _mm_xor_si128(_mm_xor_si128(minus_12, minus_32), _mm_xor_si128(minus_56 ,minus_64));
    return _mm_xor_si128(_mm_slli_epi32::<4>(wx4), _mm_srli_epi32::<28>(wx4))
}

#[inline]
#[cfg(target_feature = "ssse3")]
unsafe fn connection_of(former: __m128i, latter: __m128i) -> __m128i {
    return _mm_alignr_epi8::<8>(latter, former)
}

#[inline]
#[cfg(not(target_feature = "ssse3"))]
unsafe fn connection_of(former: __m128i, latter: __m128i) -> __m128i {
    return _mm_xor_si128(_mm_slli_si128(latter, 8), _mm_srli_si128(former, 8))
}