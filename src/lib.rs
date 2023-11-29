//! # simd-sha1
//! SHA1 implementation with simd.
//! 
//! The algorithm of implementation was published in [there](https://www.intel.com/content/www/us/en/developer/articles/technical/improving-the-performance-of-the-secure-hash-algorithm-1.html) by Maxim Loktyukhin

#[cfg(target_feature = "sha")]
mod sha1_x86;
#[cfg(target_feature = "sha")]
pub use sha1_x86::hash;

#[cfg(target_feature = "sha2")]
mod sha1_arm;
#[cfg(target_feature = "sha2")]
pub use sha1_arm::hash;

#[cfg(all(not(target_feature = "sha"), target_feature = "sse2"))]
mod sha1_sse;
#[cfg(all(not(target_feature = "sha"), target_feature = "sse2"))]
pub use sha1_sse::hash;

#[cfg(all(not(target_feature = "sha2"), target_feature = "neon"))]
mod sha1_neon;
#[cfg(all(not(target_feature = "sha2"), target_feature = "neon"))]
pub use sha1_neon::hash;