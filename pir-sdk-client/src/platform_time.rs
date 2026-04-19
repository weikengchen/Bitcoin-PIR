//! Cross-target wall-clock seed source.
//!
//! `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`
//! (unsupported platform). This helper returns a u64 seed that works on
//! both native and wasm32: wall-clock nanos on native, `Date.now() * 1e6`
//! on wasm32.
//!
//! Only use for non-cryptographic PRNG seeding — the wasm branch is
//! millisecond-resolution and directly observable to JS. Padding / dummy
//! DPF key generation is fine; do not use this to seed secret material.

pub(crate) fn seed_nanos() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys::Date::now() as u64).wrapping_mul(1_000_000)
    }
}
