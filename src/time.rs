//! Clock access. Uses `std::time` everywhere except `wasm32-unknown-unknown` with the
//! `js` feature, where `std::time` panics and the JS `Date.now()` clock is used instead.

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown", feature = "js")))]
mod imp {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub use std::time::Instant;

    /// Current time since the Unix epoch.
    pub fn unix_now() -> Duration {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown", feature = "js"))]
mod imp {
    use std::time::Duration;

    /// Millisecond-resolution instant backed by `Date.now()`.
    #[derive(Clone, Copy, Debug)]
    pub struct Instant(f64);

    impl Instant {
        pub fn now() -> Self {
            Self(js_sys::Date::now())
        }

        /// Time elapsed since `self`; clamped to zero if the wall clock moved backwards.
        pub fn elapsed(&self) -> Duration {
            Duration::from_secs_f64((js_sys::Date::now() - self.0).max(0.0) / 1000.0)
        }
    }

    /// Current time since the Unix epoch.
    pub fn unix_now() -> Duration {
        Duration::from_secs_f64(js_sys::Date::now().max(0.0) / 1000.0)
    }
}

pub(crate) use imp::{unix_now, Instant};
