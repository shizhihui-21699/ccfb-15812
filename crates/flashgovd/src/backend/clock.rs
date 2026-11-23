//! Monotonic time.
//!
//! The governor's accounting must survive wall-clock jumps — an RTC that resets
//! on battery removal, a timezone change, an NTP correction — without either
//! charging an app a lifetime of writes or handing it a fresh budget.  So all
//! intervals are measured on `CLOCK_MONOTONIC`, which never jumps.
//!
//! Two clocks are needed, and they serve different purposes:
//!
//! * **Monotonic ms** drives every budget calculation and every `dt`.  A clock
//!   jump cannot corrupt an allowance.
//! * **Wall-clock** is used only for the maintenance window (a local-hour test)
//!   and for human-readable timestamps.  It is read fresh each tick and, if it
//!   disagrees wildly with the monotonic clock, it is ignored.

use std::time::{SystemTime, UNIX_EPOCH};

fn mono_ms() -> i64 {
    // `Instant` is monotonic but has no absolute origin, so we anchor it once.
    use std::sync::OnceLock;
    use std::time::Instant;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = ORIGIN.get_or_init(Instant::now);
    origin.elapsed().as_millis() as i64
}

/// Millisecond monotonic clock.  Starts near zero at process start; that is
/// fine because the governor persists *durations* and absolute wear, not
/// deadlines keyed to this value.
pub fn now_mono_ms() -> i64 {
    mono_ms()
}

pub fn now_wall_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Local hour, 0..=23, for the maintenance window.
///
/// Uses the C library's `localtime_r` via the TZ database; falls back to UTC if
/// that fails.  Local time is what the driver experiences — a parked car at
/// 02:00 local is what the window means — so this deliberately is not UTC.
pub fn local_hour() -> u8 {
    #[cfg(target_os = "linux")]
    {
        if let Some(h) = unsafe { libc_local_hour() } {
            return h;
        }
    }
    (now_wall_ms() / 3_600_000).rem_euclid(24) as u8
}

#[cfg(target_os = "linux")]
unsafe fn libc_local_hour() -> Option<u8> {
    let now = libc::time(std::ptr::null_mut());
    if now < 0 {
        return None;
    }
    let mut tm: libc::tm = std::mem::zeroed();
    if libc::localtime_r(&now, &mut tm).is_null() {
        return None;
    }
    Some(tm.tm_hour.clamp(0, 23) as u8)
}

/// A coarse monotonic sleep that tolerates EINTR and never busy-waits.
pub fn sleep_ms(ms: u64) {
    if ms == 0 {
        return;
    }
    #[cfg(target_os = "linux")]
    {
        let mut ts = libc::timespec {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
        };
        loop {
            let rc = unsafe { libc::nanosleep(&ts, &mut ts) };
            if rc == 0 {
                break;
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_advances() {
        let a = now_mono_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = now_mono_ms();
        assert!(b >= a);
    }

    #[test]
    fn wall_clock_is_sane() {
        // After 2020 and before 2200.
        let w = now_wall_ms();
        assert!(w > 1_577_836_800_000);
        assert!(w < 7_258_118_400_000);
    }

    #[test]
    fn local_hour_in_range() {
        assert!(local_hour() < 24);
    }
}
