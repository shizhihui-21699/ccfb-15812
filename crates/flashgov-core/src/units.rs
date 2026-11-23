//! Small integer helpers.  The governor deliberately uses integer arithmetic
//! for anything that is persisted or compared, so that state survives save /
//! restore bit-exactly and simulation runs are reproducible.

pub const SECS_PER_DAY: u64 = 86_400;
pub const MS_PER_DAY: i64 = 86_400_000;

/// Fixed-point scale used for fractional ratios (1.0 == 1000).
pub const MILLI: u64 = 1_000;

/// `value * num / den`, saturating instead of overflowing.
pub fn mul_div(value: u64, num: u64, den: u64) -> u64 {
    if den == 0 {
        return 0;
    }
    let v = value as u128 * num as u128 / den as u128;
    v.min(u64::MAX as u128) as u64
}

/// `value * num / den` for signed deltas, saturating.
pub fn mul_div_i64(value: i64, num: i64, den: i64) -> i64 {
    if den == 0 {
        return 0;
    }
    let v = value as i128 * num as i128 / den as i128;
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Clamp into `[lo, hi]`.
pub fn clamp_u64(v: u64, lo: u64, hi: u64) -> u64 {
    v.max(lo).min(hi.max(lo))
}

/// Human readable byte count, e.g. `1.5 GiB`.
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

/// Human readable per-day rate, e.g. `120.0 MiB/day`.
pub fn fmt_bpd(bytes: u64) -> String {
    format!("{}/day", fmt_bytes(bytes))
}

/// Human readable per-second rate.
pub fn fmt_rate(bps: u64) -> String {
    format!("{}/s", fmt_bytes(bps))
}

/// Human readable duration in days.
pub fn fmt_days(days: f64) -> String {
    if days >= 365.0 {
        format!("{:.1} y", days / 365.25)
    } else if days >= 1.0 {
        format!("{days:.1} d")
    } else {
        format!("{:.1} h", days * 24.0)
    }
}

/// Wall-clock day index (UTC days since the epoch).  Used as a cheap day
/// boundary for "consumed today" counters; a clock jump only resets the
/// counter, which is the safe direction.
pub fn day_index(now_ms: i64) -> i64 {
    now_ms.div_euclid(MS_PER_DAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_saturates() {
        assert_eq!(mul_div(u64::MAX, 2, 1), u64::MAX);
        assert_eq!(mul_div(10, 3, 2), 15);
        assert_eq!(mul_div(10, 0, 7), 0);
        assert_eq!(mul_div(10, 7, 0), 0);
    }

    #[test]
    fn formatting() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1.5 KiB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }

    #[test]
    fn day_index_is_floor_for_negative() {
        assert_eq!(day_index(0), 0);
        assert_eq!(day_index(MS_PER_DAY - 1), 0);
        assert_eq!(day_index(MS_PER_DAY), 1);
        assert_eq!(day_index(-1), -1);
    }
}
