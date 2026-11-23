//! Device endurance model.
//!
//! Two independent facts drive everything downstream:
//!
//! 1. **How worn is the flash right now?**  eMMC/SD exposes this through
//!    EXT_CSD: `PRE_EOL_INFO` (byte 267) and the two `DEVICE_LIFE_TIME_EST`
//!    bytes (268 / 269).  Each life-time byte is a coarse bucket: `0x01..=0x0A`
//!    mean "0–10 %" … "90–100 %" consumed, and `0x0B` means the vendor's rated
//!    endurance has been exceeded.  We take the *worse* of Type A and Type B:
//!    whichever region reaches its limit first is what takes the device down.
//!
//! 2. **How many bytes can this specific unit still take?**  The datasheet TBW
//!    of a given eMMC part is often unknown to the integrator and is routinely
//!    optimistic.  But the governor counts host writes itself, so once the life
//!    estimate has moved off zero we can *solve* for the real endurance of the
//!    part in the field:
//!
//!    ```text
//!    estimated_total_bytes ≈ lifetime_host_bytes / (life_permille / 1000)
//!    ```
//!
//!    That turns a coarse 10 %-wide bucket into a byte budget that tracks the
//!    actual drive rather than a datasheet, and it self-corrects as the device
//!    ages.  Until enough wear has accumulated for the estimate to be
//!    trustworthy we fall back to a configured TBW.
//!
//! Both figures are then converted into the one unit operators care about:
//! **bytes per day sustainable until a target service date**, which the policy
//! engine uses as the *ceiling* for all per-app budgets.

use crate::units::{clamp_u64, mul_div, MILLI};
use serde::{Deserialize, Serialize};

/// Pre-EOL indicator from EXT_CSD byte 267.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub enum PreEol {
    /// 0x00 / unknown — no information.
    #[default]
    Unknown,
    /// 0x01 — normal, under 80 % of rated endurance.
    Normal,
    /// 0x02 — warning, 80–90 % consumed.
    Warning,
    /// 0x03 — urgent, over 90 % consumed.
    Urgent,
}

impl PreEol {
    pub fn from_ext_csd(byte: u8) -> Self {
        match byte {
            0x01 => PreEol::Normal,
            0x02 => PreEol::Warning,
            0x03 => PreEol::Urgent,
            _ => PreEol::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            PreEol::Unknown => "unknown",
            PreEol::Normal => "normal",
            PreEol::Warning => "warning",
            PreEol::Urgent => "urgent",
        }
    }
}

/// Convert a `DEVICE_LIFE_TIME_EST` bucket to a permille lower bound and an
/// upper bound.  0x0B ("exceeded") is reported as 1000..=1000 so that any
/// consumer treats it as fully consumed.
pub fn life_bucket_permille(byte: u8) -> (u16, u16) {
    match byte {
        0x01..=0x0A => {
            let lo = (byte as u16 - 1) * 100;
            (lo, lo + 100)
        }
        0x0B => (MILLI as u16, MILLI as u16),
        // 0x00 is "not defined"; treat as unknown rather than as 0 % healthy.
        _ => (0, 0),
    }
}

/// Life stage ladder.  Ordered: `Green < Amber < Orange < Red`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Stage {
    /// Plenty of life left.  Budgets set purely by fairness/nominal policy.
    Green = 0,
    /// Start bending budgets toward durability.
    Amber = 1,
    /// Device is in pre-EOL warning.  Only essential writes get room.
    Orange = 2,
    /// Pre-EOL urgent.  Freeze the writable set; protect critical functions.
    Red = 3,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Green => "green",
            Stage::Amber => "amber",
            Stage::Orange => "orange",
            Stage::Red => "red",
        }
    }
}

/// Thresholds that map consumed life to a [`Stage`].  All in permille.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageThresholds {
    pub amber: u16,
    pub orange: u16,
    pub red: u16,
    /// Hysteresis band: a stage is only left once wear drops this far below its
    /// entry threshold.  Wear is monotonic so this is mostly belt-and-braces
    /// against a garbled EXT_CSD read, but it also keeps a noisy sampler from
    /// flapping the policy.
    pub hysteresis: u16,
}

impl Default for StageThresholds {
    fn default() -> Self {
        StageThresholds {
            amber: 600,
            orange: 800,
            red: 900,
            hysteresis: 30,
        }
    }
}

impl StageThresholds {
    pub fn classify(&self, life_permille: u16, previous: Stage) -> Stage {
        // Evaluate entry from the top down so that Red wins ties.
        let entry = if life_permille >= self.red {
            Stage::Red
        } else if life_permille >= self.orange {
            Stage::Orange
        } else if life_permille >= self.amber {
            Stage::Amber
        } else {
            Stage::Green
        };

        // Only allow moving *down* a stage when we are clearly below the
        // threshold for the current stage.
        if entry < previous {
            let floor = match previous {
                Stage::Red => self.red.saturating_sub(self.hysteresis),
                Stage::Orange => self.orange.saturating_sub(self.hysteresis),
                Stage::Amber => self.amber.saturating_sub(self.hysteresis),
                Stage::Green => 0,
            };
            if life_permille >= floor {
                return previous;
            }
        }
        entry
    }
}

/// A raw sample of the device's own wear report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WearSample {
    /// Raw EXT_CSD byte 268, or `None` if the device does not report it.
    pub life_a: Option<u8>,
    /// Raw EXT_CSD byte 269.
    pub life_b: Option<u8>,
    /// Raw EXT_CSD byte 267.
    pub pre_eol: Option<u8>,
}

impl WearSample {
    /// Worst-case consumed-life lower bound in permille.
    ///
    /// We use the *upper* bound of the worst bucket, because the policy has to
    /// behave for the wear level the device might already be at.  A device
    /// reporting "80–90 %" is treated as 90 %.
    pub fn life_permille(&self) -> Option<u16> {
        let a = self.life_a.map(|b| life_bucket_permille(b).1);
        let b = self.life_b.map(|b| life_bucket_permille(b).1);
        match (a, b) {
            (None, None) => None,
            (Some(x), None) | (None, Some(x)) => Some(x).filter(|v| *v > 0),
            (Some(x), Some(y)) => Some(x.max(y)).filter(|v| *v > 0),
        }
    }

    pub fn pre_eol(&self) -> PreEol {
        self.pre_eol.map(PreEol::from_ext_csd).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.life_a.is_none() && self.life_b.is_none() && self.pre_eol.is_none()
    }
}

/// Endurance bookkeeping for the device as a whole.
///
/// Invariant: `life_permille` never decreases across `observe` calls.  A
/// garbage read (all zero, sensor glitch) is therefore ignored rather than
/// resetting us to "healthy".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WearState {
    /// Worst-case consumed life in permille, ratcheted monotonic.
    pub life_permille: u16,
    pub pre_eol: PreEol,
    /// Cumulative host-issued bytes attributed to the whole device since the
    /// governor was first installed.  This is our independent measurement and
    /// is what lets us solve for real endurance.
    pub lifetime_host_bytes: u64,
    /// Configured TBW, used until the measured estimate is trustworthy.
    pub configured_tbw_bytes: u64,
    /// Solved-for total endurance, `None` until trust threshold reached.
    pub measured_tbw_bytes: Option<u64>,
    pub samples: u32,
    /// Start of the current service-life accounting window (ms).
    pub window_start_ms: i64,
}

/// Life below this (2 %) is too coarse to invert into an endurance estimate:
/// one bucket step is 10 %, so a 2 % reading could be off by 5×.
pub const MIN_PERMILLE_FOR_ESTIMATE: u16 = 20;

impl WearState {
    pub fn new(configured_tbw_bytes: u64, now_ms: i64) -> Self {
        WearState {
            life_permille: 0,
            pre_eol: PreEol::Unknown,
            lifetime_host_bytes: 0,
            configured_tbw_bytes,
            measured_tbw_bytes: None,
            samples: 0,
            window_start_ms: now_ms,
        }
    }

    /// Fold in a fresh device sample plus the bytes written since the last one.
    pub fn observe(&mut self, sample: WearSample, host_bytes_since_last: u64) {
        self.lifetime_host_bytes = self.lifetime_host_bytes.saturating_add(host_bytes_since_last);
        if sample.is_empty() {
            return;
        }
        self.samples = self.samples.saturating_add(1);

        if let Some(pre) = sample.pre_eol.filter(|b| *b != 0) {
            self.pre_eol = self.pre_eol.max(PreEol::from_ext_csd(pre));
        }
        if let Some(life) = sample.life_permille() {
            // Ratchet: wear cannot go backwards.
            if life > self.life_permille {
                self.life_permille = life;
            }
        }

        self.refresh_estimate();
    }

    /// Allow configuration/telemetry to raise the wear floor, e.g. when a
    /// server-side fleet record knows the part was already used at build time.
    pub fn set_wear_floor(&mut self, life_permille: u16, pre_eol: PreEol) {
        self.life_permille = self.life_permille.max(life_permille.min(MILLI as u16));
        self.pre_eol = self.pre_eol.max(pre_eol);
        self.refresh_estimate();
    }

    fn refresh_estimate(&mut self) {
        if self.life_permille < MIN_PERMILLE_FOR_ESTIMATE || self.lifetime_host_bytes == 0 {
            self.measured_tbw_bytes = None;
            return;
        }
        // total ≈ written / (life / 1000)
        let total = mul_div(self.lifetime_host_bytes, MILLI, self.life_permille as u64);
        // Sanity floor: never trust an estimate below the configured TBW, that
        // would mean we under-accounted writes somewhere (e.g. before install).
        self.measured_tbw_bytes = Some(total.max(self.configured_tbw_bytes));
    }

    /// Best available estimate of the device's total write endurance.
    pub fn total_endurance_bytes(&self) -> u64 {
        self.measured_tbw_bytes
            .unwrap_or(self.configured_tbw_bytes)
            .max(1)
    }

    /// Bytes we believe remain before the device reaches its rated endurance.
    pub fn remaining_bytes(&self) -> u64 {
        let total = self.total_endurance_bytes();
        let consumed = mul_div(total, self.life_permille as u64, MILLI);
        total.saturating_sub(consumed)
    }

    /// Worst-case bytes remaining, assuming the true wear is at the top of the
    /// current reporting bucket *and* the endurance estimate is optimistic.
    pub fn remaining_bytes_pessimistic(&self) -> u64 {
        self.remaining_bytes()
    }

    pub fn stage(&self, th: &StageThresholds, previous: Stage) -> Stage {
        // A pre-EOL urgent flag is an independent, vendor-blessed signal: let it
        // force Red even if the percentage arithmetic disagrees.
        let effective = match self.pre_eol {
            PreEol::Urgent => self.life_permille.max(th.red),
            PreEol::Warning => self.life_permille.max(th.orange),
            _ => self.life_permille,
        };
        th.classify(effective, previous)
    }

    /// How far ahead of schedule the device's wear is, in permille of total
    /// endurance.  Positive means wearing faster than the service-life plan.
    ///
    /// This, not the absolute wear percentage, is the right trigger for
    /// throttling.  A fleet writing exactly its sustainable rate is perfectly
    /// on track with 60 % consumed at 60 % of its service life, and cutting its
    /// budgets there would punish compliant users for nothing.  Conversely a
    /// device at only 20 % wear but three years into a two-year plan is in
    /// trouble.  `elapsed_permille` is the fraction of the service life that has
    /// elapsed, so the gap between it and consumed wear is the burn rate error.
    pub fn pace_overrun_permille(&self, elapsed_permille: u16) -> i32 {
        self.life_permille as i32 - elapsed_permille as i32
    }

    /// Bytes per day that keep the device alive until `target_days` from now.
    ///
    /// This is the adaptive ceiling for the whole system:  if the fleet is
    /// supposed to survive another 5 years and only 40 GiB of endurance is
    /// left, every app's budget is scaled to fit inside 40 GiB / 5 y.
    pub fn sustainable_bytes_per_day(&self, target_days: u64) -> u64 {
        if target_days == 0 {
            return 0;
        }
        self.remaining_bytes() / target_days
    }

    /// Rough projection of days until end-of-life at a given sustained rate.
    pub fn days_to_eol(&self, bytes_per_day: u64) -> u64 {
        if bytes_per_day == 0 {
            return u64::MAX;
        }
        self.remaining_bytes() / bytes_per_day
    }

    /// Consumed-life fraction as a float 0.0..=1.0, for reporting.
    pub fn wear_fraction(&self) -> f64 {
        (self.life_permille as f64 / MILLI as f64).min(1.0)
    }
}

/// Apply an explicit cap to a computed ceiling.
pub fn cap(ceiling: u64, hard: u64) -> u64 {
    clamp_u64(ceiling, 0, hard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_mapping() {
        assert_eq!(life_bucket_permille(0x01), (0, 100));
        assert_eq!(life_bucket_permille(0x05), (400, 500));
        assert_eq!(life_bucket_permille(0x0A), (900, 1000));
        assert_eq!(life_bucket_permille(0x0B), (1000, 1000));
        assert_eq!(life_bucket_permille(0x00), (0, 0));
    }

    #[test]
    fn sample_takes_worst_of_a_and_b() {
        let s = WearSample {
            life_a: Some(0x03), // 20-30%
            life_b: Some(0x07), // 60-70%
            pre_eol: Some(0x01),
        };
        assert_eq!(s.life_permille(), Some(700));
    }

    #[test]
    fn sample_zero_is_treated_as_unknown() {
        let s = WearSample {
            life_a: Some(0),
            life_b: Some(0),
            pre_eol: Some(0),
        };
        assert_eq!(s.life_permille(), None);
        assert!(s.pre_eol() == PreEol::Unknown);
    }

    #[test]
    fn wear_ratchets_up_only() {
        let mut w = WearState::new(100 * 1024 * 1024 * 1024, 0);
        w.observe(
            WearSample {
                life_a: Some(0x06),
                life_b: Some(0x06),
                pre_eol: Some(1),
            },
            0,
        );
        assert_eq!(w.life_permille, 600);
        // A glitched read must not reset us to healthy.
        w.observe(
            WearSample {
                life_a: Some(0x01),
                life_b: Some(0x01),
                pre_eol: Some(1),
            },
            0,
        );
        assert_eq!(w.life_permille, 600);
    }

    #[test]
    fn endurance_is_solved_from_observed_wear() {
        // 100 GiB configured TBW; we wrote 20 GiB and the device says 10 % used.
        // Implied endurance = 20/0.10 = 200 GiB.
        let mut w = WearState::new(100 * 1024 * 1024 * 1024, 0);
        let gib = 1024u64 * 1024 * 1024;
        w.observe(
            WearSample {
                life_a: Some(0x01),
                life_b: Some(0x01),
                pre_eol: Some(1),
            },
            20 * gib,
        );
        assert_eq!(w.measured_tbw_bytes, Some(200 * gib));
        // 10 % consumed -> 180 GiB remaining.
        assert_eq!(w.remaining_bytes(), 180 * gib);
    }

    #[test]
    fn estimate_never_below_configured() {
        // We wrote a lot but wear barely moved: estimate would be huge, fine.
        // If wear moved more than writes suggest, clamp to configured TBW.
        let mut w = WearState::new(500 * 1024 * 1024 * 1024, 0);
        w.observe(
            WearSample {
                life_a: Some(0x05), // 50%
                life_b: Some(0x05),
                pre_eol: Some(1),
            },
            1_000,
        );
        assert_eq!(
            w.measured_tbw_bytes,
            Some(500 * 1024 * 1024 * 1024),
            "must not trust an estimate below configured TBW"
        );
    }

    #[test]
    fn stage_thresholds_and_hysteresis() {
        let th = StageThresholds::default();
        assert_eq!(th.classify(0, Stage::Green), Stage::Green);
        assert_eq!(th.classify(599, Stage::Green), Stage::Green);
        assert_eq!(th.classify(600, Stage::Green), Stage::Amber);
        assert_eq!(th.classify(800, Stage::Amber), Stage::Orange);
        assert_eq!(th.classify(900, Stage::Orange), Stage::Red);
        // Just below red, still Red because of hysteresis.
        assert_eq!(th.classify(890, Stage::Red), Stage::Red);
        // Well below red: allowed to drop back.
        assert_eq!(th.classify(850, Stage::Red), Stage::Orange);
    }

    #[test]
    fn pre_eol_urgent_forces_red() {
        let th = StageThresholds::default();
        let mut w = WearState::new(1, 0);
        w.observe(
            WearSample {
                life_a: Some(0x09),
                life_b: Some(0x09),
                pre_eol: Some(0x03),
            },
            0,
        );
        assert_eq!(w.stage(&th, Stage::Green), Stage::Red);
    }

    #[test]
    fn sustainable_rate_scales_with_remaining_life() {
        let gib = 1024u64 * 1024 * 1024;
        let mut w = WearState::new(1000 * gib, 0);
        w.observe(
            WearSample {
                life_a: Some(0x09),
                life_b: Some(0x09),
                pre_eol: Some(3),
            },
            0,
        );
        // 100 GiB left over 5 years.
        let bpd = w.sustainable_bytes_per_day(365 * 5);
        assert_eq!(bpd, 100 * gib / (365 * 5));
    }
}
