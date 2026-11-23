//! Per-app byte budget: a signed token bucket that turns a *daily allowance*
//! into an *instantaneous* rate cap that `io.max` can enforce.
//!
//! # Why not just divide by 86400?
//!
//! `bytes/day ÷ 86400` is the naive cap, and it is the single most common way a
//! write limiter breaks real software.  Navigation wants to push a 2 GiB map
//! delta in twenty minutes; a dashcam wants to flush a 512 MiB segment when the
//! ignition turns off.  Both are overwhelmingly legitimate and both look, at any
//! one instant, exactly like a runaway writer.  Throttling them to their daily
//! average means the map update never finishes, the car has stale maps, and the
//! governor gets disabled by the OEM.
//!
//! A token bucket fixes this because it distinguishes **sustained rate** from
//! **banked allowance**:
//!
//! * `quota_bpd` is the sustained refill rate.  An app that writes forever
//!   converges to exactly this average.
//! * `capacity` (burst) is how much may be spent at full device speed in one
//!   go.  It defaults to a quarter of the daily allowance, with a floor, so a
//!   normal app that writes in bursts and idles between them never sees a cap.
//! * `balance` is signed.  It can go negative when an app outruns its bucket
//!   (e.g. it was already misbehaving when the governor started), and the app
//!   then runs at a trickle until the debt is repaid.
//!
//! The instantaneous cap presented to the kernel is
//!
//! ```text
//! rate = balance / TAU + refill
//! ```
//!
//! which is the rate that would exactly drain the current balance over `TAU`
//! seconds while also letting the ongoing refill through.  With a full bucket
//! the app is effectively unlimited; as the bucket empties the cap collapses to
//! the refill rate and then, in debt, to a floor.
//!
//! The floor matters as much as the ceiling.  Setting `wbps = 0` does not make
//! an app read-only, it makes every write *block forever*, freezing the UI in a
//! way users read as "the car crashed".  A trickle (a few tens of KiB/s) lets a
//! throttled app persist its state, exit cleanly and show an honest error.

use crate::units::{day_index, mul_div, MS_PER_DAY, SECS_PER_DAY};
use serde::{Deserialize, Serialize};

/// How quickly banked allowance is allowed to be spent.  A full bucket is
/// released over this many seconds, which keeps a legitimate burst fast (map
/// deltas, dashcam segment flush) without letting a misbehaving app write at
/// line rate for minutes.
pub const DEFAULT_TAU_SECS: u64 = 60;

/// Default burst capacity as a fraction of the daily quota (1/4).
pub const DEFAULT_BURST_DIVISOR: u64 = 4;

/// Minimum burst capacity, so that an app with a tiny quota can still write a
/// settings file / a database page.
pub const MIN_BURST_BYTES: u64 = 1 << 20;

/// Never throttle below this, so a throttled app can still persist state.
pub const DEFAULT_FLOOR_BPS: u64 = 16 << 10;

/// Absolute minimum trickle, used when an app's own allowance is zero (an app
/// that has been cut off at Red).  Small enough to be a rounding error against
/// the device budget, large enough that a page write completes in under a
/// minute instead of hanging forever.
pub const MIN_TRICKLE_BPS: u64 = 64;

/// A rate/rps limit as handed to the kernel.  `None` means "no limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Cap {
    pub wbps: Option<u64>,
    pub wiops: Option<u64>,
}

impl Cap {
    pub const UNLIMITED: Cap = Cap {
        wbps: None,
        wiops: None,
    };

    pub fn from_bps(wbps: u64, wiops: u64) -> Self {
        Cap {
            wbps: Some(wbps),
            wiops: Some(wiops),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.wbps.is_none() && self.wiops.is_none()
    }
}

/// How an app is treated by the policy engine.  Ordering matters: a lower class
/// yields to a higher one when the global ceiling has to be divided up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Class {
    /// Safety- and legality-critical: reversing camera, cluster, eCall.
    /// Never frozen, never throttled below a workable floor, and at Red stage
    /// they are the only writers allowed.
    Critical = 0,
    /// Required for the vehicle to function as sold: navigation map updates,
    /// dashcam, OTA.  Large but legitimate and *predictable* write volumes.
    Essential = 1,
    /// Ordinary user-facing apps (media, messages, browsers).
    Normal = 2,
    /// Third-party apps that have not been vouched for by the OEM.
    Untrusted = 3,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Critical => "critical",
            Class::Essential => "essential",
            Class::Normal => "normal",
            Class::Untrusted => "untrusted",
        }
    }
}

/// Static quota parameters for one app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quota {
    /// Sustained allowance.
    pub quota_bpd: u64,
    /// Bucket capacity; how much may be spent at full speed after idling.
    pub burst_bytes: u64,
    /// Lowest rate a throttled app is dropped to.
    pub floor_bps: u64,
    /// Cap on write IOs per second (small-write amplification).
    pub iops_cap: u64,
}

impl Quota {
    pub fn new(quota_bpd: u64) -> Self {
        Quota {
            quota_bpd,
            burst_bytes: default_burst(quota_bpd),
            floor_bps: DEFAULT_FLOOR_BPS,
            iops_cap: 512,
        }
    }

    pub fn with_burst(mut self, burst: u64) -> Self {
        self.burst_bytes = burst.max(MIN_BURST_BYTES);
        self
    }

    pub fn with_floor(mut self, floor_bps: u64) -> Self {
        self.floor_bps = floor_bps;
        self
    }

    /// The trickle rate actually applied to a debt-laden app.
    ///
    /// Two properties are required at once, and they pull in opposite
    /// directions:
    ///
    /// * **Never zero.** A `wbps` of 0 blocks every write forever and turns a
    ///   throttle into a hang, which users experience as a crashed head unit.
    /// * **Never a back door.** A fixed byte floor would let an app on a tiny
    ///   allowance write orders of magnitude over budget while nominally
    ///   "throttled" (4 MiB/day at a 16 KiB/s floor is 350× over).
    ///
    /// An app's own sustainable rate is already a non-zero trickle for any
    /// sane allowance, so the floor is simply capped at it: a throttled app
    /// runs at exactly its own allowance and no more.  This is the honest
    /// steady state — *throttled means "on allowance"*, not "off the hook".  A
    /// debt-laden app therefore never repays in wall-clock terms, which is
    /// correct: it is spending exactly what it is entitled to.
    ///
    /// Only when the allowance is zero (an app cut off at Red) or so small it
    /// rounds to zero below does the absolute [`MIN_TRICKLE_BPS`] minimum kick
    /// in, so the app can still make progress and exit cleanly rather than hang.
    pub fn effective_floor_bps(&self) -> u64 {
        let sustainable = self.quota_bpd / SECS_PER_DAY;
        if sustainable == 0 {
            return MIN_TRICKLE_BPS;
        }
        self.floor_bps.min(sustainable).max(1)
    }
}

pub fn default_burst(quota_bpd: u64) -> u64 {
    (quota_bpd / DEFAULT_BURST_DIVISOR).max(MIN_BURST_BYTES)
}

/// A signed token bucket.  All money is in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bucket {
    /// Bytes available to spend.  Negative means the app is in debt.
    pub balance: i64,
    /// Bucket capacity (refilled up to this, never above).
    pub capacity: u64,
    /// Sustained refill rate.
    pub quota_bpd: u64,
    /// Last time the bucket was advanced (ms).
    pub last_ms: i64,
    /// Bytes charged in the current UTC day (reporting / dashboards).
    pub spent_today: u64,
    /// Day index for `spent_today`.
    pub day: i64,
    /// Lifetime bytes charged to this app.
    pub lifetime: u64,
}

impl Bucket {
    /// Start with a full bucket so that an app's first legitimate action after
    /// install is not throttled.
    pub fn new(q: &Quota, now_ms: i64) -> Self {
        Bucket {
            balance: q.burst_bytes as i64,
            capacity: q.burst_bytes,
            quota_bpd: q.quota_bpd,
            last_ms: now_ms,
            spent_today: 0,
            day: day_index(now_ms),
            lifetime: 0,
        }
    }

    /// Refill up to `dt_ms` of elapsed time.  Refill is capped at `capacity`;
    /// debt is repaid before anything accumulates again.
    pub fn advance(&mut self, now_ms: i64) {
        let dt = now_ms.saturating_sub(self.last_ms).max(0) as u64;
        self.last_ms = now_ms;
        if dt == 0 {
            return;
        }
        let gain = mul_div(self.quota_bpd, dt, MS_PER_DAY as u64) as i64;
        if gain == 0 {
            // Still roll the day counter so a very long tick doesn't miss a
            // day boundary.
            self.roll_day(now_ms);
            return;
        }
        self.balance = (self.balance + gain).min(self.capacity as i64);
        self.roll_day(now_ms);
    }

    fn roll_day(&mut self, now_ms: i64) {
        let d = day_index(now_ms);
        if d != self.day {
            self.day = d;
            self.spent_today = 0;
        }
    }

    /// Refill and charge in one step, ordered so the result does **not** depend
    /// on the tick length.
    ///
    /// A naive `advance(); charge(spent)` is wrong for any interval longer than
    /// the bucket's drain time: the refill is clipped at `capacity` *before*
    /// the interval's spending is subtracted, so a day's worth of allowance is
    /// silently thrown away and a legitimate app on a coarse tick is starved.
    /// Allowing the balance to rise to `capacity + spent` and *then* subtracting
    /// `spent` gives the same answer for a 1 s tick and a 1 day tick, because
    /// the only thing `capacity` bounds is genuinely *idle* accumulation.
    pub fn advance_charge(&mut self, now_ms: i64, spent: u64) {
        let dt = now_ms.saturating_sub(self.last_ms).max(0) as u64;
        self.last_ms = now_ms;
        let gain = if dt == 0 {
            0
        } else {
            mul_div(self.quota_bpd, dt, MS_PER_DAY as u64)
        };
        let spent_i = spent.min(i64::MAX as u64) as i64;
        let ceiling = self.capacity as i64 + spent_i;
        self.balance = (self.balance + gain as i64).min(ceiling) - spent_i;
        let max_debt = (self.capacity as i64).saturating_mul(-4);
        if self.balance < max_debt {
            self.balance = max_debt;
        }
        self.spent_today = self.spent_today.saturating_add(spent);
        self.lifetime = self.lifetime.saturating_add(spent);
        self.roll_day(now_ms);
    }

    /// The balance as seen after an observed spend.  We *observe* the kernel's
    /// counters rather than trusting our own predictions: the kernel is the
    /// source of truth for what actually reached the block layer.
    pub fn charge(&mut self, bytes: u64, now_ms: i64) {
        if bytes == 0 {
            return;
        }
        let b = bytes.min(i64::MAX as u64) as i64;
        self.balance -= b;
        // Debt is bounded so a wildly misbehaving app cannot bank an
        // arbitrarily large penalty that outlives the governor process.
        let max_debt = (self.capacity as i64).saturating_mul(-4);
        if self.balance < max_debt {
            self.balance = max_debt;
        }
        self.spent_today = self.spent_today.saturating_add(bytes);
        self.lifetime = self.lifetime.saturating_add(bytes);
        self.roll_day(now_ms);
    }

    /// When the bucket was full and the kernel tells us nothing was written, we
    /// still must not ratchet the balance above capacity.
    pub fn saturate(&mut self) {
        if self.balance > self.capacity as i64 {
            self.balance = self.capacity as i64;
        }
    }

    /// Resize the bucket's capacity while preserving the "fullness" of a
    /// bucket that was already full.
    ///
    /// This matters because the policy engine changes capacity when the wear
    /// stage changes.  If a full bucket's capacity is *raised* (e.g. a critical
    /// app gets a larger burst at Red) and we did nothing, the balance would
    /// suddenly be below capacity and the app would be throttled through no
    /// fault of its own.  A bucket that was full stays full; one that was
    /// partially drained keeps its absolute balance, which is the honest
    /// interpretation of "you have this many bytes banked".
    pub fn resize(&mut self, new_capacity: u64) {
        let was_full = self.is_full();
        self.capacity = new_capacity.max(MIN_BURST_BYTES);
        if was_full {
            self.balance = self.capacity as i64;
        } else {
            self.saturate();
        }
    }

    pub fn is_full(&self) -> bool {
        self.balance >= self.full_threshold()
    }

    /// Balance at or above which the bucket counts as full.
    ///
    /// Refill is computed by integer division (`quota * dt / day`), so a week's
    /// idle time on a 2 GiB burst bucket can land a few dozen bytes short of
    /// capacity.  Treating that as "nearly empty" and throttling the app to a
    /// few MB/s for it would be absurd, so a bucket within 0.1 % of capacity is
    /// full.  The rounding-down error is always in the safe direction (never
    /// more allowance than intended).
    fn full_threshold(&self) -> i64 {
        let tol = (self.capacity / 1000) as i64;
        self.capacity as i64 - tol
    }

    pub fn in_debt(&self) -> bool {
        self.balance < 0
    }

    /// Instantaneous write-byte cap implied by the current balance.
    ///
    /// `None` means unlimited (bucket is full).  Otherwise
    /// `balance/TAU + refill`, floored at `floor_bps`.
    pub fn wbps(&self, q: &Quota, tau_secs: u64) -> Option<u64> {
        // An app whose allowance has been cut to zero is on the absolute
        // trickle, even if it still has banked balance: otherwise "cut off at
        // Red" would mean "may spend whatever it banked at full speed".
        if q.quota_bpd == 0 {
            return Some(q.effective_floor_bps());
        }
        if self.is_full() {
            return None;
        }
        let refill_bps = self.quota_bpd / SECS_PER_DAY;
        let tau = tau_secs.max(1);
        let floor = q.effective_floor_bps();
        if self.balance <= 0 {
            // In debt: trickle, but never zero.
            return Some(floor);
        }
        let release = (self.balance as u64) / tau;
        Some((release + refill_bps).max(floor))
    }

    /// IOPS cap.  Derived from the byte cap so that the two stay consistent: an
    /// app allowed `wbps` cannot exceed `wbps / 4 KiB` IOs/s, which stops a
    /// small-write storm from burning erase cycles through write amplification
    /// while staying under the byte budget.
    pub fn wiops(&self, q: &Quota, tau_secs: u64) -> Option<u64> {
        let wbps = self.wbps(q, tau_secs)?;
        Some((wbps / 4096).max(1).min(q.iops_cap))
    }

    pub fn cap(&self, q: &Quota, tau_secs: u64) -> Cap {
        match self.wbps(q, tau_secs) {
            None => Cap::UNLIMITED,
            Some(wbps) => Cap {
                wbps: Some(wbps),
                wiops: self.wiops(q, tau_secs),
            },
        }
    }

    /// Fraction of the bucket remaining, 0.0..=1.0 (debt reads as 0).
    pub fn level(&self) -> f64 {
        if self.capacity == 0 {
            return 0.0;
        }
        ((self.balance.max(0) as f64) / self.capacity as f64).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn fresh_bucket_is_unlimited() {
        let q = Quota::new(4 * GIB);
        let b = Bucket::new(&q, 0);
        assert!(b.is_full());
        assert!(b.cap(&q, DEFAULT_TAU_SECS).is_unlimited());
    }

    #[test]
    fn sustained_writer_converges_to_quota() {
        // Drain the bucket, then let it run for 30 days at 1 s ticks. Total
        // charged should be ~quota * 30 + initial burst.
        let q = Quota::new(100 << 20); // 100 MiB/day
        let mut b = Bucket::new(&q, 0);
        let tau = DEFAULT_TAU_SECS;

        // Simulate: each second, the app writes as fast as the cap allows.
        let mut total: u64 = 0;
        let start = 0i64;
        b.charge(q.burst_bytes, 0); // spend the initial burst
        for s in 1..=(SECS_PER_DAY * 30) {
            let now = start + (s as i64) * 1000;
            b.advance(now);
            let cap = b.wbps(&q, tau).unwrap();
            // App writes exactly the cap for one second.
            let wrote = cap.min(1 << 20);
            b.charge(wrote, now);
            total += wrote;
        }
        let expected = q.quota_bpd * 30;
        // Allow for the initial burst and the debt cap.
        assert!(
            total >= expected * 90 / 100 && total <= expected * 115 / 100,
            "total {total} vs expected {expected}"
        );
    }

    #[test]
    fn tick_length_does_not_change_totals() {
        // The same workload must be judged identically at a 1 s tick and a
        // 1 hour tick.  This is the property that keeps the governor honest
        // when the daemon is starved or the device sleeps.
        let q = Quota::new(200 << 20);
        let spend_per_day = 100u64 << 20;
        let mut a = Bucket::new(&q, 0);
        let mut c = Bucket::new(&q, 0);

        // 1 s ticks for one day
        let mut spent_a = 0u64;
        for s in 1..=SECS_PER_DAY {
            let want = spend_per_day / SECS_PER_DAY;
            a.advance_charge(s as i64 * 1000, want);
            spent_a += want;
        }
        // 1 day tick
        c.advance_charge(MS_PER_DAY, spend_per_day);

        // Both see the same daily spend against the same daily allowance. A
        // per-second integer division loses at most 1 byte per tick, so allow a
        // sub-MiB difference over a day; the point is that the totals agree
        // closely rather than that the coarse tick discards a day's allowance.
        let diff = a.balance.abs_diff(c.balance);
        assert!(diff < (2 << 20), "balances diverge across tick lengths: {} vs {}", a.balance, c.balance);
        assert!(spent_a.abs_diff(spend_per_day) < SECS_PER_DAY, "spend totals agree");
        assert_eq!(a.spent_today, c.spent_today);
    }

    #[test]
    fn advance_charge_does_not_discard_allowance_on_coarse_ticks() {
        // A legitimate 500 MiB/day app observed once a day must not be pushed
        // into debt by a full day's spending.
        let q = Quota::new(500 << 20);
        let mut b = Bucket::new(&q, 0);
        b.advance_charge(MS_PER_DAY, 500 << 20);
        assert!(!b.in_debt(), "balance went negative: {:?}", b.balance);
        // It should be at or near empty, not deeply negative.
        assert!(b.balance > -(64 << 20), "over-charged: {}", b.balance);
    }

    #[test]
    fn unlike_the_naive_order_this_keeps_the_budget() {
        // Demonstrate the bug the ordering fixes: refill-then-clip-then-charge
        // loses the whole day's allowance when the tick is a full day.
        let q = Quota::new(1 << 30);
        let mut naive = Bucket::new(&q, 0);
        naive.charge(q.burst_bytes, 0);
        naive.advance(MS_PER_DAY);
        naive.charge(q.quota_bpd, MS_PER_DAY); // a legitimate day's usage
        assert!(naive.in_debt(), "naive ordering starves the app: {}", naive.balance);

        let mut fixed = Bucket::new(&q, 0);
        fixed.advance_charge(MS_PER_DAY, q.quota_bpd);
        assert!(!fixed.in_debt(), "fixed ordering is fair: {}", fixed.balance);
    }

    #[test]
    fn burst_then_idle_is_not_throttled() {
        // A map-update-shaped workload: 2 GiB once a week, nothing otherwise.
        let q = Quota::new(2 * GIB / 7).with_burst(2 * GIB);
        let mut b = Bucket::new(&q, 0);
        let tau = DEFAULT_TAU_SECS;
        assert!(b.cap(&q, tau).is_unlimited(), "first update full speed");

        b.charge(2 * GIB, 0);
        // Spending exactly the bucket's worth leaves it empty (balance 0), not
        // in debt; the bucket is drained, not overdrawn.
        assert!(!b.is_full(), "2 GiB spent from a 2 GiB bucket empties it");
        assert!(b.balance <= 0, "bucket is empty after a full burst: {}", b.balance);

        // Idle for a week.
        b.advance(7 * MS_PER_DAY);
        assert!(
            b.cap(&q, tau).is_unlimited(),
            "after a week idle the next update is full speed again"
        );
    }

    #[test]
    fn debt_trickles_instead_of_blocking() {
        let q = Quota::new(10 << 20).with_floor(64 << 10);
        let mut b = Bucket::new(&q, 0);
        b.charge(100 << 20, 0); // 10x over
        let cap = b.wbps(&q, DEFAULT_TAU_SECS).unwrap();
        // The floor is capped at the app's own sustainable rate: it may not
        // keep writing 64 KiB/s when its allowance is only 10 MiB/day.
        assert_eq!(cap, (10 << 20) / SECS_PER_DAY, "throttled to its own rate");
        assert!(cap > 0, "never zero");
    }

    #[test]
    fn trickle_never_exceeds_the_apps_own_allowance() {
        // An untrusted app on 4 MiB/day: a fixed 16 KiB/s floor would let it
        // write 1.4 GiB/day, 350x its budget. The floor must track the
        // allowance, staying within a small bounded multiple of it.
        let q = Quota::new(4 << 20).with_floor(16 << 10);
        let floor = q.effective_floor_bps();
        let sustainable = (4 << 20) / SECS_PER_DAY;
        assert!(floor > 0, "never zero: a zero cap hangs the app");
        assert!(
            floor <= sustainable.max(MIN_TRICKLE_BPS),
            "floor {floor} exceeds the app's sustainable rate"
        );
        let mut b = Bucket::new(&q, 0);
        b.charge(64 << 20, 0);
        let cap = b.wbps(&q, DEFAULT_TAU_SECS).unwrap();
        assert_eq!(cap, floor);
        // Running at the floor for 30 days must not exceed the allowance.
        let monthly = cap as u128 * 30 * SECS_PER_DAY as u128;
        assert!(
            monthly <= (4u128 << 20) * 30,
            "trickle overspends the allowance: {monthly}"
        );
    }

    #[test]
    fn zero_allowance_still_progresses() {
        // At Red an untrusted app's allowance is cut to zero. The cap must be a
        // trickle, not a hang.
        let q = Quota::new(0).with_floor(16 << 10);
        assert_eq!(q.effective_floor_bps(), MIN_TRICKLE_BPS);
        const { assert!(MIN_TRICKLE_BPS > 0) };
        let mut b = Bucket::new(&q, 0);
        b.charge(1 << 20, 0);
        assert!(b.wbps(&q, DEFAULT_TAU_SECS).unwrap() > 0);
    }

    #[test]
    fn critical_keeps_a_real_floor() {
        // A critical app on a tiny allowance still sustains a non-zero rate,
        // which is what guarantees it is never completely blocked.
        let q = Quota::new(8 << 20).with_floor(16 << 10);
        let f = q.effective_floor_bps();
        assert_eq!(f, (8 << 20) / SECS_PER_DAY);
        assert!(f > 0, "critical apps must never be blocked outright");
    }

    #[test]
    fn charging_rolls_daily_counters() {
        let q = Quota::new(GIB);
        let mut b = Bucket::new(&q, 0);
        b.charge(1000, 0);
        assert_eq!(b.spent_today, 1000);
        b.advance(MS_PER_DAY + 5);
        assert_eq!(b.spent_today, 0);
        assert_eq!(b.day, 1);
    }

    #[test]
    fn iops_tracks_byte_cap() {
        let q = Quota::new(GIB).with_floor(0);
        let mut b = Bucket::new(&q, 0);
        b.charge(q.burst_bytes, 0);
        b.advance(1000);
        let wiops = b.wiops(&q, DEFAULT_TAU_SECS).unwrap();
        let wbps = b.wbps(&q, DEFAULT_TAU_SECS).unwrap();
        assert!(wiops <= (wbps / 4096).max(1));
    }
}
