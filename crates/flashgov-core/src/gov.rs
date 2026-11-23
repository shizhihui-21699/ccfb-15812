//! The decision engine.
//!
//! One `tick` is a pure function of (`Config`, `Governor` state, `TickInput`).
//! The daemon's job is only to feed it observations and apply the resulting
//! caps; all the reasoning lives here so that it can be simulated over years of
//! device life in milliseconds.
//!
//! # The seven problems this has to solve
//!
//! 1. **A daily allowance must become an instantaneous cap** that `io.max` can
//!    enforce, without breaking bursty-but-legitimate workloads.  → [`budget`].
//! 2. **Attribution across system services.**  A cgroup is inherited by every
//!    process a sandbox spawns and cannot be escaped by `exec`, so an app
//!    writing through a shared directory is attributed correctly for free.  The
//!    remaining hole is *delegation*: app X asks the download manager to fetch a
//!    file, and the download manager writes it.  Those bytes are charged to
//!    whoever the mediator reports as sponsor, and anything unreported is capped
//!    on the mediator's own aggregate.  → [`Governor::charge_sponsored`].
//! 3. **The global ceiling must follow the device's actual wear**, not a
//!    datasheet.  → [`crate::wear::WearState::sustainable_bytes_per_day`].
//! 4. **Critical functions must survive at end of life.**  → [`Class::Critical`]
//!    and a reserve that non-critical classes cannot touch.
//! 5. **Throttling must degrade, never hang.**  Every throttle bottoms out at a
//!    non-zero trickle.  → [`crate::budget::Quota::floor_bps`].
//! 6. **The governor must not flap.**  Caps are only re-pushed when they move by
//!    more than a configured percentage.
//! 7. **The governor must not become the writer.**  It keeps no log on flash and
//!    persists a fixed-size image rarely (see `snapshot`).

use crate::budget::{default_burst, Bucket, Cap, Class, Quota, MIN_BURST_BYTES};
use crate::config::{AppClass, Config};
use crate::units::{clamp_u64, fmt_bytes, fmt_bpd, mul_div, MS_PER_DAY};
use crate::wear::{Stage, StageThresholds, WearSample, WearState};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Counters for one cgroup since the previous tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Counter {
    pub wbytes: u64,
    pub wios: u64,
}

/// A byte count a mediator (download manager, package installer, media
/// scanner…) reports as having been written *on behalf of* a sponsor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsoredCharge {
    /// Mediator name as configured in `mediators`.
    pub mediator: String,
    /// Sponsoring app's package name, as configured in `apps`.
    pub package: String,
    pub bytes: u64,
}

/// Everything the engine learns between two ticks.
#[derive(Debug, Clone, Default)]
pub struct TickInput {
    /// Monotonic milliseconds.  Monotonic is what makes the accounting robust
    /// to clock jumps; the daemon converts `CLOCK_MONOTONIC` for us.
    pub now_ms: i64,
    /// Local wall-clock hour, 0..=23, for the maintenance window.
    pub local_hour: u8,
    /// Per-cgroup write counters since the last tick, keyed by cgroup path.
    pub cgroup_writes: BTreeMap<String, Counter>,
    /// Total device write bytes observed since the last tick (all cgroups plus
    /// anything the kernel attributes elsewhere).  Used to detect a widening
    /// attribution gap: unexplained growth here is the early warning that a new
    /// shared writer has appeared.
    pub device_write_bytes: Option<u64>,
    /// Delegated writes reported by mediators.
    pub sponsored: Vec<SponsoredCharge>,
    /// Device wear sample, if one was due this tick.
    pub wear: Option<WearSample>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub package: String,
    pub cgroup: String,
    pub class: Class,
    /// Cap to install.  `Cap::UNLIMITED` means "no `io.max` entry".
    pub cap: Cap,
    /// Whether the cap differs materially from what was last pushed.
    pub changed: bool,
    /// True when the app is not running at full speed.
    pub throttled: bool,
    /// Allocated sustained allowance for this tick.
    pub quota_bpd: u64,
    /// Burst capacity: how much the app may spend at full speed from its
    /// banked allowance before the cap bites.
    pub burst_bytes: u64,
    /// Human-readable short explanation, for the UI / logs.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// An app is sustainedly over budget.
    QuotaExceeded,
    /// A delegating service wrote bytes nobody claimed.
    UnattributedMediator,
    /// The attribution gap between per-cgroup accounting and the device total
    /// grew past the sanity threshold.
    AttributionGap,
    /// Wear crossed a stage threshold.
    StageChanged,
    /// Device life is below the configured service target.
    ServiceLifeAtRisk,
    /// An app was frozen to protect the device.
    Frozen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub kind: AlertKind,
    pub subject: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    pub charged_bytes: u64,
    pub sponsored_bytes: u64,
    pub charged_today: u64,
    pub unaccounted_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct TickOutput {
    pub stage: Stage,
    /// Whole-system sustainable rate derived from measured wear.
    pub ceiling_bpd: u64,
    /// Part of `ceiling_bpd` that only critical functions may use.
    pub critical_reserve_bpd: u64,
    pub decisions: Vec<Decision>,
    pub alerts: Vec<Alert>,
    pub totals: Totals,
}

struct AppState {
    package: String,
    cgroup: String,
    class: Class,
    safety_of_life: bool,
    base: Quota,
    bucket: Bucket,
    /// Cap most recently handed to (or accepted by) the kernel.
    pushed: Cap,
    /// Bytes written today per the kernel counters.
    observed_today: u64,
    day: i64,
    frozen: bool,
    over_budget_ticks: u32,
    notified: bool,
}

impl AppState {
    /// Quota framed around the app's *current* allowance, with the burst
    /// re-clamped so it never exceeds four days of allowance.  This is what
    /// turns an adapted daily allowance into a usable instantaneous cap.
    fn effective_quota(&self) -> Quota {
        let mut q = self.base;
        // Preserve a zero allowance exactly: a cut-off app must be able to
        // reach the absolute trickle path, not be floored back to 1 byte/day.
        q.quota_bpd = self.bucket.quota_bpd;
        q.burst_bytes = q
            .burst_bytes
            .min(self.bucket.quota_bpd.saturating_mul(4).max(MIN_BURST_BYTES))
            .max(MIN_BURST_BYTES);
        q
    }
}

struct MediatorState {
    name: String,
    cgroup: String,
    bucket: Bucket,
    quota_bpd: u64,
    single_tenant: bool,
    sponsor_guess: Option<String>,
    unattributed_today: u64,
}

pub struct Governor {
    cfg: Config,
    apps: Vec<AppState>,
    app_index: BTreeMap<String, usize>,
    mediators: Vec<MediatorState>,
    mediator_index: BTreeMap<String, usize>,
    wear: WearState,
    stage: Stage,
    first_boot_ms: i64,
    last_tick_ms: i64,
    /// Bytes/day actually available to non-critical apps, after reserve.
    noncritical_pool_bpd: u64,
    /// Rolling estimate of the attribution gap, in bytes/day.
    gap_bpd_ema: u64,
    gap_last_sample_ms: i64,
}

/// Weight of a class when the global pool has to be divided up.  Essential
/// workloads (maps, dashcam) get first claim on capacity; untrusted apps get the
/// crumbs by construction, so they cannot starve a legitimate one.
fn class_weight(c: Class) -> u64 {
    match c {
        Class::Critical => 0, // sized separately from the reserve
        Class::Essential => 16,
        Class::Normal => 4,
        Class::Untrusted => 1,
    }
}

/// Water-filling allocator: divide `available` among classes in proportion to
/// `weight`, capping each class at its demand and redistributing the surplus.
/// Deterministic and exact in integer arithmetic.
pub fn waterfill(demands: &[(Class, u64)], available: u64) -> BTreeMap<Class, u64> {
    let mut out: BTreeMap<Class, u64> = BTreeMap::new();
    let mut left = available;

    // A short fixed-point loop converges because at least one class is either
    // satisfied or receives all of `left` each round.
    for _ in 0..demands.len() + 1 {
        let active: Vec<&(Class, u64)> = demands
            .iter()
            .filter(|(c, d)| *d > 0 && out.get(c).copied().unwrap_or(0) < *d)
            .collect();
        if active.is_empty() || left == 0 {
            break;
        }
        let total_w: u64 = active.iter().map(|(c, _)| class_weight(*c)).sum();
        if total_w == 0 {
            break;
        }
        let mut progressed = false;
        for (c, d) in active {
            let already = out.get(c).copied().unwrap_or(0);
            let room = d - already;
            let share = mul_div(left, class_weight(*c), total_w);
            let grant = share.min(room);
            if grant > 0 {
                out.insert(*c, already + grant);
                left -= grant;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    for (c, _) in demands {
        out.entry(*c).or_insert(0);
    }
    out
}

impl Governor {
    pub fn new(cfg: Config, now_ms: i64) -> Self {
        let first_boot = cfg.device.first_boot_ms.unwrap_or(now_ms);
        let floor = cfg.policy.floor_bps;
        let tau = cfg.policy.burst_tau_secs;

        let mut apps = Vec::with_capacity(cfg.apps.len());
        let mut app_index = BTreeMap::new();
        for (pkg, a) in &cfg.apps {
            let base = a.to_quota(floor, tau);
            app_index.insert(pkg.clone(), apps.len());
            apps.push(AppState {
                package: a.package.clone(),
                cgroup: a.cgroup.clone(),
                class: a.class.into(),
                safety_of_life: a.safety_of_life || a.class == AppClass::Critical,
                base,
                bucket: Bucket::new(&base, now_ms),
                pushed: Cap::UNLIMITED,
                observed_today: 0,
                day: crate::units::day_index(now_ms),
                frozen: false,
                over_budget_ticks: 0,
                notified: false,
            });
        }

        let mut mediators = Vec::with_capacity(cfg.mediators.len());
        let mut mediator_index = BTreeMap::new();
        for (name, m) in &cfg.mediators {
            let q = Quota::new(m.quota_bpd).with_burst(default_burst(m.quota_bpd));
            mediator_index.insert(name.clone(), mediators.len());
            mediators.push(MediatorState {
                name: name.clone(),
                cgroup: m.cgroup.clone(),
                bucket: Bucket::new(&q, now_ms),
                quota_bpd: m.quota_bpd,
                single_tenant: m.single_tenant,
                sponsor_guess: m.sponsor_guess.clone(),
                unattributed_today: 0,
            });
        }

        let mut g = Governor {
            wear: WearState::new(cfg.device.tbw_bytes(), first_boot),
            cfg,
            apps,
            app_index,
            mediators,
            mediator_index,
            stage: Stage::Green,
            first_boot_ms: first_boot,
            last_tick_ms: now_ms,
            noncritical_pool_bpd: 0,
            gap_bpd_ema: 0,
            gap_last_sample_ms: now_ms,
        };
        let c0 = g.ceiling_bpd(now_ms);
        g.noncritical_pool_bpd = c0.saturating_sub(g.reserve_bpd(c0));
        g
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn wear(&self) -> &WearState {
        &self.wear
    }

    pub fn stage(&self) -> Stage {
        self.stage
    }

    /// Apply a wear sample immediately (also done during `tick`).  Exposed so
    /// the daemon can ratchet wear as soon as the sampler reads EXT_CSD, before
    /// the next policy tick.
    pub fn observe_wear(&mut self, sample: WearSample, bytes_since_last: u64, now_ms: i64) {
        let before = self.stage;
        self.wear.observe(sample, bytes_since_last);
        self.stage = self.wear.stage(&self.cfg.policy.stages, before);
        let _ = now_ms;
    }

    pub fn first_boot_ms(&self) -> i64 {
        self.first_boot_ms
    }

    pub fn set_first_boot_ms(&mut self, ms: i64) {
        self.first_boot_ms = ms;
        self.wear.window_start_ms = ms;
    }

    /// Restore wear state from a persisted image.  Called once at boot before
    /// the first EXT_CSD sample: it seeds the ratchet so that a device whose
    /// EXT_CSD is briefly unreadable does not appear brand-new.
    pub fn wear_mut_for_restore(&mut self, life_permille: u16, pre_eol: crate::wear::PreEol) {
        self.wear.set_wear_floor(life_permille, pre_eol);
        let before = self.stage;
        self.stage = self.wear.stage(&self.cfg.policy.stages, before);
    }

    /// Produce a persistable image of the current state.
    pub fn snapshot(&self, wall_ms: i64) -> crate::snapshot::Image {
        use crate::snapshot::{Image, PersistedApp};
        Image {
            generation: 0, // the store assigns the real generation
            saved_at_ms: wall_ms,
            first_boot_ms: self.first_boot_ms,
            life_permille: self.wear.life_permille,
            pre_eol: match self.wear.pre_eol {
                crate::wear::PreEol::Unknown => 0,
                crate::wear::PreEol::Normal => 1,
                crate::wear::PreEol::Warning => 2,
                crate::wear::PreEol::Urgent => 3,
            },
            lifetime_host_bytes: self.wear.lifetime_host_bytes,
            configured_tbw_bytes: self.wear.configured_tbw_bytes,
            stage: self.stage as u8,
            apps: self
                .apps
                .iter()
                .map(|a| PersistedApp {
                    package: a.package.clone(),
                    lifetime_bytes: a.bucket.lifetime,
                    spent_today: a.bucket.spent_today,
                    balance: a.bucket.balance,
                    day: a.bucket.day,
                    frozen: a.frozen,
                })
                .collect(),
        }
    }

    /// Each app's (package, cgroup) pair, for the kernel backend to set up.
    pub fn app_targets(&self) -> impl Iterator<Item = (&str, &str, Cap)> {
        self.apps
            .iter()
            .map(|a| (a.package.as_str(), a.cgroup.as_str(), a.pushed))
    }

    /// Each app's current freeze state, for the cgroup freezer.  Returning the
    /// state for *every* app (not just the changed ones) lets the daemon
    /// reconcile the kernel toward the policy without tracking diffs itself.
    pub fn freeze_targets(&self) -> impl Iterator<Item = (&str, &str, bool)> {
        self.apps
            .iter()
            .map(|a| (a.package.as_str(), a.cgroup.as_str(), a.frozen))
    }

    /// The set of cgroups the daemon should ensure exist and have the io
    /// controller.  Used at startup to warn early rather than mid-run.
    pub fn all_cgroups(&self) -> Vec<String> {
        let mut v: Vec<String> = self.apps.iter().map(|a| a.cgroup.clone()).collect();
        v.extend(self.mediators.iter().map(|m| m.cgroup.clone()));
        v.sort();
        v.dedup();
        v
    }

    pub fn mediator_targets(&self) -> impl Iterator<Item = (&str, &str)> {
        self.mediators
            .iter()
            .map(|m| (m.name.as_str(), m.cgroup.as_str()))
    }

    /// Caps for the mediators' own cgroups, and their current allowance.
    ///
    /// A mediator is capped on its aggregate, not per sponsor: it exists to
    /// serve several apps, so its own bucket is replenished at `quota_bpd` and
    /// anything it writes without a tagged sponsor draws on that.  The cap is
    /// what stops a rogue app from using the mediator as a laundromat: it can
    /// at most exhaust the mediator, which the mediator's own budget bounds.
    pub fn mediator_caps(&self) -> impl Iterator<Item = (&str, &str, u64, Cap)> {
        self.mediators.iter().map(|m| {
            let cap = m.bucket.cap(
                &Quota::new(m.quota_bpd).with_burst(default_burst(m.quota_bpd)),
                self.cfg.policy.burst_tau_secs,
            );
            (m.name.as_str(), m.cgroup.as_str(), m.quota_bpd, cap)
        })
    }

    /// Days of service life left according to the clock, floored at 30 so that
    /// a unit past its nominal life does not get an unbounded daily ceiling.
    fn remaining_service_days(&self, now_ms: i64) -> u64 {
        let elapsed = ((now_ms - self.first_boot_ms).max(0) as u64) / MS_PER_DAY as u64;
        self.cfg
            .device
            .service_days()
            .saturating_sub(elapsed)
            .max(30)
    }

    /// Fraction of the planned service life that has already elapsed, in
    /// permille.  Used to tell "wearing on schedule" from "wearing too fast".
    fn elapsed_permille(&self, now_ms: i64) -> u16 {
        let total = self.cfg.device.service_days().max(1);
        let elapsed = ((now_ms - self.first_boot_ms).max(0) as u64) / MS_PER_DAY as u64;
        ((elapsed.min(total) * 1000) / total) as u16
    }

    /// How far ahead of schedule the device is wearing, in permille of total
    /// endurance (positive = too fast).
    ///
    /// This is the honest trigger for *rate* pressure.  Absolute wear percentage
    /// cannot be: a fleet writing exactly at its sustainable rate is on plan at
    /// 60 % consumed after 60 % of its service life, and throttling it there
    /// punishes compliant users.  Wear that races ahead of the calendar is the
    /// real danger, and it is visible years before the absolute percentage
    /// becomes alarming.
    fn pace_overrun_permille(&self, now_ms: i64) -> i32 {
        self.wear
            .pace_overrun_permille(self.elapsed_permille(now_ms))
    }

    /// The whole-system sustainable write rate, in bytes/day.
    fn ceiling_bpd(&self, now_ms: i64) -> u64 {
        let days = self.remaining_service_days(now_ms);
        let measured = self.wear.sustainable_bytes_per_day(days);
        // Never exceed the datasheet-derived plan: measured wear can look
        // better than reality early on because the occasional bucket step is
        // coarse.
        measured.min(self.cfg.nominal_ceiling_bpd())
    }

    /// Part of the ceiling held back for critical functions.
    ///
    /// This is a share of the *actual* ceiling, not the datasheet one.  Using
    /// the nominal figure was a real bug: on a worn device the true ceiling
    /// shrinks to a fraction of the datasheet rate, and a reserve sized off the
    /// datasheet would then exceed the entire budget, starving every non-critical
    /// app to nothing while reserving room nobody could use.
    fn reserve_bpd(&self, ceiling: u64) -> u64 {
        mul_div(ceiling, self.cfg.policy.critical_reserve_pct, 100)
    }

    /// Charge delegated bytes to the sponsoring app.  Called whenever a
    /// mediator reports; safe to call many times per tick.
    pub fn charge_sponsored(&mut self, charge: &SponsoredCharge, now_ms: i64) {
        if let Some(mi) = self.mediator_index.get(&charge.mediator).copied() {
            self.mediators[mi]
                .bucket
                .charge(charge.bytes, now_ms);
            self.mediators[mi].unattributed_today = self.mediators[mi]
                .unattributed_today
                .saturating_add(charge.bytes);
        }
        if let Some(ai) = self.app_index.get(&charge.package).copied() {
            let tau = self.cfg.policy.burst_tau_secs;
            let q = self.quota_for(ai);
            self.apps[ai].bucket.advance(now_ms);
            self.apps[ai].bucket.charge(charge.bytes, now_ms);
            // Re-derive the cap immediately: a delegated 3 GiB download must
            // tighten the sponsor's cap now, not at the next tick.
            let cap = self.apps[ai].bucket.cap(&q, tau);
            self.apps[ai].pushed = cap;
            self.apps[ai].observed_today = self.apps[ai]
                .observed_today
                .saturating_add(charge.bytes);
        }
    }

    /// Burst capacity for an app.
    ///
    /// Burst is the size of an indivisible write the app is allowed to land at
    /// full speed.  It is derived from the app's *configured* (base) allowance,
    /// never from the per-tick allocated quota, so a contended pool cannot make
    /// a map delta impossible.
    ///
    /// Burst is scaled only by the *hard* safety stage, not by rate pressure:
    /// when budgets are being trimmed because of pace, a legitimate update
    /// should still be able to land, just less often.  Only when the flash is
    /// genuinely near failure (Orange / Red) does burst shrink — and even then
    /// an essential app keeps a floor big enough for the largest routine map
    /// update, because a head unit with stale maps is a different kind of
    /// broken.
    fn burst_for(&self, ai: usize, stage: Stage) -> u64 {
        let a = &self.apps[ai];
        let configured = a.base.burst_bytes.max(MIN_BURST_BYTES);
        match (a.class, stage) {
            (Class::Critical, _) => configured.max(4 << 20),
            (_, Stage::Green) | (_, Stage::Amber) => configured,
            (Class::Essential, Stage::Orange) => (configured / 2).max(1 << 30),
            (Class::Essential, Stage::Red) => (configured / 4).max(512 << 20),
            (_, Stage::Orange) => (configured / 2).max(MIN_BURST_BYTES),
            (_, Stage::Red) => (configured / 4).max(MIN_BURST_BYTES),
        }
    }

    fn quota_for(&self, ai: usize) -> Quota {
        self.apps[ai].effective_quota()
    }

    /// Run one policy tick.
    pub fn tick(&mut self, input: TickInput) -> TickOutput {
        let now = input.now_ms.max(self.last_tick_ms);
        let mut alerts = Vec::new();

        // ---- 1. Attribute this tick's bytes ------------------------------
        let mut observed: BTreeMap<String, u64> = BTreeMap::new();
        let mut observed_ios: BTreeMap<String, u64> = BTreeMap::new();
        for (cg, c) in &input.cgroup_writes {
            *observed.entry(cg.clone()).or_default() += c.wbytes;
            *observed_ios.entry(cg.clone()).or_default() += c.wios;
        }

        // Sponsored charges may arrive as part of the same batch.
        let mut sponsored_by_app: BTreeMap<String, u64> = BTreeMap::new();
        for s in &input.sponsored {
            *sponsored_by_app.entry(s.package.clone()).or_default() += s.bytes;
        }

        let mut charged_bytes = 0u64;
        let mut sponsored_bytes = 0u64;

        // ---- 2. Advance and charge app buckets ---------------------------
        let tau = self.cfg.policy.burst_tau_secs;
        let today = crate::units::day_index(now);
        for ai in 0..self.apps.len() {
            let cg = self.apps[ai].cgroup.clone();
            let raw = observed.get(&cg).copied().unwrap_or(0);
            let spon = sponsored_by_app
                .get(&self.apps[ai].package)
                .copied()
                .unwrap_or(0);
            let bytes = raw.saturating_add(spon);
            let a = &mut self.apps[ai];
            a.bucket.advance(now);
            a.bucket.charge(bytes, now);
            if a.day != today {
                a.day = today;
                a.observed_today = 0;
                a.over_budget_ticks = 0;
                a.notified = false;
            }
            a.observed_today = a.observed_today.saturating_add(bytes);
            charged_bytes += raw;
            sponsored_bytes += spon;
        }

        // ---- 3. Mediators: charge what nobody claimed ---------------------
        for mi in 0..self.mediators.len() {
            let cg = self.mediators[mi].cgroup.clone();
            let raw = observed.get(&cg).copied().unwrap_or(0);
            // Bytes that an app cgroup nested under the mediator already
            // accounted for must not be charged twice.
            let nested: u64 = self
                .apps
                .iter()
                .filter(|a| is_nested_under(&a.cgroup, &cg))
                .map(|a| observed.get(&a.cgroup).copied().unwrap_or(0))
                .sum();
            let own = raw.saturating_sub(nested);
            let claimed: u64 = input
                .sponsored
                .iter()
                .filter(|s| s.mediator == self.mediators[mi].name)
                .map(|s| s.bytes)
                .sum();
            let unattributed = own.saturating_sub(claimed);
            let m = &mut self.mediators[mi];
            m.bucket.advance(now);
            if unattributed > 0 {
                m.bucket.charge(unattributed, now);
                m.unattributed_today = m.unattributed_today.saturating_add(unattributed);
                charged_bytes += unattributed;
                if m.single_tenant {
                    if let Some(guess) = m.sponsor_guess.clone() {
                        let (idx, bytes) = (self.mediator_index[&m.name], unattributed);
                        let _ = idx;
                        if let Some(ai) = self.app_index.get(&guess).copied() {
                            let a = &mut self.apps[ai];
                            a.bucket.charge(bytes, now);
                            a.observed_today = a.observed_today.saturating_add(bytes);
                            sponsored_bytes += bytes;
                            alerts.push(Alert {
                                kind: AlertKind::UnattributedMediator,
                                subject: self.mediators[mi].name.clone(),
                                message: format!(
                                    "mediator wrote {} nobody claimed; charged to sole tenant {}",
                                    fmt_bytes(bytes),
                                    guess
                                ),
                            });
                        }
                    }
                } else if unattributed > (16 << 20) {
                    alerts.push(Alert {
                        kind: AlertKind::UnattributedMediator,
                        subject: self.mediators[mi].name.clone(),
                        message: format!(
                            "{} written through the mediator with no sponsor tag; \
                             install the attribution hook or a rogue app can launder writes",
                            fmt_bytes(unattributed)
                        ),
                    });
                }
            }
        }

        // ---- 4. Wear + stage ---------------------------------------------
        let stage_before = self.stage;
        if let Some(sample) = input.wear {
            self.wear.observe(sample, 0);
        }
        self.stage = self.wear.stage(&self.cfg.policy.stages, stage_before);
        if self.stage != stage_before {
            alerts.push(Alert {
                kind: AlertKind::StageChanged,
                subject: "device".into(),
                message: format!(
                    "wear stage {} -> {} (life {:.1}% consumed, pre-eol {})",
                    stage_before.as_str(),
                    self.stage.as_str(),
                    self.wear.wear_fraction() * 100.0,
                    self.wear.pre_eol.as_str()
                ),
            });
        }

        // ---- 5. Attribution gap ------------------------------------------
        let mut totals = Totals {
            charged_bytes,
            sponsored_bytes,
            charged_today: self.apps.iter().map(|a| a.observed_today).sum(),
            unaccounted_bytes: 0,
        };
        if let Some(total) = input.device_write_bytes {
            let gap = total.saturating_sub(charged_bytes);
            totals.unaccounted_bytes = gap;
            let dt = (now - self.gap_last_sample_ms).max(1) as u64;
            let inst_bpd = mul_div(gap, MS_PER_DAY as u64, dt);
            self.gap_bpd_ema = (self.gap_bpd_ema * 3 + inst_bpd) / 4;
            self.gap_last_sample_ms = now;
            // OS overhead is real (journal, fs metadata, page cache churn); only
            // complain when the gap dwarfs every configured app combined.
            let app_total: u64 = self.apps.iter().map(|a| a.base.quota_bpd).sum();
            if self.gap_bpd_ema > app_total.saturating_mul(2).max(8 << 30) {
                alerts.push(Alert {
                    kind: AlertKind::AttributionGap,
                    subject: "device".into(),
                    message: format!(
                        "writes reach the flash without a cgroup we manage (~{}); \
                         a new shared writer exists and attribution is incomplete",
                        fmt_bpd(self.gap_bpd_ema)
                    ),
                });
            }
        }

        // ---- 6. Compute this tick's allowance plan -----------------------
        //
        // Two separate numbers are produced per app, and conflating them is the
        // classic way a write limiter breaks real workloads:
        //
        // * **Sustained allowance** (`quota_bpd`) — the refill rate.  This is
        //   what the water-filling allocator divides up when the device cannot
        //   afford everything, and what rate pressure turns down when the wear
        //   is running ahead of the service-life plan.
        // * **Burst capacity** (`burst_bytes`) — how much may be spent at full
        //   speed from banked allowance right now.  This must stay large
        //   through Amber and Orange: a 2 GiB map delta is one indivisible lump
        //   and must not be dribbled out as if it were a page write.
        //
        // Rate pressure is driven by *pace*, not by the absolute wear
        // percentage.  See `pace_overrun_permille`: a device on schedule is not
        // punished, and the *hard* protections (freezing, floors) still key off
        // the absolute stage at the very end of life.
        let ceiling = self.ceiling_bpd(now);
        let reserve = self.reserve_bpd(ceiling);
        let pool = ceiling.saturating_sub(reserve);
        self.noncritical_pool_bpd = pool;

        let window_open = self.cfg.policy.maintenance_window.contains(input.local_hour);
        let mult = if window_open {
            self.cfg.policy.maintenance_window.multiplier.max(1)
        } else {
            1
        };

        // Rate pressure factors, in eighths.  Derived from how far the wear is
        // ahead of schedule, not from the raw wear level.
        let overrun = self.pace_overrun_permille(now);
        let (ess_factor, norm_factor, unt_factor) = pace_factors(overrun);
        let ess_pressure = if window_open {
            ess_factor.saturating_mul(mult)
        } else {
            ess_factor
        };
        let mut demand: BTreeMap<Class, u64> = BTreeMap::new();
        for a in &self.apps {
            let f = match a.class {
                Class::Critical => continue,
                Class::Essential => ess_pressure,
                Class::Normal => norm_factor,
                Class::Untrusted => unt_factor,
            };
            let d = mul_div(a.base.quota_bpd, f, 8);
            *demand.entry(a.class).or_default() += d;
        }
        let demands: Vec<(Class, u64)> = demand.iter().map(|(c, d)| (*c, *d)).collect();
        let alloc = waterfill(&demands, pool);

        // ---- 7. Per-app quotas and caps ----------------------------------
        let stage = self.stage;
        let freeze_at_red = self.cfg.policy.freeze_untrusted_at_red();
        let red_pct = self.cfg.policy.stages.red / 10;
        let dry_run = self.cfg.policy.dry_run;
        let min_normal = self.cfg.policy.min_normal_bpd;
        let hard_cap = self.cfg.policy.app_hard_cap_bpd;

        let mut decisions = Vec::with_capacity(self.apps.len());
        for ai in 0..self.apps.len() {
            let base_bpd = self.apps[ai].base.quota_bpd;
            let class = self.apps[ai].class;

            // Sustained allowance.
            let quota = if class == Class::Critical {
                // Critical apps are never scaled by the pool: the reserve exists
                // precisely so their allowance is untouched.
                base_bpd
            } else {
                let pressure = match class {
                    Class::Essential => ess_pressure,
                    Class::Normal => norm_factor,
                    Class::Untrusted => unt_factor,
                    Class::Critical => 8,
                };
                let want = mul_div(base_bpd, pressure, 8);
                let class_demand = *demand.get(&class).unwrap_or(&0);
                let class_alloc = alloc.get(&class).copied().unwrap_or(0);
                let scaled = if class_demand == 0 || class_alloc >= class_demand {
                    want
                } else {
                    mul_div(want, class_alloc, class_demand)
                };
                if class >= Class::Normal {
                    scaled.max(min_normal.min(want))
                } else {
                    scaled
                }
                .min(hard_cap)
            };
            // At Red, untrusted apps lose their allowance entirely and live on
            // the trickle floor.
            let quota = if stage == Stage::Red && class == Class::Untrusted {
                0
            } else {
                quota
            };

            // Burst capacity: driven by the *base* allowance and the stage, not
            // by the possibly-starved per-tick quota, so a map delta stays
            // possible even when the pool is contended.
            let burst = self.burst_for(ai, stage);

            let a = &mut self.apps[ai];
            a.bucket.quota_bpd = quota;
            a.bucket.resize(burst);
            let q = a.effective_quota();
            let mut cap = a.bucket.cap(&q, tau);

            // Red: freeze untrusted background apps outright if configured.
            // Never freeze a safety-of-life app, whatever its class.
            let should_freeze =
                stage == Stage::Red && class == Class::Untrusted && !a.safety_of_life && freeze_at_red;
            if should_freeze && !a.frozen {
                a.frozen = true;
                alerts.push(Alert {
                    kind: AlertKind::Frozen,
                    subject: a.package.clone(),
                    message: format!(
                        "{} frozen: device below {}% life, untrusted app must not write",
                        a.package, red_pct
                    ),
                });
            } else if !should_freeze && a.frozen {
                a.frozen = false;
            }
            if a.frozen {
                cap = Cap::from_bps(q.floor_bps, 1);
            }

            // Over-budget detection, for alerts only: a bucket in debt after a
            // full day means the app is spending beyond its allowance.
            if a.bucket.in_debt() {
                a.over_budget_ticks = a.over_budget_ticks.saturating_add(1);
            } else {
                a.over_budget_ticks = 0;
            }

            let changed = cap_differs_materially(&a.pushed, &cap, self.cfg.policy.cap_hysteresis_pct);
            let throttled = cap
                .wbps
                .map(|w| w < a.base.quota_bpd / 86_400 * 2 + q.floor_bps)
                .unwrap_or(false)
                || a.bucket.in_debt();

            if changed && !dry_run {
                a.pushed = cap;
            }

            let reason = if a.frozen {
                "frozen at end-of-life".to_string()
            } else if a.bucket.in_debt() {
                format!(
                    "over budget by {}; repaying at {}",
                    fmt_bytes((-a.bucket.balance).max(0) as u64),
                    fmt_bytes(q.floor_bps)
                )
            } else if cap.is_unlimited() {
                "within allowance".to_string()
            } else if stage >= Stage::Orange && class != Class::Critical {
                format!("degraded mode ({}): app budget reduced", stage.as_str())
            } else {
                format!("throttled to {}", crate::units::fmt_rate(cap.wbps.unwrap_or(0)))
            };
            decisions.push(Decision {
                package: a.package.clone(),
                cgroup: a.cgroup.clone(),
                class,
                cap,
                changed,
                throttled,
                quota_bpd: quota,
                burst_bytes: burst,
                reason,
            });
        }

        // ---- 8. Alerts that need the day's totals -------------------------
        for (ai, d) in decisions.iter().enumerate() {
            let base_bpd = self.apps[ai].base.quota_bpd;
            let observed_today = self.apps[ai].observed_today;
            if observed_today > base_bpd.saturating_mul(3) && observed_today > 8 << 20 && !self.apps[ai].notified
            {
                self.apps[ai].notified = true;
                alerts.push(Alert {
                    kind: AlertKind::QuotaExceeded,
                    subject: d.package.clone(),
                    message: format!(
                        "{} wrote {} today against a {} allowance",
                        d.package,
                        fmt_bytes(observed_today),
                        fmt_bpd(base_bpd)
                    ),
                });
            }
        }
        if self.stage >= Stage::Orange && self.wear.days_to_eol(self.ceiling_bpd(now)) < 365 {
            alerts.push(Alert {
                kind: AlertKind::ServiceLifeAtRisk,
                subject: "device".into(),
                message: format!(
                    "at the current ceiling the device reaches end-of-life in {:.0} days",
                    self.wear.days_to_eol(self.ceiling_bpd(now))
                ),
            });
        }

        self.last_tick_ms = now;

        TickOutput {
            stage: self.stage,
            ceiling_bpd: ceiling,
            critical_reserve_bpd: reserve,
            decisions,
            alerts,
            totals,
        }
    }
}

/// Pace → rate-pressure factors, in eighths.  `8` means "no reduction".
///
/// `overrun` is how far consumed life is ahead of elapsed service life, in
/// permille.  A device on schedule (`overrun <= 0`) is never rate-pressured: it
/// is doing exactly what the plan allows.  Only when wear races ahead of the
/// calendar do budgets come down, and they come down gradually so a transient
/// heavy period (a big OTA, a month of long drives) does not immediately
/// cripple the head unit.  A *huge* overrun means something is badly wrong and
/// essentials are cut hard.
///
/// The hard protections (freezing untrusted apps, refusing all non-critical
/// writes) do **not** live here: they key off the absolute [`Stage`], because
/// they exist for the moment the flash is genuinely about to fail, not for a
/// budgeting trend.
fn pace_factors(overrun: i32) -> (u64, u64, u64) {
    // (essential, normal, untrusted) in eighths.
    match overrun {
        i32::MIN..=100 => (8, 8, 8),     // on plan or up to 10 pt ahead
        101..=200 => (8, 6, 6),          // 10–20 pt ahead: trim ordinary apps
        201..=350 => (6, 3, 1),          // 20–35 pt ahead: essentials feel it
        351..=500 => (4, 1, 1),          // 35–50 pt ahead: serious
        _ => (2, 1, 1),                  // > 50 pt ahead: cut essentials too
    }
}

/// True when `child` lies inside `parent`'s subtree (strictly below it).
fn is_nested_under(child: &str, parent: &str) -> bool {
    let p = parent.trim_end_matches('/');
    child.len() > p.len() && child.starts_with(p) && child[p.len()..].starts_with('/')
}

fn cap_differs_materially(old: &Cap, new: &Cap, hysteresis_pct: u64) -> bool {
    if old.is_unlimited() != new.is_unlimited() {
        return true;
    }
    let rel = |a: Option<u64>, b: Option<u64>| -> bool {
        match (a, b) {
            (None, None) => false,
            (Some(_), None) | (None, Some(_)) => true,
            (Some(x), Some(y)) => {
                let (lo, hi) = if x < y { (x, y) } else { (y, x) };
                if lo == 0 {
                    return hi > 0;
                }
                let delta = hi - lo;
                delta.saturating_mul(100) > lo.saturating_mul(hysteresis_pct)
            }
        }
    };
    rel(old.wbps, new.wbps) || rel(old.wiops, new.wiops)
}

/// Guess the stage thresholds in use, for reporting.
pub fn thresholds(cfg: &Config) -> StageThresholds {
    cfg.policy.stages
}

/// Bytes still owed to the device by this tick's plan.  Exposed for the
/// simulator/report tooling.
pub fn headroom(ceiling: u64, allocated: u64) -> u64 {
    clamp_u64(ceiling.saturating_sub(allocated), 0, u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn cfg() -> Config {
        serde_json::from_str(
            r#"{
              "version": 1,
              "device": { "target_tbw_gib": 3000, "service_years": 8.0, "first_boot_ms": 0 },
              "policy": { "stages": {"amber":600,"orange":800,"red":900,"hysteresis":30} },
              "apps": {
                "com.nav":   {"package":"com.nav","cgroup":"/apps/nav","class":"essential"},
                "com.cam":   {"package":"com.cam","cgroup":"/apps/cam","class":"critical","safety_of_life":true},
                "com.brow":  {"package":"com.brow","cgroup":"/apps/brow","class":"normal"},
                "com.rogue": {"package":"com.rogue","cgroup":"/apps/rogue","class":"untrusted"}
              },
              "mediators": {
                "dlm": {"cgroup":"/sys/downloads","quota_bpd":2147483648,"single_tenant":false}
              }
            }"#,
        )
        .unwrap()
    }

    fn tick_at(g: &mut Governor, now: i64, writes: &[(&str, u64)]) -> TickOutput {
        let mut cg = BTreeMap::new();
        for (k, v) in writes {
            cg.insert(k.to_string(), Counter { wbytes: *v, wios: 1 });
        }
        g.tick(TickInput {
            now_ms: now,
            local_hour: 12,
            cgroup_writes: cg,
            device_write_bytes: Some(writes.iter().map(|(_, v)| *v).sum()),
            sponsored: vec![],
            wear: None,
        })
    }

    fn sample(life: u8) -> WearSample {
        WearSample {
            life_a: Some(life),
            life_b: Some(life),
            pre_eol: Some(if life >= 0x0A { 3 } else { 1 }),
        }
    }

    #[test]
    fn fresh_device_is_unlimited_and_green() {
        let mut g = Governor::new(cfg(), 0);
        let out = tick_at(&mut g, 1000, &[]);
        assert_eq!(out.stage, Stage::Green);
        assert!(out.decisions.iter().all(|d| d.cap.is_unlimited()));
    }

    #[test]
    fn a_full_bucket_lets_a_map_delta_through_then_tightens() {
        // On a healthy device a full bucket means unlimited speed *while* the
        // delta lands.  After the bytes are charged the bucket is drained and
        // the cap tightens — but never to a hang.
        let mut g = Governor::new(cfg(), 0);
        let before = tick_at(&mut g, 1000, &[]);
        let nav = before.decisions.iter().find(|d| d.package == "com.nav").unwrap();
        assert!(nav.cap.is_unlimited(), "fresh device, full bucket -> full speed");
        assert!(nav.burst_bytes >= 2 * GIB, "map deltas need a multi-GiB burst");

        let after = tick_at(&mut g, 2000, &[("/apps/nav", 1536 * MIB)]);
        let nav = after.decisions.iter().find(|d| d.package == "com.nav").unwrap();
        assert!(!nav.cap.is_unlimited(), "after a large delta the bucket is drained");
        assert!(nav.cap.wbps.unwrap() > 0, "but the app is never hung");
    }

    #[test]
    fn sustained_abuser_gets_throttled_but_never_zero() {
        let mut g = Governor::new(cfg(), 0);
        // Untrusted app writes 64 MiB every 10 s for an hour (way over its
        // 4 MiB/day allowance).
        let mut now = 0i64;
        let mut last_cap = Cap::UNLIMITED;
        for _ in 0..360 {
            now += 10_000;
            let out = tick_at(&mut g, now, &[("/apps/rogue", 64 * MIB)]);
            last_cap = out
                .decisions
                .iter()
                .find(|d| d.package == "com.rogue")
                .unwrap()
                .cap;
        }
        assert!(!last_cap.is_unlimited(), "sustained abuse must be capped");
        // The floor is the app's own sustainable rate, which for a 4 MiB/day
        // app is ~48 B/s. It must be non-zero (never a hang) and it must not
        // exceed the allowance (else "throttled" is a fiction).
        let w = last_cap.wbps.unwrap();
        assert!(w > 0, "never a zero cap");
        assert!(w <= 4 * MIB / 86_400 + 1, "trickle must not exceed the allowance: {w}");
    }

    #[test]
    fn maintenance_window_raises_the_essential_allowance() {
        // Inside the window, an essential app may claim a multiple of its normal
        // daily allowance, so a large map delta can land in one parked night.
        // Outside it, the allowance falls back to the normal figure.
        fn nav_quota(hour: u8) -> u64 {
            let mut c = cfg();
            c.policy.maintenance_window.enabled = true;
            c.policy.maintenance_window.start_hour = 0;
            c.policy.maintenance_window.end_hour = 6;
            c.policy.maintenance_window.multiplier = 8;
            let mut g = Governor::new(c, 0);
            let out = g.tick(TickInput {
                now_ms: 1000,
                local_hour: hour,
                cgroup_writes: BTreeMap::new(),
                device_write_bytes: Some(0),
                sponsored: vec![],
                wear: None,
            });
            assert_eq!(out.stage, Stage::Green);
            out.decisions.iter().find(|d| d.package == "com.nav").unwrap().quota_bpd
        }
        let in_window = nav_quota(2);
        let out_window = nav_quota(12);
        assert!(
            in_window > out_window,
            "maintenance window must raise the essential allowance: {in_window} vs {out_window}"
        );
        assert_eq!(out_window, 512 << 20, "outside the window: the configured figure");
    }

    #[test]
    fn maintenance_window_cannot_exceed_what_the_device_affords() {
        // On a worn device the pool is the binding constraint; the window may
        // reallocate toward essentials but must never promise more endurance
        // than remains. Allocations must stay under the ceiling regardless.
        let mut c = cfg();
        c.policy.maintenance_window.enabled = true;
        c.policy.maintenance_window.start_hour = 0;
        c.policy.maintenance_window.end_hour = 23;
        c.policy.maintenance_window.multiplier = 64;
        let mut g = Governor::new(c, 0);
        g.observe_wear(sample(0x08), 0, 0);
        let out = g.tick(TickInput {
            now_ms: 1000,
            local_hour: 2,
            cgroup_writes: BTreeMap::new(),
            device_write_bytes: Some(0),
            sponsored: vec![],
            wear: Some(sample(0x08)),
        });
        assert!(out.stage >= Stage::Orange);
        let total: u64 = out.decisions.iter().map(|d| d.quota_bpd).sum();
        assert!(
            total <= out.ceiling_bpd + out.critical_reserve_bpd,
            "plan {} exceeds ceiling {} + reserve {}",
            total,
            out.ceiling_bpd,
            out.critical_reserve_bpd
        );
    }

    #[test]
    fn essential_keeps_a_burst_the_device_can_actually_afford() {
        // On a healthy 3 TiB part, a full 2 GiB map delta must be allowed as a
        // burst: the bucket is full, so the cap is unlimited until the bytes
        // land, and only then does the accounting tighten.
        let mut g = Governor::new(cfg(), 0);
        let out = tick_at(&mut g, 1000, &[]);
        let nav = out.decisions.iter().find(|d| d.package == "com.nav").unwrap();
        assert!(nav.cap.is_unlimited(), "fresh device, full bucket -> full speed");
        // After the delta lands, the app is throttled but never stopped.
        let out = tick_at(&mut g, 2000, &[("/apps/nav", 2 * GIB)]);
        let nav = out.decisions.iter().find(|d| d.package == "com.nav").unwrap();
        assert!(nav.cap.wbps.unwrap() > 0, "map app must never be hung");
    }

    #[test]
    fn red_protects_critical_and_stops_the_rest() {
        let mut g = Governor::new(cfg(), 0);
        let th = StageThresholds::default();
        g.observe_wear(sample(0x0A), 0, 0);
        assert_eq!(g.stage, Stage::Red, "{:?}", g.wear);
        let out = tick_at(&mut g, 1000, &[]);
        assert_eq!(out.stage, Stage::Red);
        let cam = out.decisions.iter().find(|d| d.package == "com.cam").unwrap();
        let rogue = out.decisions.iter().find(|d| d.package == "com.rogue").unwrap();
        let nav = out.decisions.iter().find(|d| d.package == "com.nav").unwrap();
        assert!(cam.cap.is_unlimited(), "reversing camera must keep writing");
        assert_eq!(cam.quota_bpd, 8 * MIB);
        // Untrusted is cut to a zero allowance at Red, so its cap must be the
        // absolute minimum trickle: non-zero, so it is not hung.
        assert!(rogue.cap.wbps.unwrap() > 0);
        assert!(rogue.cap.wbps.unwrap() <= 1024);
        assert!(nav.quota_bpd < GIB / 2, "nav reduced to a trickle at Red");
        let _ = th;
    }

    #[test]
    fn sponsored_writes_are_charged_to_the_sponsor() {
        let mut g = Governor::new(cfg(), 0);
        // 3 GiB "downloaded on behalf of" the untrusted app, charged through
        // the download manager's cgroup (so not in the app's own counters).
        let out = tick_at(&mut g, 1000, &[("/sys/downloads", 3 * GIB)]);
        assert!(out.totals.sponsored_bytes == 0); // tick input had none
        // Now the mediator reports it properly.
        g.charge_sponsored(
            &SponsoredCharge {
                mediator: "dlm".into(),
                package: "com.rogue".into(),
                bytes: 3 * GIB,
            },
            2000,
        );
        let out = tick_at(&mut g, 3000, &[]);
        let rogue = out.decisions.iter().find(|d| d.package == "com.rogue").unwrap();
        assert!(
            !rogue.cap.is_unlimited(),
            "3 GiB delegated to an untrusted app must be charged to it"
        );
    }

    #[test]
    fn unattributed_mediator_traffic_is_capped_and_alerted() {
        let mut g = Governor::new(cfg(), 0);
        let mut alerts = vec![];
        for i in 1..=10 {
            let out = tick_at(&mut g, i * 10_000, &[("/sys/downloads", 64 * MIB)]);
            alerts.extend(out.alerts);
        }
        assert!(alerts.iter().any(|a| a.kind == AlertKind::UnattributedMediator));
    }

    #[test]
    fn waterfill_respects_demand_and_weights() {
        let d = vec![(Class::Essential, 100), (Class::Normal, 100), (Class::Untrusted, 100)];
        let a = waterfill(&d, 10_000);
        assert_eq!(a[&Class::Essential], 100);
        assert_eq!(a[&Class::Normal], 100);
        assert_eq!(a[&Class::Untrusted], 100);

        let a = waterfill(&d, 105);
        // essential weight 16, normal 4, untrusted 1: essentials nearly all.
        assert!(a[&Class::Essential] >= 80, "{a:?}");
        assert!(a[&Class::Normal] <= 20, "{a:?}");
        assert!(a[&Class::Untrusted] <= 6, "{a:?}");
    }

    #[test]
    fn hysteresis_prevents_cap_flapping() {
        let mut previous = Cap::from_bps(100_000, 20);
        let next = Cap::from_bps(105_000, 20);
        assert!(!cap_differs_materially(&previous, &next, 12));
        let big = Cap::from_bps(140_000, 20);
        assert!(cap_differs_materially(&previous, &big, 12));
        previous.wbps = None;
        assert!(cap_differs_materially(&previous, &next, 12));
    }

    #[test]
    fn nested_cgroups_are_not_double_charged() {
        assert!(is_nested_under("/apps/nav", "/apps"));
        assert!(!is_nested_under("/apps/nav", "/apps/nav"));
        assert!(!is_nested_under("/apps2/nav", "/apps"));
    }

    #[test]
    fn ceiling_falls_as_wear_rises() {
        let mut g = Governor::new(cfg(), 0);
        let fresh = tick_at(&mut g, 1000, &[]).ceiling_bpd;
        g.observe_wear(sample(0x08), 40 * GIB, 2000); // 70-80% consumed
        let worn = tick_at(&mut g, 3000, &[]).ceiling_bpd;
        assert!(worn < fresh, "worn {worn} should be below fresh {fresh}");
    }
}

