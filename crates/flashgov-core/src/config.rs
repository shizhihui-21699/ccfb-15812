//! Configuration schema.
//!
//! The schema is deliberately *policy-light*: an integrator supplies the device
//! facts (endurance, service life) and per-app classes/overrides, and the
//! engine derives the actual byte rates.  Nothing an OEM tunes at the factory
//! should require them to compute bytes-per-second by hand.
//!
//! All fields have defaults that are safe for a mid-range eMMC head unit, so a
//! minimal config is a handful of lines.

use crate::budget::{Quota, DEFAULT_FLOOR_BPS, DEFAULT_TAU_SECS, MIN_BURST_BYTES};
use crate::units::mul_div;
use crate::wear::StageThresholds;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONFIG_VERSION: u32 = 1;

fn default_service_years() -> f64 {
    8.0
}
fn default_target_tbw_gib() -> u64 {
    // 3 TiB over an 8-year service life is ~1.05 GiB/day of sustainable host
    // writes: enough for a reference workload of map updates (~22 MiB/day on
    // average, bursty), a dashcam (~0.5 GiB/day) and ordinary app caches, with
    // room to spare.  Automotive eMMC parts span a wide range; integrators
    // should override this with the datasheet figure for the part they ship.
    3000
}
fn default_critical_reserve_pct() -> u64 {
    15
}
fn default_tau() -> u64 {
    DEFAULT_TAU_SECS
}
fn default_floor() -> u64 {
    DEFAULT_FLOOR_BPS
}
fn default_tick_ms() -> u64 {
    15_000
}
fn default_wear_sample_s() -> u64 {
    900
}
fn default_persist_s() -> u64 {
    600
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,
    pub device: DeviceConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub apps: BTreeMap<String, AppConfig>,
    #[serde(default)]
    pub mediators: BTreeMap<String, MediatorConfig>,
}

fn default_version() -> u32 {
    CONFIG_VERSION
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    /// Rated endurance of the eMMC part.  Used until the governor has measured
    /// enough wear to solve for the true value.  `target_tbw_gib <= 0` means
    /// "unknown", in which case a conservative 32 GiB is assumed.
    #[serde(default = "default_target_tbw_gib")]
    pub target_tbw_gib: u64,
    /// How long the unit must remain serviceable, in years, counted from first
    /// boot.  This is the denominator of the sustainable-write-rate ceiling.
    #[serde(default = "default_service_years")]
    pub service_years: f64,
    /// Unix ms of first boot; set at provisioning.  If absent the governor
    /// stamps the current time on first run and persists it.
    #[serde(default)]
    pub first_boot_ms: Option<i64>,
    /// Path to the block device whose life estimate should be read, e.g.
    /// `/dev/mmcblk0`.  `None` falls back to a sysfs heuristic.
    #[serde(default)]
    pub block_device: Option<String>,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            target_tbw_gib: default_target_tbw_gib(),
            service_years: default_service_years(),
            first_boot_ms: None,
            block_device: None,
        }
    }
}

impl DeviceConfig {
    pub fn tbw_bytes(&self) -> u64 {
        let gib = if self.target_tbw_gib == 0 {
            32
        } else {
            self.target_tbw_gib
        };
        gib.saturating_mul(1 << 30)
    }

    /// Service life expressed in whole days, at least 1.
    pub fn service_days(&self) -> u64 {
        let d = (self.service_years * 365.25).round();
        if d < 1.0 {
            1
        } else {
            d as u64
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub stages: StageThresholds,
    /// Fraction of the global ceiling withheld from ordinary apps so that
    /// critical functions (reversing camera, cluster, eCall) can always write.
    #[serde(default = "default_critical_reserve_pct")]
    pub critical_reserve_pct: u64,
    /// Seconds over which banked allowance may be spent (see `budget`).
    #[serde(default = "default_tau")]
    pub burst_tau_secs: u64,
    /// Rate a fully-throttled app is dropped to.  Never zero: a write of 0
    /// blocks the app forever and turns a throttle into a hang.
    #[serde(default = "default_floor")]
    pub floor_bps: u64,
    /// Minimum quota for a normal app, so the policy never makes the UI feel
    /// broken even when the device is nearly dead.
    #[serde(default = "default_min_normal_quota")]
    pub min_normal_bpd: u64,
    /// When enabled, the daemon will only *advise* (log) and never write
    /// `io.max`.  Used to validate a config in the field.
    #[serde(default)]
    pub dry_run: bool,
    /// Cap on how much any single app may write in one day regardless of
    /// remaining life.  A backstop against a pathological model.
    #[serde(default = "default_app_hard_cap")]
    pub app_hard_cap_bpd: u64,
    /// At Red stage, stop untrusted apps entirely (cgroup freezer) instead of
    /// leaving them on the trickle.  Safety-of-life apps are never frozen.
    /// Off by default: freezing is a behaviour change the OEM should opt into.
    #[serde(default)]
    pub freeze_untrusted_at_red: bool,
    /// Raise Essential-class budgets while the ignition is off, when nobody is
    /// waiting on the UI.  This is what lets a 2 GiB map delta finish in one
    /// parked night without ever competing with the user.
    #[serde(default)]
    pub maintenance_window: MaintenanceWindow,
    #[serde(default = "default_tick_ms")]
    pub tick_ms: u64,
    #[serde(default = "default_wear_sample_s")]
    pub wear_sample_secs: u64,
    #[serde(default = "default_persist_s")]
    pub persist_secs: u64,
    /// Minimum relative change before a new cap is pushed to the kernel.  Caps
    /// that wobble by a few percent cost every write path a syscall and make
    /// throughput graphs look like noise.
    #[serde(default = "default_hysteresis")]
    pub cap_hysteresis_pct: u64,
}

fn default_min_normal_quota() -> u64 {
    1 << 20 // 1 MiB/day
}
fn default_app_hard_cap() -> u64 {
    8 << 30 // 8 GiB/day
}
fn default_hysteresis() -> u64 {
    12
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            stages: StageThresholds::default(),
            critical_reserve_pct: default_critical_reserve_pct(),
            burst_tau_secs: default_tau(),
            floor_bps: default_floor(),
            min_normal_bpd: default_min_normal_quota(),
            dry_run: false,
            app_hard_cap_bpd: default_app_hard_cap(),
            freeze_untrusted_at_red: false,
            maintenance_window: MaintenanceWindow::default(),
            tick_ms: default_tick_ms(),
            wear_sample_secs: default_wear_sample_s(),
            persist_secs: default_persist_s(),
            cap_hysteresis_pct: default_hysteresis(),
        }
    }
}

impl PolicyConfig {
    pub fn freeze_untrusted_at_red(&self) -> bool {
        self.freeze_untrusted_at_red
    }

    /// Hard ceiling on how many bytes this daemon may write to flash for its
    /// own state over its lifetime.
    ///
    /// The governor must never become the problem it exists to solve.  The
    /// state image is 4 KiB and saved at most every `persist_secs`, so the
    /// expected cost is `4 KiB * (86400 / persist_secs)` per day — about 9 MB a
    /// year at the default 10-minute cadence, a rounding error against the
    /// 3000 GiB endurance model.  This cap is a hard stop well above that: if a
    /// configuration bug ever made the daemon save in a loop, it would stop
    /// writing rather than wear the flash out itself.
    pub fn self_write_budget_bytes(&self) -> u64 {
        // 1 GiB lifetime, which at the default cadence is ~100x the expected
        // cost and still 0.03 % of a 3 TiB part.
        1 << 30
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceWindow {
    #[serde(default)]
    pub enabled: bool,
    /// Local-time hour at which the window opens, 0..=23.
    #[serde(default = "default_window_start")]
    pub start_hour: u8,
    #[serde(default = "default_window_end")]
    pub end_hour: u8,
    /// Multiplier applied to Essential-class quotas inside the window.
    #[serde(default = "default_window_mult")]
    pub multiplier: u64,
}

fn default_window_start() -> u8 {
    1
}
fn default_window_end() -> u8 {
    5
}
fn default_window_mult() -> u64 {
    6
}

impl Default for MaintenanceWindow {
    fn default() -> Self {
        MaintenanceWindow {
            enabled: false,
            start_hour: 1,
            end_hour: 5,
            multiplier: 6,
        }
    }
}

impl MaintenanceWindow {
    /// `hour` is local wall-clock hour.  Handles windows that wrap midnight.
    pub fn contains(&self, hour: u8) -> bool {
        if !self.enabled {
            return false;
        }
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    /// Android package name, or any stable identifier for the sandbox.
    pub package: String,
    /// cgroup v2 path (relative to the cgroup root) that the app's processes
    /// live in.  Executed processes cannot leave their cgroup, which is what
    /// makes this a reliable enforcement point.
    pub cgroup: String,
    #[serde(default)]
    pub class: AppClass,
    /// Sustained allowance.  Omitted means "derive from class defaults".
    #[serde(default)]
    pub quota_bpd: Option<u64>,
    /// Explicit burst allowance; default is a quarter of the quota.
    #[serde(default)]
    pub burst_bytes: Option<u64>,
    /// User-visible name for the settings UI / logs.
    #[serde(default)]
    pub label: Option<String>,
    /// Apps that must never be frozen, even at Red (e.g. the reversing camera
    /// service).  Critical class implies this.
    #[serde(default)]
    pub safety_of_life: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AppClass {
    Critical,
    Essential,
    #[default]
    Normal,
    Untrusted,
}

impl From<AppClass> for crate::budget::Class {
    fn from(c: AppClass) -> Self {
        match c {
            AppClass::Critical => crate::budget::Class::Critical,
            AppClass::Essential => crate::budget::Class::Essential,
            AppClass::Normal => crate::budget::Class::Normal,
            AppClass::Untrusted => crate::budget::Class::Untrusted,
        }
    }
}

impl AppConfig {
    /// Quota used when the config does not override it.  These defaults encode
    /// the *expected* volumes of real workloads:
    ///
    /// * critical   — settings, trip log, crash dumps: tiny, but must never stall.
    /// * essential  — map deltas + dashcam: large, bursty, scheduled.
    /// * normal     — browser/media caches: moderate.
    /// * untrusted  — no legitimate reason to write much at all.
    pub fn effective_quota(&self) -> u64 {
        if let Some(q) = self.quota_bpd {
            return q;
        }
        match self.class {
            AppClass::Critical => 8 << 20,      //  8 MiB/day
            AppClass::Essential => 512 << 20,   // 512 MiB/day
            AppClass::Normal => 32 << 20,       // 32 MiB/day
            AppClass::Untrusted => 4 << 20,     //  4 MiB/day
        }
    }

    pub fn to_quota(&self, floor_bps: u64, tau_unused: u64) -> Quota {
        let q = Quota::new(self.effective_quota())
            .with_floor(floor_bps)
            .with_burst(self.burst_bytes.unwrap_or_else(|| {
                // Essential apps get a large burst by default: a map delta is
                // one indivisible lump and must not be dribbled out over days.
                let base = crate::budget::default_burst(self.effective_quota());
                if self.class == AppClass::Essential {
                    base.max(2 << 30).max(MIN_BURST_BYTES)
                } else {
                    base
                }
            }));
        let _ = tau_unused;
        q
    }
}

/// A system service that writes on behalf of apps (download manager, package
/// installer, media scanner, log shipper).
///
/// Such services are the main hole in cgroup-based attribution: when app X asks
/// the download manager to fetch a 3 GiB file, the bytes are written by the
/// download manager's processes and therefore land in *its* cgroup.  Two
/// mechanisms close the hole:
///
/// 1. The mediator reports bytes back over the attribution socket, tagged with
///    the sponsoring package (`Gov::charge_sponsored`).  Bytes are then charged
///    to the sponsor's bucket, exactly as if the app had written them.
/// 2. Whatever it fails to report still counts against the mediator's own
///    cgroup, which is itself subject to an aggregate cap (`quota_bpd` here).
///    A rogue app that abuses the mediator can therefore exhaust the mediator,
///    not the flash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediatorConfig {
    pub cgroup: String,
    /// Aggregate daily allowance for all traffic through this mediator that is
    /// not attributed to a sponsor.
    #[serde(default = "default_mediator_quota")]
    pub quota_bpd: u64,
    /// If true, unattributed writes through this mediator are charged to
    /// `sponsor_guess` when exactly one app is using the service.
    #[serde(default)]
    pub single_tenant: bool,
    #[serde(default)]
    pub sponsor_guess: Option<String>,
}

fn default_mediator_quota() -> u64 {
    2 << 30
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ConfigError {}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError(format!(
                "unsupported config version {} (expected {CONFIG_VERSION})",
                self.version
            )));
        }
        if !(0.5..=30.0).contains(&self.device.service_years) {
            return Err(ConfigError(format!(
                "device.service_years={} outside sane range 0.5..=30",
                self.device.service_years
            )));
        }
        if self.policy.floor_bps == 0 {
            return Err(ConfigError(
                "policy.floor_bps must be > 0: a zero cap blocks writes forever and hangs apps"
                    .into(),
            ));
        }
        if self.policy.critical_reserve_pct > 80 {
            return Err(ConfigError(
                "policy.critical_reserve_pct above 80 would starve every non-critical app".into(),
            ));
        }
        if self.policy.burst_tau_secs == 0 {
            return Err(ConfigError("policy.burst_tau_secs must be > 0".into()));
        }
        let th = &self.policy.stages;
        if !(th.amber < th.orange && th.orange < th.red && th.red <= 1000) {
            return Err(ConfigError(format!(
                "stage thresholds must satisfy amber < orange < red <= 1000, got {}/{}/{}",
                th.amber, th.orange, th.red
            )));
        }
        if th.amber < 100 {
            return Err(ConfigError(
                "stages.amber below 100 permille leaves too little room to react".into(),
            ));
        }
        let mut seen_cgroups: BTreeMap<&str, &str> = BTreeMap::new();
        let mut seen_pkgs: BTreeMap<&str, &str> = BTreeMap::new();
        for (key, app) in &self.apps {
            if key != &app.package {
                return Err(ConfigError(format!(
                    "apps.{key}.package is '{}'; the map key and package must match",
                    app.package
                )));
            }
            if !app.cgroup.starts_with('/') && app.cgroup.contains("..") {
                return Err(ConfigError(format!("apps.{key}.cgroup contains `..`")));
            }
            if let Some(prev) = seen_cgroups.insert(app.cgroup.as_str(), key.as_str()) {
                return Err(ConfigError(format!(
                    "apps.{prev} and apps.{key} share cgroup {}",
                    app.cgroup
                )));
            }
            if let Some(prev) = seen_pkgs.insert(app.package.as_str(), key.as_str()) {
                return Err(ConfigError(format!(
                    "apps.{prev} and apps.{key} share package {}",
                    app.package
                )));
            }
            if app.class == AppClass::Critical && app.effective_quota() > (64 << 20) {
                // Not fatal, but almost always a typo: critical apps are small
                // by nature and a large quota here means the reserve is wrong.
                return Err(ConfigError(format!(
                    "apps.{key} is critical but has a {}-byte/day quota; critical quotas should be small",
                    app.effective_quota()
                )));
            }
            if app.quota_bpd == Some(0) {
                return Err(ConfigError(format!(
                    "apps.{key}.quota_bpd=0 would block all writes; use class untrusted instead"
                )));
            }
        }
        for (name, m) in &self.mediators {
            if let Some(g) = &m.sponsor_guess {
                if !self.apps.contains_key(g) {
                    return Err(ConfigError(format!(
                        "mediators.{name}.sponsor_guess '{g}' is not a configured app"
                    )));
                }
            }
        }
        // A sanity check on the whole plan: the sum of nominal quotas should not
        // exceed the sustainable rate implied by the configured endurance and
        // service life, otherwise every app is born throttled.
        let ceiling = self.nominal_ceiling_bpd();
        if ceiling == 0 {
            return Err(ConfigError("computed ceiling is zero".into()));
        }
        Ok(())
    }

    /// Sustainable bytes/day implied by the *configured* endurance and service
    /// life, ignoring measured wear.  This is the value the engine uses on a
    /// fresh device.
    pub fn nominal_ceiling_bpd(&self) -> u64 {
        let total = self.device.tbw_bytes();
        let days = self.device.service_days();
        mul_div(total, 1, days).max(1)
    }

    pub fn critical_reserve_bpd(&self) -> u64 {
        mul_div(
            self.nominal_ceiling_bpd(),
            self.policy.critical_reserve_pct,
            100,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        serde_json::from_str(
            r#"{
                "version": 1,
                "device": { "target_tbw_gib": 120, "service_years": 8.0 },
                "policy": {},
                "apps": {
                  "com.acme.nav": {
                    "package": "com.acme.nav",
                    "cgroup": "/app.slice/com.acme.nav",
                    "class": "essential"
                  },
                  "com.acme.cam": {
                    "package": "com.acme.cam",
                    "cgroup": "/app.slice/com.acme.cam",
                    "class": "critical",
                    "safety_of_life": true
                  }
                }
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn parses_minimal_config() {
        let c = sample();
        c.validate().unwrap();
        assert_eq!(c.device.tbw_bytes(), 120 << 30);
        assert_eq!(c.device.service_days(), (8.0f64 * 365.25).round() as u64);
    }

    #[test]
    fn rejects_duplicate_cgroup() {
        let mut c = sample();
        c.apps.get_mut("com.acme.nav").unwrap().cgroup = "/app.slice/com.acme.cam".into();
        let err = c.validate().unwrap_err();
        assert!(err.0.contains("share cgroup"), "{err}");
    }

    #[test]
    fn rejects_zero_floor() {
        let mut c = sample();
        c.policy.floor_bps = 0;
        assert!(c.validate().unwrap_err().0.contains("forever"));
    }

    #[test]
    fn rejects_bad_stage_order() {
        let mut c = sample();
        c.policy.stages.amber = 900;
        assert!(c.validate().is_err());
    }

    #[test]
    fn critical_quota_must_be_small() {
        let mut c = sample();
        c.apps.get_mut("com.acme.cam").unwrap().quota_bpd = Some(10 << 30);
        assert!(c.validate().unwrap_err().0.contains("critical"));
    }

    #[test]
    fn maintenance_window_wraps_midnight() {
        let w = MaintenanceWindow {
            enabled: true,
            start_hour: 23,
            end_hour: 4,
            multiplier: 3,
        };
        assert!(w.contains(23));
        assert!(w.contains(0));
        assert!(w.contains(3));
        assert!(!w.contains(4));
        assert!(!w.contains(12));
    }

    #[test]
    fn essential_gets_a_large_burst_by_default() {
        let c = sample();
        let q = c.apps["com.acme.nav"].to_quota(DEFAULT_FLOOR_BPS, 60);
        assert!(q.burst_bytes >= 2 << 30);
        let normal = AppConfig {
            package: "x".into(),
            cgroup: "/x".into(),
            class: AppClass::Normal,
            quota_bpd: None,
            burst_bytes: None,
            label: None,
            safety_of_life: false,
        };
        let qn = normal.to_quota(DEFAULT_FLOOR_BPS, 60);
        assert_eq!(qn.burst_bytes, default_burst_for_test(32 << 20));
    }

    fn default_burst_for_test(q: u64) -> u64 {
        crate::budget::default_burst(q)
    }

    #[test]
    fn nominal_ceiling_matches_tbw_over_life() {
        let c = sample();
        let expected = (120u64 << 30) / ((8.0f64 * 365.25).round() as u64);
        assert_eq!(c.nominal_ceiling_bpd(), expected);
        // 120 GiB over 8 years is ~41 MiB/day. That is a sobering number and
        // exactly why the governor exists: a single 3 GiB/day dashcam on a
        // 120 GiB part would consume it in 40 days.
        assert!(c.nominal_ceiling_bpd() > (32 << 20));
        assert!(c.nominal_ceiling_bpd() < (64 << 20));
    }
}
