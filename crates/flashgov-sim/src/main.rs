//! A deterministic, year-scale simulator for the flash governor.
//!
//! This is the tool that answers the uncomfortable question in the brief: *does
//! the governor break legitimate heavy writers, or stop the abusive ones?*  A
//! policy that survives unit tests but starves a navigation update in the field
//! is worse than none, and you cannot discover that by running the daemon for
//! five years.
//!
//! The simulator models:
//!
//! * A fleet of apps with realistic *workload shapes*, not constant rates:
//!   navigation pushes large deltas weekly and small ones daily; the dashcam
//!   writes a segment per minute while driving and flushes on ignition-off;
//!   the browser dribbles cache; a rogue app writes flat-out.
//! * A token-bucket device model that consumes endurance per host byte written
//!   and reports wear the way EXT_CSD does (coarse 10 % buckets), so the
//!   governor's *measured-endurance* path is exercised exactly as on hardware.
//! * The governor's real decision engine, tick by tick, with the real caps
//!   applied to each app's writes.
//!
//! Run `flashgov-sim --years 8` to see whether the fleet survives its service
//! life while every legitimate workload still completes.

use flashgov_core::budget::Class;
use flashgov_core::config::{Config, AppClass};
use flashgov_core::gov::{Counter, Governor, TickInput};
use flashgov_core::units::{fmt_bytes, fmt_days};
use flashgov_core::wear::WearSample;
use serde_json::json;
use std::collections::BTreeMap;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// A workload shape.  The simulator asks each workload how many bytes it wants
/// to write during a given minute; the governor decides how many it may write.
#[derive(Debug, Clone)]
struct Workload {
    package: String,
    cgroup: String,
    class: AppClass,
    kind: Shape,
    /// Bytes this workload *intended* to write (demand).
    demanded: u64,
    /// Bytes it actually got to write (after caps).
    granted: u64,
    /// Minutes in which it wanted to write but was throttled.
    throttled_minutes: u64,
    /// Minutes in which it wanted to write but got (almost) nothing.
    starved_minutes: u64,
    /// Largest single *minute's* worth of writes it managed.
    peak_minute: u64,
    /// Big transfers: planned, completed within their deadline, and missed.
    planned_big: u64,
    completed_big: u64,
    missed_big: u64,
    /// A big transfer in flight: bytes still owed, and the deadline minute.
    active: Option<ActiveTransfer>,
}

#[derive(Debug, Clone)]
struct ActiveTransfer {
    remaining: u64,
    deadline_minute: u64,
    size: u64,
}

/// Deadline for a big transfer, in minutes from its start.  A map delta has a
/// whole parked night; a dashcam flush has until the next drive begins.  If the
/// governor cannot land it in that window, the workload has genuinely been
/// broken — that is what the completion metric has to measure, not whether a
/// 2 GiB delta fits in one minute.
fn transfer_deadline_minutes(shape: &Shape) -> u64 {
    match shape {
        // A map delta is a parked-car background job with the whole night
        // available.  OEMs ship it overnight precisely so a slow tail after the
        // bucket drains is a non-issue.
        Shape::Nav { .. } => 10 * 60,
        // An OTA may run for hours; the driver just needs it done before the
        // next scheduled update window.
        Shape::Ota { .. } => 6 * 60,
        Shape::Dashcam { .. } => 45,
        _ => 60,
    }
}

#[derive(Debug, Clone)]
enum Shape {
    /// Navigation: a big weekly map delta plus small daily POI/traffic deltas.
    /// The delta is the canonical large-but-legitimate write.
    Nav {
        big_bytes: u64,
        big_period_days: u64,
        small_bytes_per_day: u64,
    },
    /// Dashcam: a continuous ring-buffer write while driving.  There is no
    /// separate "flush" — finalising a segment fsyncs data already written, it
    /// does not duplicate it — so its demand is simply its steady rate.
    Dashcam {
        driving_minutes_per_day: u64,
        bytes_per_driving_minute: u64,
    },
    /// OTA updater: usually idle, then a very large firmware download.  This is
    /// the hardest legitimate case: rare, huge, and absolutely must complete.
    Ota {
        bytes_per_update: u64,
        period_days: u64,
    },
    /// Ordinary app: a steady dribble (caches, small databases).
    Browser { bytes_per_day: u64 },
    /// Critical: tiny, but must never be blocked.
    Critical { bytes_per_day: u64 },
    /// Rogue: writes as fast as it can, forever.
    Rogue { bytes_per_minute: u64 },
}

impl Shape {
    /// The sustained daily allowance and the burst capacity an OEM should
    /// configure for this workload.
    ///
    /// The subtle part — and the reason a naive "burst = size of the biggest
    /// file" config silently breaks — is that the bucket *also* has to absorb
    /// the steady traffic between big operations.  If the burst equals the map
    /// delta exactly, the delta is perpetually a hundred megabytes short
    /// (because the daily POI/traffic writes nibbled the bucket during the
    /// week), and it trickles past its deadline forever.  So burst is sized as
    /// the largest single operation plus a full period's worth of steady
    /// traffic, doubled for margin.
    fn base_quota_and_burst(&self) -> (u64, u64) {
        match self {
            Shape::Nav {
                big_bytes,
                big_period_days,
                small_bytes_per_day,
            } => {
                let period = (*big_period_days).max(1);
                let per_day = big_bytes / period + small_bytes_per_day;
                // Largest operation + everything steady between two of them.
                let burst = (big_bytes + small_bytes_per_day * period) * 3 / 2;
                (per_day, burst)
            }
            Shape::Dashcam {
                driving_minutes_per_day,
                bytes_per_driving_minute,
            } => {
                let per_day = driving_minutes_per_day * bytes_per_driving_minute;
                // Burst covers a day's driving, so a single long trip after an
                // idle week never hits a cap.
                (per_day, (per_day * 3 / 2).max(64 * MIB))
            }
            Shape::Ota {
                bytes_per_update,
                period_days,
            } => {
                let period = (*period_days).max(1);
                let per_day = bytes_per_update / period + MIB;
                // The whole update must be able to land in one burst.
                (per_day, bytes_per_update * 3 / 2)
            }
            Shape::Browser { bytes_per_day } => (*bytes_per_day, (bytes_per_day / 4).max(8 * MIB)),
            Shape::Critical { bytes_per_day } => (*bytes_per_day, 4 * MIB),
            Shape::Rogue { .. } => {
                // Crucially, the rogue app *declares* a small, plausible
                // allowance — as a malicious app would, to avoid standing out in
                // a config review.  The governor has to catch it from its
                // observed write rate, not from a self-declared number.  If the
                // sim instead gave it a huge configured quota, the water-fill
                // allocator would faithfully reserve a huge share for it and
                // every honest app would be starved — which is exactly the
                // "a declared budget is not a trusted budget" lesson.
                (4 * MIB, MIB)
            }
        }
    }

    /// Bytes the workload wants to write in this minute, plus whether this
    /// minute *announces* a new large transfer.
    ///
    /// A large transfer is announced once and then drained over as many minutes
    /// as the deadline allows (see the simulation loop); the announcement
    /// carries no bytes itself.  This models reality: `rsync`/OTA/download
    /// stages do not write 2 GiB in a single minute, they stream it, and the
    /// question the governor must answer is whether the stream *finishes*.
    fn demand(&self, minute: u64) -> (u64, bool) {
        let day = minute / 1440;
        let minute_of_day = minute % 1440;
        match self {
            Shape::Nav {
                big_period_days,
                small_bytes_per_day,
                ..
            } => {
                let small = small_bytes_per_day / 1440;
                let is_big = *big_period_days > 0
                    && minute_of_day == 60 // 01:00, inside the maintenance window
                    && day % big_period_days == 0;
                (small, is_big)
            }
            Shape::Dashcam {
                driving_minutes_per_day,
                bytes_per_driving_minute,
            } => {
                // Drive between 08:00 and 09:00 plus 17:00-18:00, scaled to the
                // configured daily driving minutes.
                let driving = (8 * 60..8 * 60 + driving_minutes_per_day / 2)
                    .contains(&minute_of_day)
                    || (17 * 60..17 * 60 + driving_minutes_per_day - driving_minutes_per_day / 2)
                        .contains(&minute_of_day);
                if driving {
                    (*bytes_per_driving_minute, false)
                } else {
                    (0, false)
                }
            }
            Shape::Ota { period_days, .. } => {
                // Announce the update at 02:00 on the first day of the period.
                (0, *period_days > 0 && day % *period_days == 0 && minute_of_day == 2 * 60)
            }
            Shape::Browser { bytes_per_day } => (bytes_per_day / 1440, false),
            Shape::Critical { bytes_per_day } => (*bytes_per_day / 1440, false),
            Shape::Rogue { bytes_per_minute } => (*bytes_per_minute, false),
        }
    }

    /// Size of the big transfer announced on this minute, if any.
    fn big_size(&self) -> Option<u64> {
        match self {
            Shape::Nav { big_bytes, .. } => Some(*big_bytes),
            Shape::Ota { bytes_per_update, .. } => Some(*bytes_per_update),
            _ => None,
        }
    }
}

struct Device {
    /// Absolute capacity, in bytes, of host writes the part can take.
    total_endurance: u64,
    wrote: u64,
    /// Lifetime write amplification factor (block layer + FTL overhead).  The
    /// governor sees host bytes; the flash sees more.  1.15 is conservative for
    /// a well-managed eMMC under mostly-sequential dashcam traffic.
    amplification_milli: u64,
}

impl Device {
    fn life_permille(&self) -> u64 {
        let worn = self.wrote.saturating_mul(self.amplification_milli) / 1000;
        (worn.saturating_mul(1000) / self.total_endurance).min(1000)
    }

    fn ext_csd_sample(&self) -> WearSample {
        // Quantise to the 1..=10 buckets + 0x0B, exactly as eMMC reports.
        let permille = self.life_permille();
        let byte = if permille >= 1000 {
            0x0B
        } else {
            ((permille / 100) + 1).min(10) as u8
        };
        let pre_eol = if permille >= 900 {
            0x03
        } else if permille >= 800 {
            0x02
        } else {
            0x01
        };
        WearSample {
            life_a: Some(byte),
            life_b: Some(byte),
            pre_eol: Some(pre_eol),
        }
    }
}

struct SimConfig {
    years: u64,
    device: Device,
    apps: Vec<Workload>,
}

/// Which device we are simulating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceClass {
    /// 3 TiB part.  The reference workload genuinely fits with room to spare:
    /// this is the case where a well-tuned governor should be *invisible* to
    /// legitimate apps and only ever bite the rogue one.
    Comfortable,
    /// 1 TiB part.  The very same workload does **not** fit.  Here the governor
    /// must make hard choices — ration fairly, keep critical functions alive,
    /// and extend life — which is the situation the incident report describes.
    Oversubscribed,
}

fn device_for(class: DeviceClass) -> Device {
    let tib = match class {
        DeviceClass::Comfortable => 3_000,
        DeviceClass::Oversubscribed => 1_000,
    };
    Device {
        total_endurance: tib * GIB,
        wrote: 0,
        amplification_milli: 1150,
    }
}

fn build_world(class: DeviceClass) -> SimConfig {
    let device = device_for(class);
    let apps = vec![
        Workload::new(
            "com.oem.nav",
            "/apps/nav",
            AppClass::Essential,
            Shape::Nav {
                big_bytes: 2 * GIB,
                big_period_days: 7,
                small_bytes_per_day: 24 * MIB,
            },
        ),
        Workload::new(
            "com.oem.dashcam",
            "/apps/dashcam",
            AppClass::Essential,
            Shape::Dashcam {
                driving_minutes_per_day: 90,
                // ~2.5 MiB/min is a realistic 720p dashcam loop rate.  The
                // earlier 6 MiB/min was Mobileye-grade and alone would consume
                // most of any realistic part.
                bytes_per_driving_minute: 5 * MIB / 2,
            },
        ),
        Workload::new(
            "com.oem.browser",
            "/apps/browser",
            AppClass::Normal,
            Shape::Browser {
                bytes_per_day: 40 * MIB,
            },
        ),
        Workload::new(
            "com.oem.ota",
            "/apps/ota",
            AppClass::Essential,
            Shape::Ota {
                bytes_per_update: 4 * GIB,
                period_days: 90,
            },
        ),
        Workload::new(
            "com.oem.cluster",
            "/apps/cluster",
            AppClass::Critical,
            Shape::Critical {
                bytes_per_day: 6 * MIB,
            },
        ),
        // The malicious / badly-written app from the incident report.
        Workload::new(
            "com.evil.sync",
            "/apps/evil",
            AppClass::Untrusted,
            Shape::Rogue {
                bytes_per_minute: 40 * MIB,
            },
        ),
    ];
    SimConfig {
        years: 8,
        device,
        apps,
    }
}

impl Workload {
    fn new(package: &str, cgroup: &str, class: AppClass, kind: Shape) -> Self {
        Workload {
            package: package.into(),
            cgroup: cgroup.into(),
            class,
            kind,
            demanded: 0,
            granted: 0,
            throttled_minutes: 0,
            starved_minutes: 0,
            peak_minute: 0,
            planned_big: 0,
            completed_big: 0,
            missed_big: 0,
            active: None,
        }
    }
}

fn make_config(sim: &SimConfig) -> Config {
    let apps: BTreeMap<String, serde_json::Value> = sim
        .apps
        .iter()
        .map(|w| {
            let (quota, burst) = w.kind.base_quota_and_burst();
            let class = match w.class {
                AppClass::Critical => "critical",
                AppClass::Essential => "essential",
                AppClass::Normal => "normal",
                AppClass::Untrusted => "untrusted",
            };
            (
                w.package.clone(),
                json!({
                    "package": w.package,
                    "cgroup": w.cgroup,
                    "class": class,
                    "quota_bpd": quota,
                    "burst_bytes": burst,
                    "safety_of_life": matches!(w.class, AppClass::Critical),
                }),
            )
        })
        .collect();
    let tbw_gib = sim.device.total_endurance / GIB;
    let v = json!({
        "version": 1,
        "device": {
            "target_tbw_gib": tbw_gib,
            "service_years": 8.0,
            "first_boot_ms": 0,
        },
        "policy": {
            "stages": {"amber": 600, "orange": 800, "red": 900, "hysteresis": 30},
            "maintenance_window": {
                "enabled": true,
                "start_hour": 1,
                "end_hour": 5,
                "multiplier": 6,
            },
        },
        "apps": apps,
    });
    serde_json::from_value(v).expect("generated config must be valid")
}

struct Outcome {
    device_life_permille: u64,
    wrote_total: u64,
    days: u64,
    died: bool,
    stage_at_end: String,
    apps: Vec<AppReport>,
}

struct AppReport {
    package: String,
    class: Class,
    demanded: u64,
    granted: u64,
    throttled_pct: f64,
    starved_pct: f64,
    peak_minute: u64,
    completed_big: u64,
    planned_big: u64,
    missed_big: u64,
}

fn run(sim: &mut SimConfig, governor_on: bool) -> Outcome {
    let cfg = make_config(sim);
    let mut g = Governor::new(cfg, 0);
    let total_minutes = sim.years * 365 * 1440;
    let mut last_wear_minute = 0u64;
    let mut stage = "green".to_string();
    let mut death_minute: Option<u64> = None;

    for minute in 1..=total_minutes {
        let now_ms = minute as i64 * 60_000;

        // ---- what each app wants this minute -------------------------
        let mut wants: Vec<u64> = Vec::with_capacity(sim.apps.len());
        let mut announce: Vec<bool> = Vec::with_capacity(sim.apps.len());
        for w in &sim.apps {
            let (mut d, big) = w.kind.demand(minute);
            // An in-flight big transfer wants to finish as fast as it can: it
            // asks for everything it has left, and the governor's cap — not the
            // workload — is what limits it.  This is how a real downloader, OTA
            // agent or `rsync` behaves, and it is the honest test: if the
            // governor lets it drain a full bucket, the transfer completes at
            // flash speed; if it has been throttled, it takes longer.
            if let Some(active) = &w.active {
                d = d.saturating_add(active.remaining);
            }
            wants.push(d);
            announce.push(big);
        }
        // Logical demand: the bytes the workload *needs* written — steady
        // traffic plus each big transfer counted once at announcement, never
        // the repeated per-minute ask.  Using the per-minute ask would inflate
        // demand by the number of minutes a transfer is in flight and make every
        // utilisation figure meaningless.
        let mut need_this_min: Vec<u64> = Vec::with_capacity(sim.apps.len());
        for (i, w) in sim.apps.iter().enumerate() {
            let (steady, _) = w.kind.demand(minute);
            let big = if announce[i] { w.kind.big_size().unwrap_or(0) } else { 0 };
            let _ = i;
            need_this_min.push(steady + big);
        }

        // Expire transfers that ran out of time before we compute caps.
        for (i, w) in sim.apps.iter_mut().enumerate() {
            if let Some(active) = w.active.as_ref() {
                if minute > active.deadline_minute {
                    let _ = active;
                    w.missed_big += 1;
                    w.active = None;
                    let _ = i;
                }
            }
        }
        // Start newly announced transfers.
        for (i, w) in sim.apps.iter_mut().enumerate() {
            if announce[i] {
                if let Some(size) = w.kind.big_size() {
                    w.planned_big += 1;
                    w.active = Some(ActiveTransfer {
                        remaining: size,
                        deadline_minute: minute + transfer_deadline_minutes(&w.kind),
                        size,
                    });
                }
            }
        }

        // ---- what it is allowed --------------------------------------
        // The governor is consulted on a 1-minute tick during the sim so that
        // the burst mechanics are exercised at realistic granularity.
        let mut cg = BTreeMap::new();
        for w in &sim.apps {
            cg.insert(w.cgroup.clone(), Counter::default());
        }
        let local_hour = ((minute % 1440) / 60) as u8;

        // First, ask for the current caps *before* this minute's writes, so a
        // full bucket really does let a big transfer start at full speed.
        let out = g.tick(TickInput {
            now_ms,
            local_hour,
            cgroup_writes: cg.clone(),
            device_write_bytes: Some(0),
            sponsored: vec![],
            wear: None,
        });
        stage = out.stage.as_str().to_string();
        let mut caps: Vec<Option<u64>> = Vec::with_capacity(sim.apps.len());
        for w in sim.apps.iter() {
            let cap = out
                .decisions
                .iter()
                .find(|d| d.package == w.package)
                .and_then(|d| d.cap.wbps);
            caps.push(if governor_on { cap } else { None });
        }

        // ---- run the minute ------------------------------------------
        let mut wrote_by_cg: BTreeMap<String, Counter> = BTreeMap::new();
        let mut accounted: u64 = 0;
        for (i, w) in sim.apps.iter_mut().enumerate() {
            let want = wants[i];
            let mut allowed = want;
            if let Some(bps) = caps[i] {
                let per_min = bps.saturating_mul(60);
                if want > per_min {
                    allowed = per_min;
                    w.throttled_minutes += 1;
                    if allowed * 20 < want {
                        w.starved_minutes += 1;
                    }
                }
            }
            w.demanded = w.demanded.saturating_add(need_this_min[i]);
            w.granted = w.granted.saturating_add(allowed.min(need_this_min[i] + wants[i].saturating_sub(need_this_min[i])));
            if allowed > w.peak_minute {
                w.peak_minute = allowed;
            }
            // Credit an in-flight big transfer by what it actually got.
            let mut completed: Option<u64> = None;
            if let Some(active) = w.active.as_mut() {
                let credit = allowed.min(active.remaining);
                active.remaining -= credit;
                if active.remaining == 0 {
                    completed = Some(active.size);
                }
            }
            if completed.is_some() {
                w.completed_big += 1;
                w.active = None;
            }
            sim.device.wrote = sim.device.wrote.saturating_add(allowed);
            accounted += allowed;
            wrote_by_cg.insert(
                w.cgroup.clone(),
                Counter {
                    wbytes: allowed,
                    wios: (allowed / 4096).max(1),
                },
            );
        }

        // ---- feed the writes back and sample wear --------------------
        let sample_due = minute - last_wear_minute >= 60 * 6;
        let wear = if sample_due {
            last_wear_minute = minute;
            Some(sim.device.ext_csd_sample())
        } else {
            None
        };
        // The device total includes the apps plus a fixed OS overhead (journal,
        // fs metadata) that the governor does not attribute to any app.  This is
        // what a real box looks like and exercises the attribution-gap logic.
        let os_overhead = accounted / 40; // ~2.5 %
        sim.device.wrote = sim.device.wrote.saturating_add(os_overhead);
        if death_minute.is_none() && sim.device.life_permille() >= 1000 {
            death_minute = Some(minute);
        }
        g.tick(TickInput {
            now_ms: now_ms + 1,
            local_hour,
            cgroup_writes: wrote_by_cg,
            device_write_bytes: Some(accounted + os_overhead),
            sponsored: vec![],
            wear,
        });
    }

    // Any transfer still in flight at the end never completed.
    for w in sim.apps.iter_mut() {
        if w.active.is_some() {
            w.missed_big += 1;
            w.active = None;
        }
    }

    let days = death_minute.map(|m| m / 1440).unwrap_or(total_minutes / 1440);
    let apps = sim
        .apps
        .iter()
        .map(|w| AppReport {
            package: w.package.clone(),
            class: w.class.into(),
            demanded: w.demanded,
            granted: w.granted,
            throttled_pct: if w.demanded > 0 {
                100.0 * w.throttled_minutes as f64 / (sim.years * 365 * 1440) as f64
            } else {
                0.0
            },
            starved_pct: if w.demanded > 0 {
                100.0 * w.starved_minutes as f64 / (sim.years * 365 * 1440) as f64
            } else {
                0.0
            },
            peak_minute: w.peak_minute,
            completed_big: w.completed_big,
            planned_big: w.planned_big,
            missed_big: w.missed_big,
        })
        .collect();

    Outcome {
        device_life_permille: sim.device.life_permille(),
        wrote_total: sim.device.wrote,
        days,
        died: death_minute.is_some(),
        stage_at_end: stage,
        apps,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut years = 8u64;
    let mut json_out = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--years" => {
                i += 1;
                years = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(8);
            }
            "--json" => json_out = true,
            "--help" | "-h" => {
                println!(
                    "flashgov-sim [--years N] [--json]\n\
                     \n\
                     Runs the governor's policy engine against a synthetic fleet over a full\n\
                     service life, on two device classes:\n\
                     \n\
                     * comfortable      3 TiB part; the workload fits with room to spare. The\n\
                                        governor should be invisible to every legitimate app\n\
                                        and only bite the rogue one.\n\
                     * oversubscribed   1 TiB part; the same workload does NOT fit. The\n\
                                        governor must ration fairly and keep critical\n\
                                        functions alive — the incident-report scenario.\n\
                     \n\
                     Each class is run both governed and ungoverned, so the diff shows what\n\
                     the governor actually bought and what it cost."
                );
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    let mut results = Vec::new();
    for class in [DeviceClass::Comfortable, DeviceClass::Oversubscribed] {
        let mut world = build_world(class);
        world.years = years;
        let governed = run(&mut world, true);

        let mut base_world = build_world(class);
        base_world.years = years;
        let ungoverned = run(&mut base_world, false);
        results.push((class, governed, ungoverned));
    }

    if json_out {
        let out = json!({
            "years": years,
            "scenarios": results.iter().map(|(class, g, b)| json!({
                "device": match class {
                    DeviceClass::Comfortable => "comfortable",
                    DeviceClass::Oversubscribed => "oversubscribed",
                },
                "endurance_gib": device_for(*class).total_endurance / GIB,
                "governed": outcome_json(g),
                "baseline": outcome_json(b),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        return;
    }

    println!("flashgov-sim — {years}-year fleet simulation");
    println!(
        "Reference fleet: nav (2 GiB delta/week), dashcam (90 min/day), OTA (4 GiB/quarter),\n\
         browser, cluster (critical), and one rogue writer. 1.15x write amplification.\n"
    );

    for (class, governed, ungoverned) in &results {
        let (name, blurb) = match class {
            DeviceClass::Comfortable => (
                "COMFORTABLE DEVICE (3 TiB)",
                "the workload fits: a good governor should be invisible to honest apps",
            ),
            DeviceClass::Oversubscribed => (
                "OVERSUBSCRIBED DEVICE (1 TiB)",
                "the workload does NOT fit: the governor must ration and protect criticals",
            ),
        };
        println!("########################################################################");
        println!("# {name}");
        println!("# {blurb}");
        println!("########################################################################\n");
        print_outcome("GOVERNED", governed);
        print_outcome("BASELINE (no governor)", ungoverned);
        print_diff(governed, ungoverned);
        println!();
    }
}

fn print_outcome(label: &str, o: &Outcome) {
    println!("== {label} ==");
    let verdict = if o.died {
        format!("DEVICE DIED after {}", fmt_days(o.days as f64))
    } else {
        format!("survived {:.1}y at {:.1}% wear", o.days as f64 / 365.25, o.device_life_permille as f64 / 10.0)
    };
    println!("  total written: {}   {}   final stage: {}", fmt_bytes(o.wrote_total), verdict, o.stage_at_end);
    println!(
        "  {:<16} {:<10} {:>10} {:>10} {:>7} {:>7} {:>8} {:>8} {:>9}",
        "app", "class", "demanded", "granted", "thr%", "starv%", "big ok", "big miss", "peak/min"
    );
    for a in &o.apps {
        println!(
            "  {:<16} {:<10} {:>10} {:>10} {:>6.1}% {:>6.1}% {:>8} {:>8} {:>9}",
            a.package,
            format!("{:?}", a.class).to_lowercase(),
            fmt_bytes(a.demanded),
            fmt_bytes(a.granted),
            a.throttled_pct,
            a.starved_pct,
            format!("{}/{}", a.completed_big, a.planned_big),
            a.missed_big,
            fmt_bytes(a.peak_minute),
        );
    }
    println!();
}

fn print_diff(governed: &Outcome, ungoverned: &Outcome) {
    println!("  -- what the governor changed --");
    let rogue_g = governed.apps.iter().find(|a| a.package == "com.evil.sync").unwrap();
    let rogue_b = ungoverned.apps.iter().find(|a| a.package == "com.evil.sync").unwrap();
    println!(
        "  rogue app: {} governed vs {} ungoverned ({:.0}x less)",
        fmt_bytes(rogue_g.granted),
        fmt_bytes(rogue_b.granted),
        rogue_b.granted as f64 / rogue_g.granted.max(1) as f64
    );
    let nav_g = governed.apps.iter().find(|a| a.package == "com.oem.nav").unwrap();
    let ota_g = governed.apps.iter().find(|a| a.package == "com.oem.ota").unwrap();
    let cluster_g = governed.apps.iter().find(|a| a.package == "com.oem.cluster").unwrap();
    let dash_g = governed.apps.iter().find(|a| a.package == "com.oem.dashcam").unwrap();
    println!(
        "  navigation: {}/{} map deltas on time ({} missed)",
        nav_g.completed_big, nav_g.planned_big, nav_g.missed_big
    );
    println!(
        "  OTA: {}/{} firmware updates on time ({} missed)",
        ota_g.completed_big, ota_g.planned_big, ota_g.missed_big
    );
    println!(
        "  dashcam: {:.1}% of its demand met, starved {:.1}%",
        100.0 * dash_g.granted as f64 / dash_g.demanded.max(1) as f64,
        dash_g.starved_pct
    );
    println!(
        "  cluster (critical): {:.0}% of its demand met, starved {:.2}%",
        100.0 * cluster_g.granted as f64 / cluster_g.demanded.max(1) as f64,
        cluster_g.starved_pct
    );
    let g = if governed.died {
        format!("DEVICE DIED after {}", fmt_days(governed.days as f64))
    } else {
        format!("alive after {} at {:.1}% wear", fmt_days(governed.days as f64), governed.device_life_permille as f64 / 10.0)
    };
    let b = if ungoverned.died {
        format!("DEVICE DIED after {}", fmt_days(ungoverned.days as f64))
    } else {
        format!("alive after {} at {:.0}% wear", fmt_days(ungoverned.days as f64), ungoverned.device_life_permille as f64 / 10.0)
    };
    println!("  device: governed {g}   |   ungoverned {b}");
}

fn outcome_json(o: &Outcome) -> serde_json::Value {
    json!({
        "device_life_permille": o.device_life_permille,
        "wrote_total": o.wrote_total,
        "days": o.days,
        "died": o.died,
        "stage_at_end": o.stage_at_end,
        "apps": o.apps.iter().map(|a| json!({
            "package": a.package,
            "class": format!("{:?}", a.class).to_lowercase(),
            "demanded": a.demanded,
            "granted": a.granted,
            "throttled_pct": a.throttled_pct,
            "starved_pct": a.starved_pct,
            "big_completed": a.completed_big,
            "big_planned": a.planned_big,
            "big_missed": a.missed_big,
            "peak_minute": a.peak_minute,
        })).collect::<Vec<_>>(),
    })
}
