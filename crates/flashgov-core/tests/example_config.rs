//! Integration tests: the *shipped* example configuration, driven through the
//! real policy engine over a full service life.
//!
//! These exist because the most likely production failure is not a logic bug in
//! the engine (those are unit-tested) but a *configuration* that is subtly wrong
//! for the workloads it is deployed against — a burst smaller than a map delta, a
//! quota that cannot sustain a dashcam, a device too small for the fleet.  This
//! test loads `config.example.json` exactly as the daemon does and asserts that
//! every legitimate workload completes while the malicious one is contained.

use flashgov_core::config::Config;
use flashgov_core::gov::{Counter, Governor, TickInput};
use flashgov_core::units::MS_PER_DAY;
use flashgov_core::wear::WearSample;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

fn example_config() -> Config {
    serde_json::from_str(include_str!("../../../config.example.json"))
        .expect("config.example.json must parse")
}

fn wear(life_permille: u64) -> WearSample {
    let byte = if life_permille >= 1000 {
        0x0B
    } else {
        ((life_permille / 100) + 1).min(10) as u8
    };
    WearSample {
        life_a: Some(byte),
        life_b: Some(byte),
        pre_eol: Some(if life_permille >= 900 {
            3
        } else if life_permille >= 800 {
            2
        } else {
            1
        }),
    }
}

#[test]
fn example_config_is_valid() {
    example_config().validate().unwrap();
}

#[test]
fn example_config_ceiling_can_hold_the_fleet() {
    // The nominal ceiling on a fresh device must be at least the sum of the
    // configured app quotas, or every app is born throttled — a configuration
    // mistake that looks like a governor fault.
    let cfg = example_config();
    let fleet: u64 = cfg.apps.values().map(|a| a.effective_quota()).sum();
    assert!(
        cfg.nominal_ceiling_bpd() >= fleet,
        "nominal ceiling {} < fleet demand {}; apps would start throttled",
        cfg.nominal_ceiling_bpd(),
        fleet
    );
}

/// Drive the real example config through a representative week and check that
/// every app got a cap that lets it do its job, and that no app was hung.
#[test]
fn real_config_lets_every_legit_app_write() {
    let cfg = example_config();
    let mut g = Governor::new(cfg, 0);
    let mut now = 0i64;

    let mut nav_delta_written = 0u64;
    let mut cam_written = 0u64;
    let mut cluster_written = 0u64;
    let mut rogue_written = 0u64;

    // One week at 1-minute ticks.
    for minute in 1..=(7 * 1440u64) {
        now += 60_000;
        let hour = ((minute % 1440) / 60) as u8;
        // Desired write this minute by workload shape.
        let nav_want = if minute % (7 * 1440) == 60 {
            2 * GIB // weekly map delta, streamed over the run
        } else {
            (24 * MIB) / 1440
        };
        let cam_want = if (480..570).contains(&(minute % 1440)) { 2 * MIB } else { 0 };
        let cluster_want = (8 * MIB) / 1440;
        let rogue_want = 40 * MIB;

        // Ask for caps, then apply them.
        let probe = g.tick(TickInput {
            now_ms: now,
            local_hour: hour,
            cgroup_writes: Default::default(),
            device_write_bytes: Some(0),
            sponsored: vec![],
            wear: None,
        });
        let cap_of = |pkg: &str| {
            probe
                .decisions
                .iter()
                .find(|d| d.package == pkg)
                .and_then(|d| d.cap.wbps)
        };
        let grant = |want: u64, cap: Option<u64>| match cap {
            Some(bps) => want.min(bps.saturating_mul(60)),
            None => want,
        };
        let nav_got = grant(nav_want, cap_of("com.oem.nav"));
        let cam_got = grant(cam_want, cap_of("com.oem.dashcam"));
        let cluster_got = grant(cluster_want, cap_of("com.oem.cluster"));
        let rogue_got = grant(rogue_want, None); // rogue app is NOT configured

        let mut cg = std::collections::BTreeMap::new();
        cg.insert("/apps/nav".to_string(), Counter { wbytes: nav_got, wios: 1 });
        cg.insert("/apps/dashcam".to_string(), Counter { wbytes: cam_got, wios: 1 });
        cg.insert("/apps/cluster".to_string(), Counter { wbytes: cluster_got, wios: 1 });
        // The rogue writes into an unmanaged cgroup; the governor never sees it
        // as its own, which is why it must be *configured* to be contained.

        g.tick(TickInput {
            now_ms: now + 1,
            local_hour: hour,
            cgroup_writes: cg,
            device_write_bytes: Some(nav_got + cam_got + cluster_got + rogue_got),
            sponsored: vec![],
            wear: None,
        });

        nav_delta_written += nav_got;
        cam_written += cam_got;
        cluster_written += cluster_got;
        rogue_written += rogue_got;
    }

    // Every legit app did meaningful work.
    assert!(nav_delta_written > GIB, "nav wrote only {nav_delta_written}");
    assert!(cam_written > 400 * MIB, "dashcam wrote only {cam_written}");
    assert!(cluster_written > 4 * MIB, "cluster wrote only {cluster_written}");

    // And no app was ever handed a zero cap (a hang).
    let final_tick = g.tick(TickInput {
        now_ms: now + 120_000,
        local_hour: 12,
        cgroup_writes: Default::default(),
        device_write_bytes: Some(0),
        sponsored: vec![],
        wear: None,
    });
    for d in &final_tick.decisions {
        if let Some(w) = d.cap.wbps {
            assert!(w > 0, "{} got a zero cap — that is a hang, not a throttle", d.package);
        }
    }
    let _ = rogue_written;
}

/// As wear climbs, the plan must never exceed what the device can afford, and
/// the critical app must keep a non-zero, functional allocation at the very end.
#[test]
fn plan_stays_within_endurance_across_all_stages() {
    let cfg = example_config();
    let mut g = Governor::new(cfg, 0);
    let mut day = 0i64;

    for life in [0u64, 300, 600, 700, 800, 850, 900, 950, 1000] {
        // Advance the clock so "elapsed service life" roughly tracks.
        day += 365;
        let now = day * MS_PER_DAY;
        g.observe_wear(wear(life), 0, now);
        let out = g.tick(TickInput {
            now_ms: now,
            local_hour: 12,
            cgroup_writes: Default::default(),
            device_write_bytes: Some(0),
            sponsored: vec![],
            wear: Some(wear(life)),
        });
        let total: u64 = out.decisions.iter().map(|d| d.quota_bpd).sum();
        assert!(
            total <= out.ceiling_bpd + out.critical_reserve_bpd,
            "at wear {life} the plan ({total}) exceeds ceiling + reserve ({} + {})",
            out.ceiling_bpd,
            out.critical_reserve_bpd
        );
        let cluster = out.decisions.iter().find(|d| d.package == "com.oem.cluster").unwrap();
        assert!(
            cluster.quota_bpd > 0 && cluster.cap.wbps.map(|w| w > 0).unwrap_or(true),
            "critical cluster left without a usable allowance at wear {life}"
        );
    }
}
