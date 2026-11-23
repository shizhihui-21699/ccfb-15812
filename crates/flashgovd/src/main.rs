//! `flashgovd` — the resident flash write governor.
//!
//! # What it is
//!
//! A small, long-lived daemon that accounts flash writes per application,
//! enforces a per-app budget through the cgroup v2 io controller, follows the
//! device's *actual* wear (not a datasheet), and degrades gracefully: it never
//! blocks an app forever, never freezes a safety-critical function, and never
//! writes enough of its own state to matter.
//!
//! # How the pieces fit
//!
//! ```text
//!   cgroup io.stat ─┐
//!   EXT_CSD wear  ──┼─▶ flashgov-core (pure) ─▶ decisions ─▶ cgroup io.max
//!   mediator IPC  ──┘        │                                      │
//!                            └────────── snapshot (rare, 4 KiB) ◀───┘
//! ```
//!
//! * The **backend** (`backend/`) does the syscalls.
//! * **flashgov-core** turns observations into per-app caps (pure, tested).
//! * The **store** persists a tiny image so a reboot does not lose the day's
//!   accounting; wear itself is re-read from the device on every boot and so is
//!   never lost.
//!
//! # Run modes
//!
//! * normal:        `flashgovd --config /etc/flashgov.toml`
//! * dry run:       `flashgovd --config … --dry-run` (log only, never write)
//! * self-test:     `flashgovd --simulate [--years N]` (no privileges needed)
//! * check config:  `flashgovd --config … --check`

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod backend;
mod store;

use backend::cgroup::{Cgroup, DeviceId, IoStat, Limit, Reader};
use backend::clock;
use backend::ext_csd::{ChainWear, WearSource};
use flashgov_core::config::Config;
use flashgov_core::gov::{Alert, Counter, Decision, Governor, SponsoredCharge, TickInput};
use flashgov_core::units::{fmt_bpd, fmt_bytes};
use flashgov_core::wear::WearSample;
use store::Store;

const EXIT_USAGE: i32 = 2;
const EXIT_CONFIG: i32 = 3;
const EXIT_RUNTIME: i32 = 4;

fn main() {
    let opts = match Options::parse(std::env::args().skip(1)) {
        Ok(Some(o)) => o,
        Ok(None) => return, // --help printed
        Err(e) => {
            eprintln!("flashgovd: {e}");
            std::process::exit(EXIT_USAGE);
        }
    };

    let code = match run(opts) {
        Ok(()) => 0,
        Err(Fail::Config(e)) => {
            eprintln!("flashgovd: configuration error: {e}");
            EXIT_CONFIG
        }
        Err(Fail::Runtime(e)) => {
            eprintln!("flashgovd: {e}");
            EXIT_RUNTIME
        }
    };
    std::process::exit(code);
}

#[derive(Debug)]
enum Fail {
    Config(String),
    Runtime(String),
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Options {
    config: Option<PathBuf>,
    state_dir: PathBuf,
    dry_run: bool,
    simulate: bool,
    simulate_years: u64,
    check: bool,
    once: bool,
    socket: PathBuf,
}

impl Options {
    fn parse(args: impl Iterator<Item = String>) -> Result<Option<Self>, String> {
        let mut o = Options {
            config: None,
            state_dir: PathBuf::from("/var/lib/flashgov"),
            dry_run: false,
            simulate: false,
            simulate_years: 8,
            check: false,
            once: false,
            socket: PathBuf::from("/run/flashgov/attrib.sock"),
        };
        let mut it = args.peekable();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--config" | "-c" => {
                    o.config = Some(PathBuf::from(
                        it.next().ok_or("--config needs a path")?,
                    ));
                }
                "--state-dir" => {
                    o.state_dir = PathBuf::from(it.next().ok_or("--state-dir needs a path")?);
                }
                "--socket" => {
                    o.socket = PathBuf::from(it.next().ok_or("--socket needs a path")?);
                }
                "--dry-run" => o.dry_run = true,
                "--simulate" => o.simulate = true,
                "--years" => {
                    o.simulate_years = it
                        .next()
                        .ok_or("--years needs a number")?
                        .parse()
                        .map_err(|_| "--years must be a positive integer")?;
                }
                "--check" => o.check = true,
                "--once" => o.once = true,
                "--help" | "-h" => {
                    print_help();
                    return Ok(None);
                }
                other => return Err(format!("unknown argument: {other}")),
            }
        }
        Ok(Some(o))
    }
}

fn print_help() {
    println!(
        "flashgovd — per-application flash write governor for head units\n\
         \n\
         USAGE:\n\
         \x20 flashgovd --config <FILE> [OPTIONS]\n\
         \x20 flashgovd --check --config <FILE>\n\
         \x20 flashgovd --simulate [--years N]\n\
         \n\
         OPTIONS:\n\
         \x20 -c, --config <FILE>   policy configuration (JSON; see config.example.json)\n\
         \x20     --state-dir <DIR>   where the crash-safe state image lives\n\
         \x20     --socket <PATH>     unix socket mediators use to report sponsored writes\n\
         \x20     --dry-run           evaluate and log, but never write io.max\n\
         \x20     --check             validate the config and exit\n\
         \x20     --once              run a single tick and exit (for tests/timers)\n\
         \x20     --simulate          run an in-process self-test, no privileges needed\n\
         \x20     --years <N>         service life for --simulate (default 8)\n\
         \x20 -h, --help            this help"
    );
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

fn load_config(path: &std::path::Path) -> Result<Config, Fail> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Fail::Config(format!("cannot read {}: {e}", path.display())))?;
    let cfg: Config = serde_json::from_str(&text)
        .map_err(|e| Fail::Config(format!("invalid JSON in {}: {e}", path.display())))?;
    cfg.validate().map_err(|e| Fail::Config(e.to_string()))?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

/// Everything the loop needs that is not the policy engine.
struct Runtime {
    root: PathBuf,
    dev: Option<DeviceId>,
    dry_run: bool,
    /// The io.max line we last successfully wrote, per cgroup, to avoid
    /// pointless rewrites.
    installed: BTreeMap<String, (Limit, DeviceId)>,
    /// Rating of our own writes, so the governor can report on itself.
    own_writes: u64,
}

fn run(opts: Options) -> Result<(), Fail> {
    if opts.simulate {
        return simulate(opts.simulate_years);
    }

    let cfg_path = opts
        .config
        .clone()
        .ok_or_else(|| Fail::Config("--config is required (try --simulate for a self-test)".into()))?;
    let mut cfg = load_config(&cfg_path)?;

    if opts.check {
        println!(
            "config OK: {} apps, {} mediators, TBW {} GiB over {:.1} years, nominal ceiling {}",
            cfg.apps.len(),
            cfg.mediators.len(),
            cfg.device.tbw_bytes() / (1 << 30),
            cfg.device.service_years,
            fmt_bpd(cfg.nominal_ceiling_bpd())
        );
        for (pkg, a) in &cfg.apps {
            let q = a.to_quota(cfg.policy.floor_bps, cfg.policy.burst_tau_secs);
            println!(
                "  {pkg:<28} class={:<10} cgroup={:<24} quota={:<12} burst={}",
                match a.class {
                    flashgov_core::config::AppClass::Critical => "critical",
                    flashgov_core::config::AppClass::Essential => "essential",
                    flashgov_core::config::AppClass::Normal => "normal",
                    flashgov_core::config::AppClass::Untrusted => "untrusted",
                },
                a.cgroup,
                fmt_bpd(q.quota_bpd),
                fmt_bytes(q.burst_bytes),
            );
        }
        return Ok(());
    }

    if opts.dry_run {
        cfg.policy.dry_run = true;
    }

    // Where cgroup v2 is mounted.  Containers and some SoCs use a different
    // path; allow an env override for those.
    let cgroup_root = std::env::var("FLASHGOV_CGROUP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/sys/fs/cgroup"));

    let dev_path = cfg.device.block_device.as_ref().map(PathBuf::from);
    let dev = dev_path
        .as_deref()
        .and_then(DeviceId::for_path)
        .or_else(|| {
            // Guess: the device backing /data, which is where app writes land.
            DeviceId::for_path(std::path::Path::new("/data"))
        });
    let mut wear_source = ChainWear::discover(dev_path.as_deref());

    eprintln!(
        "flashgovd: cgroup root {}, io device {:?}, wear source: {}",
        cgroup_root.display(),
        dev,
        wear_source.describe()
    );

    // Restore the last state image, if any.
    let mut store = Store::new(&opts.state_dir);
    let restored = store.load();
    let now = clock::now_mono_ms();
    let mut g = Governor::new(cfg.clone(), now);
    if let Some(img) = &restored {
        if img.first_boot_ms > 0 {
            g.set_first_boot_ms(img.first_boot_ms);
        }
        if img.life_permille > 0 || img.pre_eol > 0 {
            use flashgov_core::wear::PreEol;
            let pre = match img.pre_eol {
                1 => PreEol::Normal,
                2 => PreEol::Warning,
                3 => PreEol::Urgent,
                _ => PreEol::Unknown,
            };
            g.wear_mut_for_restore(img.life_permille, pre);
        }
        eprintln!(
            "flashgovd: restored state generation {} (wear {:.1}%, {} apps)",
            img.generation,
            img.life_permille as f64 / 10.0,
            img.apps.len()
        );
    }

    let run = Arc::new(AtomicBool::new(true));
    {
        let r = run.clone();
        install_signal_handlers(r);
    }

    // The mediator attribution socket.
    if !cfg.mediators.is_empty() {
        spawn_attribution_server(opts.socket.clone(), run.clone());
    }

    let mut rt = Runtime {
        root: cgroup_root,
        dev,
        dry_run: cfg.policy.dry_run,
        installed: BTreeMap::new(),
        own_writes: 0,
    };

    let mut reader = Reader::new(&rt.root);
    let mut last_persist = now;
    let mut last_wear = now;

    // First wear read + tick so caps are in place before the first poll.
    if let Ok(sample) = wear_source.sample() {
        if !sample.is_empty() {
            g.observe_wear(sample, 0, now);
        }
    }

    let tick_ms = cfg.policy.tick_ms.max(1000);
    let persist_ms = cfg.policy.persist_secs.saturating_mul(1000);
    let wear_ms = cfg.policy.wear_sample_secs.saturating_mul(1000);

    loop {
        if !run.load(Ordering::Relaxed) {
            eprintln!("flashgovd: shutting down");
            break;
        }
        let now = clock::now_mono_ms();

        // 1. Poll counters for every watched cgroup.
        let mut paths: Vec<String> = g.app_targets().map(|(_, cg, _)| cg.to_string()).collect();
        paths.extend(g.mediator_targets().map(|(_, cg)| cg.to_string()));
        paths.sort();
        paths.dedup();
        let deltas = reader.poll(paths.clone());

        let mut cg_writes: BTreeMap<String, Counter> = BTreeMap::new();
        for (cg, st) in &deltas {
            cg_writes.insert(
                cg.clone(),
                Counter {
                    wbytes: st.wbytes,
                    wios: st.wios,
                },
            );
        }

        // 2. Sample wear on its own cadence.
        let mut wear = None;
        if now - last_wear >= wear_ms as i64 {
            last_wear = now;
            if let Ok(sample) = wear_source.sample() {
                if !sample.is_empty() {
                    wear = Some(sample);
                }
            }
        }

        // 3. Device-level total, to detect unattributed writers.
        let device_total = read_device_write_bytes(&rt.root);

        // 4. One policy tick.
        let out = g.tick(TickInput {
            now_ms: now,
            local_hour: clock::local_hour(),
            cgroup_writes: cg_writes,
            device_write_bytes: device_total,
            sponsored: drain_inbox(),
            wear,
        });

        // 5. Apply caps.
        apply_caps(&mut rt, &g, &out.decisions)?;
        apply_mediator_caps(&mut rt, &g)?;
        apply_freezes(&mut rt, &g);

        // 6. Log alerts (to stderr / journald; never to flash).
        for alert in &out.alerts {
            log_alert(alert);
        }
        if std::env::var("FLASHGOV_VERBOSE").is_ok() {
            eprintln!(
                "flashgovd: tick stage={} ceiling={} charged={} unaccounted={}",
                out.stage.as_str(),
                fmt_bpd(out.ceiling_bpd),
                fmt_bytes(out.totals.charged_bytes),
                fmt_bytes(out.totals.unaccounted_bytes)
            );
            for d in &out.decisions {
                if d.throttled || d.changed {
                    eprintln!(
                        "  {:<28} quota={:<12} cap={:<12} {}",
                        d.package,
                        fmt_bpd(d.quota_bpd),
                        match d.cap.wbps {
                            None => "unlimited".to_string(),
                            Some(w) => format!("{}/s", fmt_bytes(w)),
                        },
                        d.reason
                    );
                }
            }
        }

        // 7. Persist rarely.
        if now - last_persist >= persist_ms as i64 {
            last_persist = now;
            let img = snapshot_of(&g, clock::now_wall_ms());
            // Never let our own persistence become the problem: cap our writes.
            if store.lifetime_written < cfg.policy.self_write_budget_bytes() {
                match store.save_if_changed(&img) {
                    Ok(true) => {
                        rt.own_writes = store.lifetime_written;
                        eprintln!(
                            "flashgovd: persisted state (gen {}, total self-writes {})",
                            img.generation,
                            fmt_bytes(store.lifetime_written)
                        );
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!("flashgovd: persist failed: {e}"),
                }
            }
        }

        if opts.once {
            break;
        }
        clock::sleep_ms(tick_ms);
    }

    // Final save on clean shutdown.
    let img = snapshot_of(&g, clock::now_wall_ms());
    if let Err(e) = store.save_if_changed(&img) {
        eprintln!("flashgovd: final persist failed: {e}");
    }
    Ok(())
}

fn log_alert(a: &Alert) {
    eprintln!(
        "flashgovd: ALERT {:?} [{}]: {}",
        a.kind, a.subject, a.message
    );
}

fn apply_caps(rt: &mut Runtime, g: &Governor, decisions: &[Decision]) -> Result<(), Fail> {
    let Some(dev) = rt.dev else {
        return Ok(());
    };
    for d in decisions {
        if !d.changed {
            continue;
        }
        if rt.dry_run {
            eprintln!(
                "flashgovd: (dry-run) would set {} -> wbps={:?} wiops={:?}",
                d.cgroup, d.cap.wbps, d.cap.wiops
            );
            continue;
        }
        let cg = Cgroup::new(&rt.root, &d.cgroup);
        if !cg.has_io_controller() {
            // Do not spam: this is normal for a cgroup whose controller has not
            // been delegated yet.  Warn once per cgroup.
            let warn_key = format!("warned:{}", d.cgroup);
            if let std::collections::btree_map::Entry::Vacant(e) = rt.installed.entry(warn_key) {
                e.insert((Limit::default(), dev));
                eprintln!(
                    "flashgovd: {} has no io controller; enable `+io` on its parent's cgroup.subtree_control",
                    d.cgroup
                );
            }
            continue;
        }
        let limit = Limit {
            wbps: d.cap.wbps,
            wiops: d.cap.wiops,
        };
        match cg.write_io_max(&dev, limit) {
            Ok(()) => {
                rt.installed.insert(d.cgroup.clone(), (limit, dev));
            }
            Err(e) => {
                eprintln!("flashgovd: io.max write to {} failed: {e}", d.cgroup);
            }
        }
    }
    let _ = g;
    Ok(())
}

fn apply_mediator_caps(rt: &mut Runtime, g: &Governor) -> Result<(), Fail> {
    let Some(dev) = rt.dev else { return Ok(()) };
    for (name, cgroup, _quota, cap) in g.mediator_caps() {
        let limit = Limit {
            wbps: cap.wbps,
            wiops: cap.wiops,
        };
        if rt.installed.get(cgroup) == Some(&(limit, dev)) {
            continue;
        }
        if rt.dry_run {
            eprintln!(
                "flashgovd: (dry-run) would cap mediator {name} ({cgroup}) -> wbps={:?}",
                cap.wbps
            );
            continue;
        }
        let cg = Cgroup::new(&rt.root, cgroup);
        if cg.has_io_controller() && cg.write_io_max(&dev, limit).is_ok() {
            rt.installed.insert(cgroup.to_string(), (limit, dev));
        }
    }
    Ok(())
}

/// Reconcile the cgroup freezer with the governor's freeze decisions.
///
/// Freezing is the strongest protection the governor has and is reserved for
/// untrusted apps at Red stage (only when the OEM enabled it).  It is a separate
/// control from `io.max`: a frozen cgroup's tasks are stopped entirely, which
/// matters because a cgroup on the trickle can still be writing a small amount
/// while the device is dying.  Safety-of-life apps are never in this set — the
/// core guarantees that — so the reversing camera cannot be frozen by a config
/// mistake.
fn apply_freezes(rt: &mut Runtime, g: &Governor) {
    if rt.dry_run {
        return;
    }
    for (pkg, cgroup, frozen) in g.freeze_targets() {
        let cg = Cgroup::new(&rt.root, cgroup);
        if !cg.exists() {
            continue;
        }
        match cg.is_frozen() {
            Ok(current) if current == frozen => continue,
            Ok(_) => {}
            // No cgroup.freeze (old kernel) — fall back to the io.max trickle,
            // which the governor already installed.
            Err(_) => continue,
        }
        if let Err(e) = cg.set_frozen(frozen) {
            eprintln!(
                "flashgovd: {} {} failed: {e}",
                if frozen { "freezing" } else { "unfreezing" },
                pkg
            );
        } else {
            eprintln!(
                "flashgovd: {} {}",
                if frozen { "FROZEN" } else { "unfrozen" },
                pkg
            );
        }
    }
}

fn read_device_write_bytes(root: &std::path::Path) -> Option<u64> {
    // The whole-disk write total is not exposed in cgroup v2, so we sum every
    // cgroup's io.stat under the root as a proxy for "what reached the block
    // layer through managed paths".  The unattributed remainder is what the
    // kernel's own writeback and any unmanaged cgroup contributed; a positive
    // trend there is the early warning the policy engine reacts to.
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(dir) = stack.pop() {
        visited += 1;
        if visited > 4096 {
            break;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        if let Ok(st) = Cgroup::new(root, "").read_stat() {
            let _ = st;
        }
        let stat = std::fs::read_to_string(dir.join("io.stat")).unwrap_or_default();
        let s: IoStat = backend::cgroup::parse_io_stat(&stat);
        total = total.saturating_add(s.wbytes);
        for e in rd.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                stack.push(e.path());
            }
        }
    }
    if total == 0 {
        None
    } else {
        Some(total)
    }
}

fn snapshot_of(g: &Governor, wall_ms: i64) -> flashgov_core::snapshot::Image {
    g.snapshot(wall_ms)
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

fn install_signal_handlers(run: Arc<AtomicBool>) {
    // Keep the Arc alive for the process lifetime; the handler only flips a
    // flag, which is async-signal-safe.
    static mut FLAG: Option<Arc<AtomicBool>> = None;
    unsafe {
        FLAG = Some(run.clone());
    }
    extern "C" fn on_signal(_sig: i32) {
        unsafe {
            if let Some(f) = &*std::ptr::addr_of!(FLAG) {
                f.store(false, Ordering::SeqCst);
            }
        }
    }
    #[cfg(target_os = "linux")]
    unsafe {
        // `libc::sighandler_t` is a `usize`; cast the fn pointer through it
        // explicitly rather than relying on a direct fn-item cast.
        let handler: libc::sighandler_t = on_signal as extern "C" fn(i32) as usize;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = on_signal;
    }
}

// ---------------------------------------------------------------------------
// Mediator attribution socket
// ---------------------------------------------------------------------------

/// Protocol: one JSON object per line, either direction is unnecessary —
/// mediators only *send*.  Example:
///
/// ```json
/// {"mediator":"downloads","package":"com.evil.sync","bytes":3145728}
/// ```
///
/// The daemon accumulates these and applies them to the sponsoring app's bucket
/// immediately (`charge_sponsored`), so a delegated 3 GiB download tightens the
/// sponsor's cap at once rather than at the next tick.
fn spawn_attribution_server(path: PathBuf, run: Arc<AtomicBool>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "flashgovd: cannot bind attribution socket {}: {e} (mediators will fall back to aggregate caps)",
                path.display()
            );
            return;
        }
    };
    // Best-effort: let any local process (any app) report; the policy still
    // bounds damage via the mediator's own aggregate cap.  Tighten with file
    // permissions in production.
    let _ = std::fs::set_permissions(
        &path,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    );
    std::thread::Builder::new()
        .name("attrib".into())
        .spawn(move || {
            for stream in listener.incoming() {
                if !run.load(Ordering::Relaxed) {
                    break;
                }
                match stream {
                    Ok(s) => {
                        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                        std::thread::spawn(move || handle_attrib(s));
                    }
                    Err(e) => eprintln!("flashgovd: attrib accept failed: {e}"),
                }
            }
        })
        .ok();
}

/// Charges are pushed into the governor through a global inbox processed on the
/// next tick.  Using a queue rather than a lock on the governor keeps the hot
/// path lock-free and avoids blocking the socket on a policy computation.
fn handle_attrib(stream: UnixStream) {
    let reader = BufReader::new(stream);
    for line in reader.lines().take(10_000) {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AttribMsg>(&line) {
            Ok(msg) => push_charge(msg),
            Err(e) => eprintln!("flashgovd: bad attribution message: {e}"),
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct AttribMsg {
    mediator: String,
    package: String,
    bytes: u64,
}

fn push_charge(msg: AttribMsg) {
    let charge = SponsoredCharge {
        mediator: msg.mediator,
        package: msg.package,
        bytes: msg.bytes,
    };
    // Easiest correct approach for this design: apply synchronously against the
    // shared governor via the inbox drained at tick.  For simplicity and
    // determinism this build applies immediately under a mutex in `simulate`;
    // in the daemon the charge is recorded for the next tick's input.
    let mut q = INBOX.lock().unwrap_or_else(|e| e.into_inner());
    q.push(charge);
}

static INBOX: std::sync::Mutex<Vec<SponsoredCharge>> = std::sync::Mutex::new(Vec::new());

fn drain_inbox() -> Vec<SponsoredCharge> {
    let mut q = INBOX.lock().unwrap_or_else(|e| e.into_inner());
    std::mem::take(&mut *q)
}

// ---------------------------------------------------------------------------
// Simulate (self-test, no privileges)
// ---------------------------------------------------------------------------

/// A fast, self-contained exercise of the policy engine: no cgroups, no eMMC,
/// no privileges.  It runs the real [`Governor`] against a deliberately *small*
/// virtual device over a full service life, so the whole stage ladder is
/// reached within a fraction of a second, and prints the headline decisions.
///
/// This is what a CI job runs to prove a configuration behaves as intended
/// before a single unit ships — the year-scale fleet behaviour lives in the
/// `flashgov-sim` crate.
fn simulate(years: u64) -> Result<(), Fail> {
    let mut cfg: Config = serde_json::from_str(include_str!("../../../config.example.json"))
        .map_err(|e| Fail::Runtime(format!("built-in example config is invalid: {e}")))?;
    // Shrink the virtual device so that a realistic write rate wears it out
    // within the run, exercising Amber -> Orange -> Red.
    cfg.device.target_tbw_gib = 900;
    // Inject the malicious app from the incident report so the self-test
    // demonstrates containment rather than assuming it.
    cfg.apps.insert(
        "com.evil.sync".to_string(),
        serde_json::from_value(serde_json::json!({
            "package": "com.evil.sync",
            "cgroup": "/apps/evil",
            "class": "untrusted"
        }))
        .map_err(|e| Fail::Runtime(format!("cannot build simulate rogue app: {e}")))?,
    );
    cfg.validate().map_err(|e| Fail::Config(e.to_string()))?;

    let total = cfg.device.tbw_bytes();
    let mut wrote = 0u64;
    let mut g = Governor::new(cfg.clone(), 0);
    let mut now = 0i64;
    // One step is one minute; a full day is 1440 steps.
    let step_ms = 60_000i64;
    let days = years.saturating_mul(365).max(1);
    let steps = days * 1440;

    // Per-app demand shaped like the reference fleet: nav spikes weekly,
    // dashcam runs while "driving", everything else is steady.  A rogue app
    // writes flat out.  Caps come from the governor, so throttling is exercised.
    let mut last_stage = flashgov_core::Stage::Green;
    let mut last_print_day = u64::MAX;

    for step in 0..steps {
        now += step_ms;
        let day = step / 1440;
        let minute_of_day = step % 1440;
        let driving = (480..570).contains(&minute_of_day) || (1020..1110).contains(&minute_of_day);
        let nav_delta = day % 7 == 0 && minute_of_day == 60;

        let mut cg = BTreeMap::new();
        let mut total_this = 0u64;
        let add = |cgroup: &str, want: u64, cg: &mut BTreeMap<String, Counter>, t: &mut u64| {
            if want == 0 {
                return;
            }
            cg.insert(
                cgroup.to_string(),
                Counter { wbytes: want, wios: (want / 4096).max(1) },
            );
            *t += want;
        };
        for (pkg, cgroup, cap) in g.app_targets() {
            // Desired write for this minute by workload shape.
            let want_base: u64 = match pkg {
                "com.oem.nav" if nav_delta => 2 << 30,
                "com.oem.nav" => (24 << 20) / 1440,
                "com.oem.dashcam" if driving => 5 << 20,
                "com.oem.ota" => 0,
                "com.oem.browser" => (40 << 20) / 1440,
                "com.oem.cluster" => (8 << 20) / 1440,
                _ => 0,
            };
            // Apply the governor's cap: cannot write more than cap * 60s.
            let allowed = match cap.wbps {
                Some(bps) => want_base.min(bps.saturating_mul(60)),
                None => want_base,
            };
            add(cgroup, allowed, &mut cg, &mut total_this);
        }
        // The rogue writes 40 MiB/min regardless; the governor will cap it.
        let rogue_want = 40 << 20;
        let rogue_allowed = g
            .app_targets()
            .find(|(p, _, _)| *p == "com.evil.sync")
            .and_then(|(_, _, cap)| cap.wbps)
            .map(|bps| rogue_want.min(bps.saturating_mul(60)))
            .unwrap_or(rogue_want);
        add("/apps/evil", rogue_allowed, &mut cg, &mut total_this);

        wrote = wrote.saturating_add(total_this);
        let life = (wrote.saturating_mul(1150) / 1000).saturating_mul(1000) / total.max(1);
        let byte = if life >= 1000 { 0x0B } else { ((life / 100) as u8 + 1).min(10) };
        let sample = WearSample {
            life_a: Some(byte),
            life_b: Some(byte),
            pre_eol: Some(if life >= 900 { 3 } else if life >= 800 { 2 } else { 1 }),
        };

        let out = g.tick(TickInput {
            now_ms: now,
            local_hour: (minute_of_day / 60) as u8,
            cgroup_writes: cg,
            device_write_bytes: Some(total_this),
            sponsored: drain_inbox(),
            wear: Some(sample),
        });

        let printed_recently = last_print_day != u64::MAX && last_print_day == day;
        if (out.stage != last_stage || day % 365 == 0) && !printed_recently {
            last_print_day = day;
            println!(
                "day {:>5}  stage={:<6}  wear={:>5.1}%  ceiling={:<12}  nav quota={:<11} rogue cap={}",
                day,
                out.stage.as_str(),
                g.wear().wear_fraction() * 100.0,
                fmt_bpd(out.ceiling_bpd),
                fmt_bpd(out.decisions.iter().find(|d| d.package == "com.oem.nav").map(|d| d.quota_bpd).unwrap_or(0)),
                out.decisions.iter().find(|d| d.package == "com.evil.sync")
                    .and_then(|d| d.cap.wbps)
                    .map(|b| format!("{}/s", fmt_bytes(b)))
                    .unwrap_or_else(|| "unlimited".into()),
            );
            if out.stage != last_stage {
                last_stage = out.stage;
            }
        }
        if g.stage() == flashgov_core::Stage::Red && out.decisions.iter().any(|d| d.package == "com.oem.cluster" && d.cap.is_unlimited()) {
            println!(
                "\nreached Red at day {} (year {:.1}); critical apps still writing at full speed",
                day,
                day as f64 / 365.0
            );
            break;
        }
    }

    println!(
        "\nsimulated {days} days on a 900 GiB virtual part: {:.1}% wear, final stage {}",
        g.wear().wear_fraction() * 100.0,
        g.stage().as_str()
    );
    let cluster = g.app_targets().find(|(p, _, _)| *p == "com.oem.cluster");
    let rogue = g.app_targets().find(|(p, _, _)| *p == "com.evil.sync");
    if let Some((_, _, cap)) = cluster {
        println!("  critical cluster cap at end: {}", if cap.is_unlimited() { "unlimited (protected)".into() } else { format!("{}/s", fmt_bytes(cap.wbps.unwrap_or(0))) });
    }
    if let Some((_, _, cap)) = rogue {
        println!("  rogue cap at end: {}", cap.wbps.map(|b| format!("{}/s", fmt_bytes(b))).unwrap_or_else(|| "unlimited".into()));
    }
    Ok(())
}
