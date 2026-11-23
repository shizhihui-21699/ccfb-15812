//! cgroup v2 io controller: reading per-cgroup write counters and writing
//! `io.max`.
//!
//! # Why cgroup v2 and not per-process accounting
//!
//! The requirement is "charge application X for the bytes it causes to be
//! written, including when it writes through a system service or a shared
//! directory".  The only kernel mechanism that gets this right by construction
//! is the cgroup its processes live in:
//!
//! * A process cannot escape its cgroup.  It can `exec`, `fork`, `setsid`,
//!   `chdir` and `unshare` all it likes — every descendant stays in the same
//!   subtree.  So every write the app's own processes issue is attributed to
//!   the app, no matter which path or service it goes through.
//! * The io controller's `io.stat` counts the bytes the *block layer* sees for
//!   that cgroup, i.e. after page-cache coalescing and including metadata the
//!   kernel writes on the app's behalf.
//! * `io.max` applies the same traversal: a child cgroup's processes are
//!   throttled by every ancestor's limit, so a per-app cgroup under a
//!   mediated subtree is bounded both individually and in aggregate.
//!
//! What cgroup accounting *cannot* see is a write made by a *different*
//! cgroup's process on the app's behalf — the download manager.  That is the one
//! hole, and it is closed by the mediator attribution channel
//! (`Governor::charge_sponsored`) plus an aggregate cap on the mediator.
//!
//! # Reading `io.stat`
//!
//! ```text
//! 8:0 rbytes=1234 wbytes=5678 rios=10 wios=20 dbytes=0 dios=0
//! ```
//!
//! `wbytes` is the counter we charge.  It is monotonically increasing and
//! 64-bit, and we always charge a *delta* between samples, clamping at zero so a
//! counter that wraps or resets (cgroup recreated) cannot produce a spurious
//! negative.

#![allow(dead_code)] // some API is exercised only on the Linux target

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// A cgroup's write counters at one instant, summed across all block devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IoStat {
    pub wbytes: u64,
    pub wios: u64,
}

/// Parse a single `io.stat` blob, summing `wbytes`/`wios` over all devices.
///
/// Unknown keys (`rbytes`, `dbytes`, …) are ignored, which keeps us compatible
/// with kernels that add fields.  Malformed lines are skipped rather than
/// failing the whole read — a partially-readable statue must not blind the
/// governor.
pub fn parse_io_stat(text: &str) -> IoStat {
    let mut out = IoStat::default();
    for line in text.lines() {
        // Skip the leading "MAJ:MIN".
        let mut parts = line.split_ascii_whitespace();
        let head = parts.next().unwrap_or("");
        if !head.contains(':') {
            continue;
        }
        for kv in parts {
            if let Some((k, v)) = kv.split_once('=') {
                let Ok(n) = v.parse::<u64>() else { continue };
                match k {
                    "wbytes" => out.wbytes = out.wbytes.saturating_add(n),
                    "wios" => out.wios = out.wios.saturating_add(n),
                    _ => {}
                }
            }
        }
    }
    out
}

/// One cgroup's interface, rooted at `<cgroup_root>/<path>`.
#[derive(Debug, Clone)]
pub struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    pub fn new(root: &Path, path: &str) -> Self {
        Cgroup {
            dir: root.join(path.trim_start_matches('/')),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn exists(&self) -> bool {
        self.dir.join("io.stat").exists() || self.dir.exists()
    }

    /// Read `io.stat`.  A cgroup that has no io controller (or does not exist
    /// yet, because the app has not started) yields a zero reading rather than
    /// an error: the governor must tolerate apps appearing and disappearing.
    pub fn read_stat(&self) -> io::Result<IoStat> {
        match fs::read_to_string(self.dir.join("io.stat")) {
            Ok(s) => Ok(parse_io_stat(&s)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(IoStat::default()),
            Err(e) => Err(e),
        }
    }

    /// Whether the io controller is enabled for this cgroup.  Feeding `+io` to
    /// `cgroup.subtree_control` of the parent delegates it; the leaf file
    /// `io.max` only exists when it is.
    pub fn has_io_controller(&self) -> bool {
        self.dir.join("io.max").exists()
    }

    /// Write an `io.max` line.  `None` disables the limit for that dimension.
    ///
    /// The kernel syntax is `MAJ:MIN rbps=… wbps=… riops=… wiops=…`, with `max`
    /// meaning unlimited.  We write `max` for read dimensions (we do not limit
    /// reads), and for a dimension we are not limiting, so the file is replaced
    /// wholesale rather than merged — `io.max` is a replace, not a patch.
    pub fn write_io_max(&self, dev: &DeviceId, cap: Limit) -> io::Result<()> {
        let line = format!(
            "{}:{ } rbps=max wbps={} riops=max wiops={}\n",
            dev.major, dev.minor,
            fmt_limit(cap.wbps),
            fmt_limit(cap.wiops)
        );
        let path = self.dir.join("io.max");
        // `io.max` is write-only-ish; a plain write replaces the entry for the
        // named device while leaving entries for other devices intact.  That is
        // exactly the granularity we want.
        fs::write(path, line.replace("{ }", " "))
    }

    /// Freeze / unfreeze the cgroup (all processes stop/continue).
    /// Requires the cgroup freezer, present in cgroup v2 as `cgroup.freeze`.
    pub fn set_frozen(&self, frozen: bool) -> io::Result<()> {
        fs::write(self.dir.join("cgroup.freeze"), if frozen { "1\n" } else { "0\n" })
    }

    pub fn is_frozen(&self) -> io::Result<bool> {
        let s = fs::read_to_string(self.dir.join("cgroup.freeze"))?;
        Ok(s.trim() == "1")
    }
}

fn fmt_limit(v: Option<u64>) -> String {
    match v {
        None => "max".to_string(),
        // The kernel rejects a literal 0 as a rate; the smallest meaningful
        // value is 1.  But we never intend 0 — the policy guarantees a floor.
        Some(0) => "1".to_string(),
        Some(n) => n.to_string(),
    }
}

/// A block device identified the way `io.max` needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId {
    pub major: u32,
    pub minor: u32,
}

impl DeviceId {
    pub fn new(major: u32, minor: u32) -> Self {
        DeviceId { major, minor }
    }

    /// Parse the `MAJ:MIN` of a device from sysfs `dev` file contents.
    pub fn parse_dev(s: &str) -> Option<DeviceId> {
        let (maj, min) = s.trim().split_once(':')?;
        Some(DeviceId {
            major: maj.parse().ok()?,
            minor: min.parse().ok()?,
        })
    }

    /// Resolve the underlying device of a path (e.g. the filesystem holding
    /// `/data`) by walking `/sys/dev/block` or stat-ing the mount source.
    pub fn for_path(path: &Path) -> Option<DeviceId> {
        device_id_via_metadata(path)
    }
}

fn device_id_via_metadata(path: &Path) -> Option<DeviceId> {
    use std::os::unix::fs::MetadataExt;
    let md = fs::metadata(path).ok()?;
    let rdev = md.rdev();
    if rdev == 0 {
        return None;
    }
    // Linux dev_t encoding: major in bits 8..20 and 32+, minor in 0..8 and 20+.
    let major = ((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfff);
    let minor = (rdev & 0xff) | ((rdev >> 12) & !0xff);
    Some(DeviceId {
        major: major as u32,
        minor: minor as u32,
    })
}

/// A limit to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limit {
    pub wbps: Option<u64>,
    pub wiops: Option<u64>,
}

/// A full snapshot of every watched cgroup's counters, with deltas.
pub struct Reader {
    root: PathBuf,
    last: BTreeMap<String, IoStat>,
}

impl Reader {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Reader {
            root: root.into(),
            last: BTreeMap::new(),
        }
    }

    /// Read the given cgroups, returning non-negative deltas since the previous
    /// call.  A cgroup seen for the first time reports zero (we have no
    /// baseline) rather than its lifetime total — charging a lifetime total to
    /// today's budget would instantly bankrupt every app on first boot.
    pub fn poll(&mut self, paths: impl IntoIterator<Item = String>) -> BTreeMap<String, IoStat> {
        let mut deltas = BTreeMap::new();
        for path in paths {
            let cg = Cgroup::new(&self.root, &path);
            let Ok(now) = cg.read_stat() else { continue };
            let prev = self.last.get(&path).copied();
            let delta = match prev {
                Some(p) => IoStat {
                    wbytes: now.wbytes.saturating_sub(p.wbytes),
                    wios: now.wios.saturating_sub(p.wios),
                },
                None => IoStat::default(),
            };
            self.last.insert(path.clone(), now);
            deltas.insert(path, delta);
        }
        deltas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_device() {
        let s = "8:0 rbytes=1000 wbytes=5000 rios=10 wios=20 dbytes=0 dios=0\n";
        let st = parse_io_stat(s);
        assert_eq!(st.wbytes, 5000);
        assert_eq!(st.wios, 20);
    }

    #[test]
    fn sums_multiple_devices() {
        let s = "8:0 rbytes=0 wbytes=1000 rios=0 wios=5 dbytes=0 dios=0\n\
                 8:16 rbytes=0 wbytes=2000 rios=0 wios=7 dbytes=0 dios=0\n";
        let st = parse_io_stat(s);
        assert_eq!(st.wbytes, 3000);
        assert_eq!(st.wios, 12);
    }

    #[test]
    fn ignores_unknown_fields_and_garbage() {
        let s = "8:0 wbytes=100 future=1\nnot-a-device wbytes=999\n8:1 wbytes=abc\n";
        let st = parse_io_stat(s);
        assert_eq!(st.wbytes, 100);
        assert_eq!(st.wios, 0);
    }

    #[test]
    fn empty_stat_is_zero() {
        assert_eq!(parse_io_stat(""), IoStat::default());
    }

    #[test]
    fn device_id_parses() {
        assert_eq!(DeviceId::parse_dev("179:0\n"), Some(DeviceId::new(179, 0)));
        assert_eq!(DeviceId::parse_dev("garbage"), None);
    }

    #[test]
    fn fmt_limit_never_emits_zero() {
        assert_eq!(fmt_limit(None), "max");
        assert_eq!(fmt_limit(Some(0)), "1");
        assert_eq!(fmt_limit(Some(4096)), "4096");
    }

    #[test]
    fn reader_first_sight_is_zero_then_delta() {
        // A first observation must not charge the lifetime total.
        let dir = std::env::temp_dir().join(format!("flashgov-test-{}", std::process::id()));
        let cgdir = dir.join("apps/nav");
        fs::create_dir_all(&cgdir).unwrap();
        fs::write(cgdir.join("io.stat"), "8:0 wbytes=100000 wios=10\n").unwrap();

        let mut r = Reader::new(&dir);
        let first = r.poll(["/apps/nav".to_string()]);
        assert_eq!(first["/apps/nav"].wbytes, 0, "first sight must not charge lifetime");

        fs::write(cgdir.join("io.stat"), "8:0 wbytes=140000 wios=13\n").unwrap();
        let second = r.poll(["/apps/nav".to_string()]);
        assert_eq!(second["/apps/nav"].wbytes, 40000);
        assert_eq!(second["/apps/nav"].wios, 3);

        // A counter reset (cgroup recreated) must clamp to zero, not go negative.
        fs::write(cgdir.join("io.stat"), "8:0 wbytes=5 wios=1\n").unwrap();
        let third = r.poll(["/apps/nav".to_string()]);
        assert_eq!(third["/apps/nav"].wbytes, 0);

        fs::remove_dir_all(&dir).ok();
    }
}
