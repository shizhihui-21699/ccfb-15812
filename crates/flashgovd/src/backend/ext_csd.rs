//! Reading the device's own wear report from eMMC EXT_CSD.
//!
//! # The problem with trusting a datasheet
//!
//! An integrator writes `target_tbw_gib` into the config from whatever the part
//! datasheet said, and that number is frequently wrong: parts are binned
//! differently, some ship with more spare area, and the datasheet TBW is under a
//! particular workload (usually sequential).  Worse, the *same* board design may
//! ship with two different parts over a production run.
//!
//! The eMMC itself knows how worn it is.  EXT_CSD exposes:
//!
//! * byte 267 `PRE_EOL_INFO`   — 0 unknown, 1 normal (<80 %), 2 warning
//!   (80–90 %), 3 urgent (>90 %).
//! * byte 268 `DEVICE_LIFE_TIME_EST_TYP_A`
//! * byte 269 `DEVICE_LIFE_TIME_EST_TYP_B` — each a bucket: 0x01..=0x0A mean
//!   0–10 % … 90–100 % of the rated endurance consumed, 0x0B means exceeded.
//!
//! Type A and Type B are different *regions* of the die (typically SLC cache vs
//! MLC/TLC main area, or two partitions).  Whichever wears out first is what
//! kills the device, so we take the worse of the two.
//!
//! # How to read it
//!
//! Two routes, tried in order:
//!
//! 1. **`/sys/block/<dev>/device/life_time`** and the sibling
//!    `pre_eol_info` on kernels that export an `mmc` sysfs attribute.  Cheapest
//!    and needs no privileges.
//! 2. **`MMC_IOC_CMD` ioctl** with `CMD6`/`CMD8`-style EXT_CSD read, as used by
//!    `mmc-utils`.  This is what works on most automotive kernels even when the
//!    sysfs attributes are absent.  It requires opening the block device
//!    (read-only is enough) and, typically, `CAP_SYS_RAWIO`.
//!
//! Both are best-effort: if neither works we return `WearSample::default()`
//! (all `None`) and the governor falls back to counting host writes against the
//! configured TBW.  That fallback is still far better than no governor.

#![allow(dead_code)] // the ioctl route is compiled only on Linux

use flashgov_core::wear::WearSample;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// EXT_CSD byte offsets we care about (eMMC 5.x JEDEC standard).
pub mod offsets {
    pub const PRE_EOL_INFO: usize = 267;
    pub const LIFE_TIME_EST_TYP_A: usize = 268;
    pub const LIFE_TIME_EST_TYP_B: usize = 269;
    pub const LEN: usize = 512;
}

/// A source of wear samples.
pub trait WearSource {
    /// Read the current sample.  `Ok(default)` means "the device does not
    /// report wear", which is a valid and common answer, not an error.
    fn sample(&mut self) -> io::Result<WearSample>;
    fn describe(&self) -> String;
}

/// Sysfs-backed reader: parses `/sys/block/<dev>/device/{pre_eol_info,life_time}`.
pub struct SysfsWear {
    pre_eol: PathBuf,
    life_time: PathBuf,
}

impl SysfsWear {
    pub fn for_block(device: &Path) -> Option<Self> {
        let name = device.file_name()?.to_str()?;
        let base = Path::new("/sys/block").join(name).join("device");
        let pre_eol = base.join("pre_eol_info");
        let life_time = base.join("life_time");
        if pre_eol.exists() || life_time.exists() {
            Some(SysfsWear { pre_eol, life_time })
        } else {
            None
        }
    }

    /// `life_time` in sysfs is usually printed as two hex bytes,
    /// e.g. `0x01 0x02` (Type A then Type B), or two decimal values on some
    /// vendor kernels.  Parse both defensively.
    fn parse_life_time(s: &str) -> (Option<u8>, Option<u8>) {
        let mut vals: Vec<Option<u8>> = Vec::new();
        for tok in s.split_whitespace() {
            if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
                vals.push(u8::from_str_radix(hex, 16).ok());
            } else {
                vals.push(tok.parse::<u8>().ok());
            }
        }
        match vals.as_slice() {
            [a, b] => (*a, *b),
            [a] => (*a, None),
            _ => (None, None),
        }
    }

    fn parse_pre_eol(s: &str) -> Option<u8> {
        let t = s.trim();
        if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u8::from_str_radix(hex, 16).ok()
        } else {
            t.parse::<u8>().ok()
        }
    }
}

impl WearSource for SysfsWear {
    fn sample(&mut self) -> io::Result<WearSample> {
        let life = fs::read_to_string(&self.life_time).unwrap_or_default();
        let (a, b) = Self::parse_life_time(&life);
        let pre = fs::read_to_string(&self.pre_eol)
            .ok()
            .and_then(|s| Self::parse_pre_eol(&s));
        Ok(WearSample {
            life_a: a.filter(|v| *v != 0),
            life_b: b.filter(|v| *v != 0),
            pre_eol: pre,
        })
    }

    fn describe(&self) -> String {
        format!("sysfs ({})", self.life_time.display())
    }
}

/// Parse a 512-byte EXT_CSD image into our sample.  Split out so it is testable
/// without a device.
pub fn parse_ext_csd(csd: &[u8]) -> WearSample {
    if csd.len() < offsets::LEN {
        return WearSample::default();
    }
    let nonzero = |b: u8| if b == 0 { None } else { Some(b) };
    WearSample {
        life_a: nonzero(csd[offsets::LIFE_TIME_EST_TYP_A]),
        life_b: nonzero(csd[offsets::LIFE_TIME_EST_TYP_B]),
        pre_eol: nonzero(csd[offsets::PRE_EOL_INFO]),
    }
}

/// A reader that tries several sources in order, so a box that lacks sysfs
/// attributes can still use the ioctl and vice versa.
pub struct ChainWear {
    sources: Vec<Box<dyn WearSource>>,
}

impl ChainWear {
    pub fn new(sources: Vec<Box<dyn WearSource>>) -> Self {
        ChainWear { sources }
    }

    /// Build the best chain available for a device path.
    pub fn discover(device: Option<&Path>) -> Self {
        let mut sources: Vec<Box<dyn WearSource>> = Vec::new();
        let dev = device
            .map(|p| p.to_path_buf())
            .or_else(default_mmc_device);
        if let Some(dev) = &dev {
            if let Some(s) = SysfsWear::for_block(dev) {
                sources.push(Box::new(s));
            }
            #[cfg(target_os = "linux")]
            sources.push(Box::new(IoctlWear::new(dev.clone())));
        }
        ChainWear { sources }
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

impl WearSource for ChainWear {
    fn sample(&mut self) -> io::Result<WearSample> {
        for s in &mut self.sources {
            if let Ok(sample) = s.sample() {
                if !sample.is_empty() {
                    return Ok(sample);
                }
            }
        }
        Ok(WearSample::default())
    }

    fn describe(&self) -> String {
        if self.sources.is_empty() {
            "none (falling back to configured TBW)".into()
        } else {
            self.sources
                .iter()
                .map(|s| s.describe())
                .collect::<Vec<_>>()
                .join(" -> ")
        }
    }
}

/// Find the first `mmcblk*` device, which is where the head unit's soldered
/// eMMC is.  Falls back to `None`.
pub fn default_mmc_device() -> Option<PathBuf> {
    let entries = fs::read_dir("/sys/block").ok()?;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("mmcblk") && !name.contains("boot") && !name.contains("rpmb") {
            return Some(PathBuf::from("/dev").join(name.as_ref()));
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Linux MMC ioctl route
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct IoctlWear {
    device: PathBuf,
}

#[cfg(target_os = "linux")]
impl IoctlWear {
    pub fn new(device: PathBuf) -> Self {
        IoctlWear { device }
    }
}

#[cfg(target_os = "linux")]
mod ioctl {
    // MMC ioctl ABI, mirroring <linux/mmc/ioctl.h>.
    pub const MMC_BLOCK_MAJOR: u32 = 179;
    pub const MMC_IOC_CMD: u64 = 0xC048_B300; // _IOWR(0xB3, 0, struct mmc_ioc_cmd), 0x48 bytes
    pub const MMC_RSP_PRESENT: u32 = 1 << 0;
    pub const MMC_RSP_136: u32 = 1 << 1;
    pub const MMC_RSP_CRC: u32 = 1 << 2;
    pub const MMC_RSP_BUSY: u32 = 1 << 3;
    pub const MMC_RSP_OPCODE: u32 = 1 << 4;
    pub const MMC_CMD_ADTC: u32 = 1 << 5;
    pub const MMC_RSP_R1: u32 = 1 << 6;
    pub const MMC_RSP_R1B: u32 = 1 << 7;
    pub const MMC_RSP_SPI_SDI: u32 = 1 << 8;
    pub const MMC_GO_IDLE_STATE: u32 = 0;
    pub const MMC_SEND_EXT_CSD: u32 = 8;
    pub const MMC_SWITCH: u32 = 6;

    /// `struct mmc_ioc_cmd`.  Layout must match the kernel exactly; the target
    /// is 64-bit Linux, which is what automotive SoCs use.
    #[repr(C)]
    #[derive(Default)]
    pub struct MmcIocCmd {
        pub write_flag: i32,
        pub is_acmd: i32,
        pub opcode: u32,
        pub arg: u32,
        pub response: [u32; 4],
        pub flags: u32,
        pub blksz: u32,
        pub blocks: u32,
        pub postsleep_min_us: u32,
        pub postsleep_max_us: u32,
        pub data_timeout_ns: u32,
        pub cmd_timeout_ms: u32,
        pub __pad: u64,
        pub data_ptr: u64,
    }

    extern "C" {
        pub fn ioctl(fd: i32, request: u64, ...) -> i32;
        pub fn open(path: *const i8, flags: i32, ...) -> i32;
        pub fn close(fd: i32) -> i32;
    }
    pub const O_RDONLY: i32 = 0;
}

/// Read EXT_CSD over the MMC ioctl.  Best-effort: any failure yields an empty
/// sample so the chain falls through to the next source.
#[cfg(target_os = "linux")]
impl WearSource for IoctlWear {
    fn sample(&mut self) -> io::Result<WearSample> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use ioctl::*;

        let cpath = CString::new(self.device.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad device path"))?;
        let fd = unsafe { open(cpath.as_ptr(), O_RDONLY) };
        if fd < 0 {
            return Ok(WearSample::default());
        }

        let mut buf = [0u8; 512];
        let mut cmd = MmcIocCmd {
            opcode: MMC_SEND_EXT_CSD,
            flags: MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE | MMC_CMD_ADTC | MMC_RSP_R1,
            blksz: 512,
            blocks: 1,
            data_timeout_ns: 1_000_000_000,
            cmd_timeout_ms: 1000,
            data_ptr: buf.as_mut_ptr() as u64,
            ..Default::default()
        };
        let rc = unsafe { ioctl(fd, MMC_IOC_CMD, &mut cmd as *mut MmcIocCmd) };
        unsafe { close(fd) };
        if rc < 0 {
            return Ok(WearSample::default());
        }
        Ok(parse_ext_csd(&buf))
    }

    fn describe(&self) -> String {
        format!("mmc ioctl ({})", self.device.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn life_time_parses_hex() {
        assert_eq!(SysfsWear::parse_life_time("0x01 0x02\n"), (Some(1), Some(2)));
    }

    #[test]
    fn life_time_parses_decimal() {
        assert_eq!(SysfsWear::parse_life_time("1 2\n"), (Some(1), Some(2)));
    }

    #[test]
    fn life_time_single_value() {
        assert_eq!(SysfsWear::parse_life_time("0x05"), (Some(5), None));
    }

    #[test]
    fn pre_eol_parses() {
        assert_eq!(SysfsWear::parse_pre_eol("0x02\n"), Some(2));
        assert_eq!(SysfsWear::parse_pre_eol("3\n"), Some(3));
    }

    #[test]
    fn ext_csd_offsets() {
        let mut csd = [0u8; 512];
        csd[267] = 0x03; // urgent
        csd[268] = 0x07; // Typ A 60-70%
        csd[269] = 0x09; // Typ B 80-90%
        let s = parse_ext_csd(&csd);
        assert_eq!(s.pre_eol, Some(3));
        assert_eq!(s.life_a, Some(7));
        assert_eq!(s.life_b, Some(9));
        // Worst-case life is the worse type: 900 permille.
        assert_eq!(s.life_permille(), Some(900));
    }

    #[test]
    fn zero_means_unreported() {
        let csd = [0u8; 512];
        let s = parse_ext_csd(&csd);
        assert!(s.is_empty());
        assert_eq!(s.life_permille(), None);
    }

    #[test]
    fn short_buffer_is_safe() {
        assert!(parse_ext_csd(&[1, 2, 3]).is_empty());
    }

    #[test]
    fn empty_chain_reports_none() {
        let mut c = ChainWear::new(vec![]);
        assert!(c.describe().contains("none"));
        assert!(c.sample().unwrap().is_empty());
    }
}
