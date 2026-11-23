//! Crash-safe state image.
//!
//! The governor must not itself be a significant writer (problem 6 in the
//! brief), so its own persistence is designed to be *tiny and rare*:
//!
//! * The image is a fixed 4 KiB, so a save is exactly one page — one eMMC
//!   program cycle, not one per app per tick.
//! * It is written at most every `persist_secs` (default 10 min) and only when
//!   the state actually changed, so a parked car costs zero writes.
//! * The write is `write tmp; fsync; rename; fsync(dir)` against a file on a
//!   filesystem the governor chooses, and the previous image is kept, so a
//!   power cut mid-save can never leave an unreadable state — worst case we
//!   lose the last 10 minutes of accounting, and because wear is ratcheted and
//!   re-read from EXT_CSD on every boot, that is not cumulative.
//!
//! The encoding is a hand-rolled fixed layout rather than `serde_json`:
//! deterministic size, no allocation at save time, and it can be read back by
//! the bootloader-side recovery tool without a JSON parser.

use serde::{Deserialize, Serialize};

pub const MAGIC: [u8; 4] = *b"FGV1";
pub const IMAGE_LEN: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PersistedApp {
    pub package: String,
    pub lifetime_bytes: u64,
    pub spent_today: u64,
    pub balance: i64,
    pub day: i64,
    pub frozen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Image {
    pub generation: u64,
    pub saved_at_ms: i64,
    pub first_boot_ms: i64,
    pub life_permille: u16,
    pub pre_eol: u8,
    pub lifetime_host_bytes: u64,
    pub configured_tbw_bytes: u64,
    pub stage: u8,
    pub apps: Vec<PersistedApp>,
}

/// Errors from decode.  A decode failure is never fatal: the daemon falls back
/// to a fresh image and re-reads wear from EXT_CSD, which is authoritative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    BadChecksum,
    Truncated,
    BadString,
    TooManyApps,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DecodeError::TooShort => "image shorter than header",
            DecodeError::BadMagic => "bad magic",
            DecodeError::BadChecksum => "checksum mismatch",
            DecodeError::Truncated => "image truncated",
            DecodeError::BadString => "invalid utf-8 / length",
            DecodeError::TooManyApps => "too many apps for image",
        };
        f.write_str(s)
    }
}

const MAX_APPS: usize = 32;
const MAX_PKG: usize = 64;
const HEADER_LEN: usize = 32;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

struct Writer<'a> {
    buf: &'a mut [u8],
    off: usize,
    overflow: bool,
}

impl<'a> Writer<'a> {
    fn put(&mut self, bytes: &[u8]) {
        if self.off + bytes.len() > self.buf.len() {
            self.overflow = true;
            return;
        }
        self.buf[self.off..self.off + bytes.len()].copy_from_slice(bytes);
        self.off += bytes.len();
    }
    fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.put(&v.to_le_bytes());
    }
    fn string(&mut self, s: &str) -> Result<(), DecodeError> {
        let b = s.as_bytes();
        if b.len() > MAX_PKG {
            return Err(DecodeError::BadString);
        }
        self.u8(b.len() as u8);
        self.put(b);
        Ok(())
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.off + n > self.buf.len() {
            return Err(DecodeError::Truncated);
        }
        let s = &self.buf[self.off..self.off + n];
        self.off += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<String, DecodeError> {
        let n = self.u8()? as usize;
        if n > MAX_PKG {
            return Err(DecodeError::BadString);
        }
        let b = self.take(n)?;
        String::from_utf8(b.to_vec()).map_err(|_| DecodeError::BadString)
    }
}

impl Image {
    /// Serialize into a caller-provided 4 KiB buffer.  Returns the number of
    /// bytes written (always `IMAGE_LEN` on success).
    pub fn encode_into(&self, out: &mut [u8; IMAGE_LEN]) -> Result<usize, DecodeError> {
        if self.apps.len() > MAX_APPS {
            return Err(DecodeError::TooManyApps);
        }
        out.fill(0);
        let mut w = Writer {
            buf: out,
            off: 0,
            overflow: false,
        };
        w.put(&MAGIC);
        // generation at header[4..12], checksum at [12..20], reserved to 32.
        w.u64(self.generation);
        w.put(&[0u8; 8]); // checksum placeholder
        w.put(&[0u8; 12]); // reserved, keeps header 32 B aligned
        w.i64(self.saved_at_ms);
        w.i64(self.first_boot_ms);
        w.u16(self.life_permille);
        w.u8(self.pre_eol);
        w.u8(self.stage);
        w.u64(self.lifetime_host_bytes);
        w.u64(self.configured_tbw_bytes);
        w.u8(self.apps.len() as u8);
        for a in &self.apps {
            w.string(&a.package)?;
            w.u64(a.lifetime_bytes);
            w.u64(a.spent_today);
            w.i64(a.balance);
            w.i64(a.day);
            w.u8(a.frozen as u8);
        }
        if w.overflow {
            return Err(DecodeError::TooManyApps);
        }
        let end = w.off;
        let payload_len = (end - HEADER_LEN) as u32;
        out[20..24].copy_from_slice(&payload_len.to_le_bytes());
        let sum = fnv1a(&out[HEADER_LEN..end]);
        out[12..20].copy_from_slice(&sum.to_le_bytes());
        Ok(IMAGE_LEN)
    }

    pub fn encode(&self) -> Result<[u8; IMAGE_LEN], DecodeError> {
        let mut out = [0u8; IMAGE_LEN];
        self.encode_into(&mut out)?;
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Image, DecodeError> {
        if buf.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if buf[0..4] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let want = u64::from_le_bytes(buf[12..20].try_into().unwrap());
        let payload_len = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;
        if HEADER_LEN + payload_len > buf.len() {
            return Err(DecodeError::Truncated);
        }
        let got = fnv1a(&buf[HEADER_LEN..HEADER_LEN + payload_len]);
        if want != got {
            return Err(DecodeError::BadChecksum);
        }
        let mut r = Reader {
            buf,
            off: HEADER_LEN,
        };
        let saved_at_ms = r.i64()?;
        let first_boot_ms = r.i64()?;
        let life_permille = r.u16()?;
        let pre_eol = r.u8()?;
        let stage = r.u8()?;
        let lifetime_host_bytes = r.u64()?;
        let configured_tbw_bytes = r.u64()?;
        let n = r.u8()? as usize;
        if n > MAX_APPS {
            return Err(DecodeError::TooManyApps);
        }
        let mut apps = Vec::with_capacity(n);
        for _ in 0..n {
            let package = r.string()?;
            let lifetime_bytes = r.u64()?;
            let spent_today = r.u64()?;
            let balance = r.i64()?;
            let day = r.i64()?;
            let frozen = r.u8()? != 0;
            apps.push(PersistedApp {
                package,
                lifetime_bytes,
                spent_today,
                balance,
                day,
                frozen,
            });
        }
        let generation = u64::from_le_bytes(buf[4..12].try_into().unwrap());
        Ok(Image {
            generation,
            saved_at_ms,
            first_boot_ms,
            life_permille,
            pre_eol,
            stage,
            lifetime_host_bytes,
            configured_tbw_bytes,
            apps,
        })
    }
}

/// Cheap "has anything materially changed" check so an idle car never pays for
/// a flash write.  Only fields that matter for correctness across a power cut
/// are compared: lifetime totals move by a byte or two continuously and would
/// defeat the point, so they are compared in coarse 1 MiB buckets.
pub fn materially_changed(a: &Image, b: &Image) -> bool {
    const BUCKET: u64 = 1 << 20;
    if a.life_permille != b.life_permille
        || a.pre_eol != b.pre_eol
        || a.stage != b.stage
        || a.first_boot_ms != b.first_boot_ms
    {
        return true;
    }
    if a.lifetime_host_bytes / BUCKET != b.lifetime_host_bytes / BUCKET {
        return true;
    }
    if a.apps.len() != b.apps.len() {
        return true;
    }
    let mut ba: Vec<_> = a.apps.iter().collect();
    let mut bb: Vec<_> = b.apps.iter().collect();
    ba.sort_by(|x, y| x.package.cmp(&y.package));
    bb.sort_by(|x, y| x.package.cmp(&y.package));
    for (x, y) in ba.iter().zip(bb.iter()) {
        if x.package != y.package
            || x.frozen != y.frozen
            || x.day != y.day
            || x.lifetime_bytes / BUCKET != y.lifetime_bytes / BUCKET
            || x.spent_today / BUCKET != y.spent_today / BUCKET
            // balance is what actually gates writes; compare it exactly but
            // tolerate the natural refill drift of one minute's quota.
            || (x.balance - y.balance).unsigned_abs() > 1 << 20
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Image {
        Image {
            generation: 7,
            saved_at_ms: 1_700_000_000_000,
            first_boot_ms: 1_600_000_000_000,
            life_permille: 620,
            pre_eol: 2,
            lifetime_host_bytes: 42 << 30,
            configured_tbw_bytes: 120 << 30,
            stage: 1,
            apps: vec![
                PersistedApp {
                    package: "com.acme.nav".into(),
                    lifetime_bytes: 30 << 30,
                    spent_today: 1 << 30,
                    balance: -(3 << 20),
                    day: 19_000,
                    frozen: false,
                },
                PersistedApp {
                    package: "com.acme.rogue".into(),
                    lifetime_bytes: 90 << 30,
                    spent_today: 12 << 20,
                    balance: -500,
                    day: 19_000,
                    frozen: true,
                },
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let i = image();
        let bytes = i.encode().unwrap();
        assert_eq!(bytes.len(), IMAGE_LEN);
        let back = Image::decode(&bytes).unwrap();
        assert_eq!(back, i);
    }

    #[test]
    fn image_is_exactly_one_page() {
        // A save must cost one program cycle, not an unbounded write.
        assert_eq!(IMAGE_LEN, 4096);
    }

    #[test]
    fn rejects_corruption() {
        let mut bytes = image().encode().unwrap();
        // Corrupt a byte inside the checksummed payload (header is 32 B and the
        // payload starts there), not in the zero padding.
        bytes[HEADER_LEN + 4] ^= 0xff;
        assert_eq!(Image::decode(&bytes), Err(DecodeError::BadChecksum));
        assert_eq!(Image::decode(b"xx"), Err(DecodeError::TooShort));
        let mut b2 = image().encode().unwrap();
        b2[0] = b'X';
        assert_eq!(Image::decode(&b2), Err(DecodeError::BadMagic));
    }

    #[test]
    fn idle_ticks_do_not_trigger_saves() {
        let mut a = image();
        let b = image();
        assert!(!materially_changed(&a, &b));
        a.apps[0].lifetime_bytes += 1000; // < 1 MiB drift
        assert!(!materially_changed(&a, &b));
        a.apps[0].lifetime_bytes += 2 << 20;
        assert!(materially_changed(&a, &b));
    }

    #[test]
    fn wear_change_triggers_save() {
        let a = image();
        let mut b = image();
        b.life_permille = 700;
        assert!(materially_changed(&a, &b));
    }

    #[test]
    fn too_many_apps_rejected() {
        let mut i = image();
        for n in 0..MAX_APPS {
            i.apps.push(PersistedApp {
                package: format!("p{n}"),
                ..Default::default()
            });
        }
        assert_eq!(i.encode(), Err(DecodeError::TooManyApps));
    }
}
