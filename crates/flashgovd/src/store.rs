//! Crash-safe persistence of the governor's state image.
//!
//! # The requirement: the governor must not be a writer
//!
//! A daemon that saves its state every tick becomes exactly the problem it was
//! installed to solve.  So the persistence policy is deliberately stingy:
//!
//! * **Rare.** At most once per `persist_secs` (default 10 min), and only when
//!   the image has materially changed.  A parked car costs zero writes.
//! * **Small.** The image is a fixed 4 KiB — one eMMC page — so a save is one
//!   program cycle regardless of how many apps are watched.
//! * **Atomic.** `write tmp → fsync → rename → fsync(dir)`.  A power cut at any
//!   point leaves either the old image or the new one, never a torn file.  The
//!   previous image is retained as `.bak`, so a corrupt rename target can be
//!   recovered.
//!
//! # Where the file lives
//!
//! The image is tiny and rewritten rarely, but it is still flash.  Ideally it
//! lives on the same medium we are protecting (there is no other on many head
//! units); the write budget it consumes is a rounding error — ~9 MB/year at the
//! default cadence — which is why `flashgovd` reports its own lifetime write
//! total and refuses to save more often than a hard floor.

use flashgov_core::snapshot::{materially_changed, Image, IMAGE_LEN};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub struct Store {
    dir: PathBuf,
    last_saved_generation: u64,
    last_saved: Option<Image>,
    /// Total bytes this daemon has written, for honest self-reporting.
    pub lifetime_written: u64,
    /// Number of saves performed.
    pub saves: u64,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store {
            dir: dir.into(),
            last_saved_generation: 0,
            last_saved: None,
            lifetime_written: 0,
            saves: 0,
        }
    }

    fn image_path(&self) -> PathBuf {
        self.dir.join("state.img")
    }
    fn tmp_path(&self) -> PathBuf {
        self.dir.join("state.img.tmp")
    }
    fn bak_path(&self) -> PathBuf {
        self.dir.join("state.img.bak")
    }

    /// Load the last image.  Tries the primary then the backup.  Any failure —
    /// missing, truncated, bad checksum — returns `None`, which the caller
    /// treats as "first boot": wear is re-read from EXT_CSD and per-app totals
    /// restart.  That is safe because wear is ratcheted on the device itself.
    pub fn load(&mut self) -> Option<Image> {
        for path in [self.image_path(), self.bak_path()] {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(img) = Image::decode(&bytes) {
                    self.last_saved_generation = img.generation;
                    self.last_saved = Some(img.clone());
                    return Some(img);
                }
            }
        }
        None
    }

    /// Save if needed.  Returns `true` if a write actually happened.
    ///
    /// `materially_changed` compares coarse buckets so that the few bytes of
    /// drift between ticks never trigger a save; only real changes (wear stage,
    /// a freeze, a day rollover, a megabyte of progress) do.
    pub fn save_if_changed(&mut self, image: &Image) -> io::Result<bool> {
        if let Some(prev) = &self.last_saved {
            if !materially_changed(prev, image) {
                return Ok(false);
            }
        }
        let mut img = image.clone();
        img.generation = self.last_saved_generation + 1;
        let bytes = img
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        fs::create_dir_all(&self.dir)?;

        // Keep the previous good image as a backup before replacing.
        if self.image_path().exists() {
            let _ = fs::copy(self.image_path(), self.bak_path());
        }

        let tmp = self.tmp_path();
        {
            let mut f = File::options()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.image_path())?;
        // fsync the directory so the rename itself is durable.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }

        self.last_saved_generation = img.generation;
        self.last_saved = Some(img);
        self.lifetime_written = self.lifetime_written.saturating_add(bytes.len() as u64);
        self.saves += 1;
        Ok(true)
    }

    #[allow(dead_code)]
    pub fn image_len(&self) -> usize {
        IMAGE_LEN
    }

    #[allow(dead_code)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flashgov_core::snapshot::PersistedApp;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "flashgov-store-{}-{}-{}",
            std::process::id(),
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn img(life: u16) -> Image {
        Image {
            generation: 0,
            saved_at_ms: 1,
            first_boot_ms: 0,
            life_permille: life,
            pre_eol: 1,
            lifetime_host_bytes: 1 << 30,
            configured_tbw_bytes: 3 << 40,
            stage: 0,
            apps: vec![PersistedApp {
                package: "com.x".into(),
                lifetime_bytes: 1 << 20,
                spent_today: 0,
                balance: 0,
                day: 0,
                frozen: false,
            }],
        }
    }

    #[test]
    fn save_and_load_roundtrip() {
        let d = tmpdir("rt");
        let mut s = Store::new(&d);
        assert!(s.load().is_none());
        assert!(s.save_if_changed(&img(500)).unwrap());
        let mut s2 = Store::new(&d);
        let got = s2.load().unwrap();
        assert_eq!(got.life_permille, 500);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn unchanged_image_does_not_write() {
        let d = tmpdir("idle");
        let mut s = Store::new(&d);
        let i = img(500);
        assert!(s.save_if_changed(&i).unwrap());
        // Same image again: no write, lifetime_written unchanged.
        let before = s.lifetime_written;
        assert!(!s.save_if_changed(&i).unwrap());
        assert_eq!(s.lifetime_written, before);
        // Material change: writes.
        assert!(s.save_if_changed(&img(700)).unwrap());
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn corrupt_primary_falls_back_to_backup() {
        let d = tmpdir("bak");
        let mut s = Store::new(&d);
        s.save_if_changed(&img(500)).unwrap();
        s.save_if_changed(&img(700)).unwrap(); // backup now holds 500
        // Corrupt the primary.
        fs::write(d.join("state.img"), b"garbage").unwrap();
        let mut s2 = Store::new(&d);
        let got = s2.load().unwrap();
        assert_eq!(got.life_permille, 500, "must recover the previous good image");
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn generation_increments() {
        let d = tmpdir("gen");
        let mut s = Store::new(&d);
        s.save_if_changed(&img(100)).unwrap();
        s.save_if_changed(&img(200)).unwrap();
        let mut s2 = Store::new(&d);
        let got = s2.load().unwrap();
        assert_eq!(got.generation, 2);
        fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn save_is_one_page() {
        let d = tmpdir("len");
        let mut s = Store::new(&d);
        s.save_if_changed(&img(500)).unwrap();
        let len = fs::metadata(d.join("state.img")).unwrap().len();
        assert_eq!(len as usize, IMAGE_LEN);
        assert_eq!(s.lifetime_written, IMAGE_LEN as u64);
        fs::remove_dir_all(&d).ok();
    }
}
