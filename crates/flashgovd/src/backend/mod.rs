//! Linux kernel interfaces used by the governor.
//!
//! Everything that touches the OS lives here, behind small traits, so the
//! decision engine in `flashgov-core` stays pure and testable and so the daemon
//! can be exercised on a developer laptop with a fake backend.

pub mod cgroup;
pub mod clock;
pub mod ext_csd;


