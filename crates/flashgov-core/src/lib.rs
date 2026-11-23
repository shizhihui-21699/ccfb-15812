//! Platform-free core of the flash write governor.
//!
//! Everything in this crate is deterministic and free of syscalls: the clock is
//! injected, observations are passed in, decisions are returned.  That keeps the
//! policy engine unit-testable on a developer laptop and lets the simulator in
//! `flashgov-sim` run years of device life in a few seconds.
//!
//! The layers are:
//!
//! * [`units`] — byte/rate formatting and small integer helpers.
//! * [`wear`] — the device endurance model and the life-stage ladder.
//! * [`budget`] — the per-app token bucket that turns a daily allowance into an
//!   instantaneous byte-per-second cap for `io.max`.
//! * [`config`] — the on-disk configuration schema.
//! * [`gov`] — attribution, adaptation and the per-tick decision engine.
//! * [`snapshot`] — a fixed-size, crash-safe state image.

pub mod budget;
pub mod config;
pub mod gov;
pub mod snapshot;
pub mod units;
pub mod wear;

pub use config::Config;
pub use budget::Cap;
pub use gov::{Decision, Governor, TickInput, TickOutput};
pub use wear::{PreEol, Stage, WearState};
