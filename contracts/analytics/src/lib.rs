//! qed-analytics: visit counts for qed.coproduct.dev.
//!
//! - [`core`]: the state machine and the publisher, translated to Lean
//!   (`lean/`) and proved there.
//! - [`paths`]: the allow-list of site paths and the beacon's wire format.
//! - [`noise`]: the noise sampler (fair coins from the operating system).
//! - [`store`]: the collector's state on disk and its weekly publication.
//! - [`server`]: the loopback HTTP endpoint Caddy forwards beacons to.
//!
//! contracts/analytics/README.md says what is proved, what is stored, and
//! what the proofs do not cover.
pub mod core;
pub mod noise;
pub mod paths;
pub mod server;
pub mod store;
