//! Cerberus rule packs — Phase 7 of the build plan.
//!
//! Versioned and signed detection rule packs,
//! with Ed25519 signature verification and auto-update with rollback.

pub mod default_pack;
pub mod license;
pub mod pack;
pub mod telemetry;
pub mod updater;
pub mod wire;
