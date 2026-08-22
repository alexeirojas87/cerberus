//! Cerberus rule packs — Fase 7 del build plan.
//!
//! Paquetes versionados y firmados de reglas de detección,
//! con verificación de firma Ed25519 y auto-update con rollback.

pub mod default_pack;
pub mod license;
pub mod pack;
pub mod telemetry;
pub mod updater;
pub mod wire;
