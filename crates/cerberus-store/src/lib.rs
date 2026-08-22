//! Cerberus persistence, audit and telemetry — Fase 5 del build plan.
//!
//! Almacenamiento local `SQLite` con escritura async no bloqueante,
//! retención configurable y garantía de fuga cero de secretos.

pub mod event;
pub mod stats;
pub mod store;
