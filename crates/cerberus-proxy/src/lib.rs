//! Cerberus proxy core — Fase 3 del build plan.
//!
//! Reverse proxy provider-agnostic que escanea y redacta el egress
//! hacia cualquier LLM. Reusa el motor de detección de `cerberus-engine`.

pub mod adapters;
pub mod api;
pub mod config;
pub mod decoder;
pub mod detection_policy;
pub mod forward;
pub mod health;
pub mod json_redact;
pub mod log;
pub mod policy;
pub mod proxy;
pub mod shadow;
/// Test utilities for proxy integration tests.
///
/// Only used by integration tests in `tests/` directory.
/// Not intended for end-user consumption.
pub mod test_utils;
