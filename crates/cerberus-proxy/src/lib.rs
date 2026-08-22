//! Cerberus proxy core — Phase 3 of the build plan.
//!
//! Provider-agnostic reverse proxy that scans and redacts egress
//! toward any LLM. Reuses the detection engine from `cerberus-engine`.

#![allow(unknown_lints)]

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
