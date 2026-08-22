//! Cerberus persistence, audit and telemetry — Phase 5 of the build plan.
//!
//! Local `SQLite` storage with non-blocking async writes,
//! configurable retention and a zero-leak secret guarantee.

pub mod event;
pub mod stats;
pub mod store;
