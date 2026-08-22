//! Cerberus detection engine — pure library that turns text into findings.
//!
//! # Fase 1 — rule-loader
//!
//! Loads rules from JSON/YAML, compiles them into the hybrid AC+regex engine
//! (decided in F0, see `evidence/f0/decision-motor-matching.md`), and scans
//! text producing [`Finding`]s with SHA-256 hashed values (never the raw secret).
//!
//! This crate is **pure** — no network, no persistence. Later fases build on it.

pub mod break_glass;
pub mod constraints;
pub mod engine;
pub mod entropy;
pub mod feedback;
pub mod loader;
pub mod multiline;
/// In-place text redaction engine for transforming findings into redacted output.
pub mod redact;
pub mod rule;
pub mod scan;
pub mod validator;
/// Reversible vault for opt-in reversible redaction.
pub mod vault;
