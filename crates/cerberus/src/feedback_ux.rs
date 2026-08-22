//! Dev feedback — notifications and CLI messages.
//!
//! When something is redacted or blocked, the dev is notified via:
//! - A message on the command line (stderr, the daemon runs in the foreground)
//! - A desktop notification (macOS/Linux via notify-rust, rate-limited;
//!   on unsupported platforms the fallback prints to stderr with an emoji)
//!
//! F4 (dev feedback): the daemon watches the audit event buffer
//! (`ApiContext.events`) and calls [`send_dev_feedback`] for each intervention
//! event (`block` | `redact` | `warn`). Everything is best-effort: the source
//! of truth is the audit store, not the notifications.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerberus_engine::engine::Finding;
use cerberus_engine::feedback::RedactFeedback;
use cerberus_engine::rule::Action;
use cerberus_store::event::AuditEvent;

/// Actions that trigger dev feedback (from the audit schema).
#[must_use]
pub(crate) fn is_dev_intervention(action_taken: &str) -> bool {
    matches!(action_taken, "block" | "redact" | "warn")
}

/// Watches the in-memory event buffer (`ApiContext.events`) and only
/// delivers the NEW ones since the last call.
///
/// The control plane buffer keeps the last `10_000` events (trims from the
/// front). The watcher uses a positional watermark: if the buffer is trimmed
/// and the watermark falls out of range, it resyncs without doing a replay —
/// feedback is best-effort and the durable store is the source of truth.
#[derive(Debug, Default)]
pub(crate) struct InterventionWatcher {
    processed: usize,
}

impl InterventionWatcher {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { processed: 0 }
    }

    /// Returns the new events with an intervention `action_taken` since the
    /// last call (references into the given slice). Immutable regarding the
    /// events: only advances the watermark.
    pub(crate) fn drain_interventions<'a>(&mut self, events: &'a [AuditEvent]) -> Vec<&'a AuditEvent> {
        let len = events.len();
        if len < self.processed {
        // The buffer trimmed from the front (cap 10k): resync without
        // re-notifying what was already delivered.
            self.processed = len;
            return Vec::new();
        }
        let start = self.processed;
        self.processed = len;
        events[start..len]
            .iter()
            .filter(|e| is_dev_intervention(&e.action_taken))
            .collect()
    }
}

/// Send dev feedback for a freshly logged intervention event.
///
/// Strategy (F4):
/// 1. Desktop notification if available (macOS/Linux via notify-rust), with
///    **rate limited to 1 per second** so as not to bombard.
/// 2. If the notification does not exist or fails, the CLI line is printed to
///    stderr (the daemon runs in a terminal; stderr does not contaminate stdout).
pub(crate) fn send_dev_feedback(event: &AuditEvent) {
    let line = dev_feedback_line(event);
    if acquire_feedback_slot() {
        match notify_desktop(&title_for(&event.action_taken), &line) {
            Ok(()) => tracing::debug!("cerberus dev feedback notification sent"),
            Err(e) => {
                tracing::debug!("desktop notification unavailable ({e}); feedback via CLI line");
                eprintln!("{line}");
            }
        }
    } else {
        eprintln!("{line}");
    }
}

/// Single-line feedback line: flag + hash of the detected value. NEVER the
/// raw value (`AuditEvent` only carries SHA-256 hashes).
#[must_use]
fn dev_feedback_line(event: &AuditEvent) -> String {
    let verb = match event.action_taken.as_str() {
        "block" => "blocked",
        "redact" => "redacted",
        "warn" => "warned",
        other => other,
    };
    let flag = event.flags.first().map_or("unknown", String::as_str);
    let hash = event.hashed_values.first().map_or("sha256:n/a", String::as_str);
    format!(
        "Cerberus {verb}: flag={flag} hash={hash} (tool={} → provider={}, {})",
        event.tool, event.provider, event.severity
    )
}

/// Short title for the desktop notification based on the action.
#[must_use]
fn title_for(action_taken: &str) -> String {
    match action_taken {
        "block" => "Cerberus blocked traffic",
        "redact" => "Cerberus redacted a secret",
        "warn" => "Cerberus warning",
        _ => "Cerberus",
    }
    .to_string()
}

// ─── Desktop notification (platform-specific) ──────────────────────────────

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn notify_desktop(title: &str, body: &str) -> Result<(), String> {
    notify_rust::Notification::new()
        .summary(title)
        .body(body)
        .appname("Cerberus")
        .timeout(notify_rust::Timeout::Milliseconds(5000))
        .show()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn notify_desktop(title: &str, body: &str) -> Result<(), String> {
    // Unsupported platform (Windows, etc.): the "notification" is a line to
    // stderr with an emoji — the dev still sees what was blocked/redacted.
    eprintln!("⚠️ {title} — {body}");
    Ok(())
}

/// Minimum interval between desktop notifications (anti-spam).
const NOTIFY_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Last instant a desktop notification was emitted.
static LAST_NOTIFICATION: Mutex<Option<Instant>> = Mutex::new(None);

/// Does the notification rate admit a new one? (max 1/sec). CLI lines do not
/// go through here: only desktop popups are throttled.
fn acquire_feedback_slot() -> bool {
    let mut last = LAST_NOTIFICATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let now = Instant::now();
    if does_rate_allow(*last, now) {
        *last = Some(now);
        true
    } else {
        false
    }
}

/// Pure rate-limit rule (testable without touching global state).
#[must_use]
fn does_rate_allow(last: Option<Instant>, now: Instant) -> bool {
    last.is_none_or(|t| now.duration_since(t) >= NOTIFY_MIN_INTERVAL)
}

#[cfg(test)]
fn reset_feedback_slot() {
    *LAST_NOTIFICATION
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}

// ─── Orchestration from the daemon ──────────────────────────────────────────

/// Review the in-memory event buffer (`ApiContext.events`) and emit feedback
/// for new interventions. Locks the events mutex only during the drain (short
/// and with no internal await).
pub(crate) async fn emit_interventions(
    events: &Arc<tokio::sync::Mutex<Vec<AuditEvent>>>,
    watcher: &mut InterventionWatcher,
) {
    let guard = events.lock().await;
    for event in watcher.drain_interventions(&guard) {
        send_dev_feedback(event);
    }
}

// ─── Engine feedback (local scan) ───────────────────────────────────────────

/// Show feedback about findings to the dev (`scan`/`test` CLI mode).
///
/// Returns the feedback message (if any) for the CLI to print.
#[must_use]
pub(crate) fn show_feedback(findings: &[Finding], action_taken: Action) -> String {
    let feedback = RedactFeedback::from_findings(findings, action_taken);

    if !feedback.has_intervention() {
        return String::new();
    }

    let line = feedback.summary_line();

    // Show on stderr so as not to contaminate stdout of the pipeline
    eprintln!("{line}");

    // Desktop notification (silent opt-in)
    if let Err(e) = send_notification(&feedback) {
        tracing::debug!("notification failed (non-critical): {e}");
    }

    // Detailed messages
    let mut output = String::new();
    for msg in &feedback.messages {
        output.push_str(msg);
        output.push('\n');
    }
    output
}

/// Send a desktop notification (based on the engine summary).
fn send_notification(feedback: &RedactFeedback) -> Result<(), String> {
    if !feedback.has_intervention() {
        return Ok(());
    }

    let summary = feedback.summary_line();
    let first_flag = feedback
        .by_flag
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    notify(&summary, &first_flag)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn notify(summary: &str, body: &str) -> Result<(), String> {
    notify_rust::Notification::new()
        .summary(summary)
        .body(body)
        .appname("Cerberus")
        .timeout(notify_rust::Timeout::Milliseconds(5000))
        .show()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn notify(_summary: &str, _body: &str) -> Result<(), String> {
    // Desktop notifications not supported on this platform yet
    Ok(())
}

/// Show the welcome message when starting the daemon.
#[must_use]
pub(crate) fn welcome_message(port: u16) -> String {
    format!(
        r"
╔══════════════════════════════════════════╗
║           Cerberus Local v{}            ║
║   Sensitive-data firewall                ║
║                                          ║
║   Local proxy: http://127.0.0.1:{port}  ║
║   Mode: enforce                          ║
║                                          ║
║   Configure your agent:                  ║
║     export CLAUDE_CODE_BASE_URL=...      ║
║     export OPENCODE_BASE_URL=...         ║
╚══════════════════════════════════════════╝
",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerberus_engine::engine::Finding;
    use cerberus_engine::rule::{Action, Category, Severity};
    use cerberus_store::event::AuditEvent;

    fn make_finding(flag: &str, action: Action) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: Category::Secrets,
            severity: Severity::High,
            action,
            start: 0,
            end: 5,
            hashed_value: "sha256:test".to_string(),
        }
    }

    fn make_event(id: &str, action_taken: &str) -> AuditEvent {
        AuditEvent {
            id: format!("evt_{id}"),
            ts: "2026-08-21T00:00:00Z".to_string(),
            mode: "local".to_string(),
            tool: "claude-code".to_string(),
            provider: "anthropic".to_string(),
            flags: vec!["secret.openai_api_key".to_string()],
            counts: std::collections::HashMap::new(),
            action_taken: action_taken.to_string(),
            hashed_values: vec!["sha256:deadbeef".to_string()],
            severity: "critical".to_string(),
            ts_unix: 1_700_000_000,
        }
    }

    // ─── F4: intervention selection and drain ─────────────────────────────

    #[test]
    fn intervention_actions_match_product_set() {
        assert!(is_dev_intervention("block"));
        assert!(is_dev_intervention("redact"));
        assert!(is_dev_intervention("warn"));
        assert!(!is_dev_intervention("allow"));
        assert!(!is_dev_intervention(""));
        assert!(!is_dev_intervention("blocked"));
    }

    #[test]
    fn watcher_only_delivers_new_interventions() {
        let mut w = InterventionWatcher::new();
        let events = [
            make_event("1", "allow"),
            make_event("2", "block"),
            make_event("3", "warn"),
            make_event("4", "redact"),
            make_event("5", "allow"),
            make_event("6", "block"),
        ];
        let first = w.drain_interventions(&events);
        let ids: Vec<&str> = first.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, vec!["evt_2", "evt_3", "evt_4", "evt_6"]);

        // No new events → nothing new (does not reprocess what was seen).
        assert!(w.drain_interventions(&events).is_empty());

        // New events appended: only the unseen ones (the daemon re-passes the
        // COMPLETE buffer each tick, never just the tail).
        let mut all = events.to_vec();
        all.push(make_event("7", "warn"));
        all.push(make_event("8", "block"));
        let second = w.drain_interventions(&all);
        let ids2: Vec<&str> = second.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids2, vec!["evt_7", "evt_8"]);
    }

    #[test]
    fn watcher_resyncs_after_trim_without_replay() {
        #[allow(clippy::default_trait_access)]
        let mut w = InterventionWatcher::default();
        let events = vec![make_event("a", "block"), make_event("b", "redact")];
        w.drain_interventions(&events);
        assert_eq!(w.processed, 2);

        // Simulate the buffer trim by the cap (front trim).
        let trimmed = events[1..].to_vec();
        let out = w.drain_interventions(&trimmed);
        assert!(out.is_empty(), "the trim must not replay old events");
        assert_eq!(w.processed, 1);
    }

    #[test]
    fn watcher_empty_buffer_is_ok() {
        let mut w = InterventionWatcher::new();
        assert!(w.drain_interventions(&[]).is_empty());
        let events = vec![make_event("a", "redact")];
        let out = w.drain_interventions(&events);
        assert_eq!(out.len(), 1);
    }

    // ─── Phase: feedback line ───────────────────────────────────────────────

    #[test]
    fn dev_feedback_line_has_flag_and_hash_never_raw() {
        let ev = make_event("x", "block");
        let line = dev_feedback_line(&ev);
        assert!(line.contains("blocked"), "action verb: {line}");
        assert!(line.contains("secret.openai_api_key"), "flag: {line}");
        assert!(line.contains("sha256:deadbeef"), "hash: {line}");
    }

    #[test]
    fn dev_feedback_line_empty_event_safe() {
        let ev = AuditEvent {
            id: "evt_e".to_string(),
            ts: String::new(),
            mode: String::new(),
            tool: String::new(),
            provider: String::new(),
            flags: vec![],
            counts: std::collections::HashMap::new(),
            action_taken: "warn".to_string(),
            hashed_values: vec![],
            severity: String::new(),
            ts_unix: 0,
        };
        let line = dev_feedback_line(&ev);
        assert!(line.contains("warned"));
        assert!(line.contains("unknown"));
        assert!(line.contains("sha256:n/a"));
    }

    #[test]
    fn title_changes_with_action() {
        assert_eq!(title_for("block"), "Cerberus blocked traffic");
        assert_eq!(title_for("redact"), "Cerberus redacted a secret");
        assert_eq!(title_for("warn"), "Cerberus warning");
        assert_eq!(title_for("allow"), "Cerberus");
    }

    // ─── Phase: rate limit ──────────────────────────────────────────────────

    #[test]
    fn rate_limit_allows_first_and_blocks_immediately() {
        let now = Instant::now();
        assert!(does_rate_allow(None, now));
        assert!(!does_rate_allow(Some(now), now));
        assert!(!does_rate_allow(Some(now), now + Duration::from_millis(500)));
        assert!(does_rate_allow(Some(now), now + Duration::from_secs(1)));
    }

    #[test]
    fn acquire_feedback_slot_enforces_min_interval() {
        reset_feedback_slot();
        assert!(acquire_feedback_slot(), "first notification ok");
        assert!(!acquire_feedback_slot(), "immediate second blocked by the rate");
        reset_feedback_slot();
    }

    // ─── Engine feedback (regression) ──────────────────────────────────────

    #[test]
    fn feedback_empty_no_output() {
        let output = show_feedback(&[], Action::Allow);
        assert!(output.is_empty());
    }

    #[test]
    fn feedback_block_has_message() {
        let findings = vec![make_finding("test.flag", Action::Block)];
        let output = show_feedback(&findings, Action::Block);
        assert!(!output.is_empty());
        assert!(output.contains("blocked") || output.contains("block"));
    }

    #[test]
    fn feedback_redact_has_message() {
        let findings = vec![make_finding("test.flag", Action::Redact)];
        let output = show_feedback(&findings, Action::Redact);
        assert!(!output.is_empty());
    }

    #[test]
    fn welcome_message_contains_version() {
        let msg = welcome_message(8787);
        assert!(msg.contains("Cerberus Local"));
        assert!(msg.contains("8787"));
    }
}
