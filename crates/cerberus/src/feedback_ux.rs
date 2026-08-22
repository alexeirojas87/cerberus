//! Feedback al dev — notificaciones y mensajes CLI.
//!
//! Cuando algo se redacta o bloquea, el dev se entera mediante:
//! - Mensaje en la línea de comandos (stderr, el daemon corre en primer plano)
//! - Notificación de escritorio (macOS/Linux via notify-rust, tasa limitada;
//!   en plataformas sin soporte el fallback imprime a stderr con emoji)
//!
//! F4 (feedback al dev): el daemon vigea el buffer de eventos de auditoría
//! (`ApiContext.events`) y llama a [`send_dev_feedback`] para cada evento de
//! intervención (`block` | `redact` | `warn`). Todo es best-effort: la fuente
//! de verdad es el audit store, no las notificaciones.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerberus_engine::engine::Finding;
use cerberus_engine::feedback::RedactFeedback;
use cerberus_engine::rule::Action;
use cerberus_store::event::AuditEvent;

/// Acciones que disparan feedback al dev (del schema de auditoría).
#[must_use]
pub(crate) fn is_dev_intervention(action_taken: &str) -> bool {
    matches!(action_taken, "block" | "redact" | "warn")
}

/// Vigila el buffer en memoria de eventos (`ApiContext.events`) y solo
/// entrega los NUEVOS desde la última llamada.
///
/// El buffer del control plane mantiene los últimos `10_000` eventos (recorta
/// por el frente). El watcher usa un watermark posicional: si el buffer se
/// recorta y el watermark queda fuera de rango, se resincroniza sin hacer
/// replay — el feedback es best-effort y el store durable es la fuente de
/// verdad.
#[derive(Debug, Default)]
pub(crate) struct InterventionWatcher {
    processed: usize,
}

impl InterventionWatcher {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { processed: 0 }
    }

    /// Devuelve los eventos nuevos con `action_taken` de intervención desde la
    /// última llamada (referencias al slice dado). Inmutable en cuanto a los
    /// eventos: solo avanza el watermark.
    pub(crate) fn drain_interventions<'a>(&mut self, events: &'a [AuditEvent]) -> Vec<&'a AuditEvent> {
        let len = events.len();
        if len < self.processed {
            // El buffer recortó por el frente (cap 10k): resincronizar sin
            // notificar de nuevo lo ya entregado.
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

/// Enviar feedback al dev por un evento de intervención recién registrado.
///
/// Estrategia (F4):
/// 1. Notificación de escritorio si está disponible (macOS/Linux via
///    notify-rust), con **tasa limitada a 1 por segundo** para no bombardear.
/// 2. Si la notificación no existe o falla, se imprime la línea CLI a stderr
///    (el daemon corre en una terminal; stderr no contamina el stdout).
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

/// Línea de feedback single-line: flag + hash del valor detectado. NUNCA el
/// valor crudo (los `AuditEvent` solo transportan hashes SHA-256).
#[must_use]
fn dev_feedback_line(event: &AuditEvent) -> String {
    let verb = match event.action_taken.as_str() {
        "block" => "bloqueó",
        "redact" => "redactó",
        "warn" => "advirtió",
        other => other,
    };
    let flag = event.flags.first().map_or("unknown", String::as_str);
    let hash = event.hashed_values.first().map_or("sha256:n/a", String::as_str);
    format!(
        "Cerberus {verb}: flag={flag} hash={hash} (tool={} → provider={}, {})",
        event.tool, event.provider, event.severity
    )
}

/// Título corto de la notificación de escritorio según la acción.
#[must_use]
fn title_for(action_taken: &str) -> String {
    match action_taken {
        "block" => "Cerberus bloqueó tráfico",
        "redact" => "Cerberus redactó un secreto",
        "warn" => "Cerberus advierte",
        _ => "Cerberus",
    }
    .to_string()
}

// ─── Notificación de escritorio (plataforma-específica) ────────────────────

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
    // Plataforma sin soporte nativo (Windows, etc.): la "notificación" es una
    // línea a stderr con emoji — el dev igual ve qué se bloqueó/redactó.
    eprintln!("⚠️ {title} — {body}");
    Ok(())
}

/// Intervalo mínimo entre notificaciones de escritorio (anti-spam).
const NOTIFY_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// Último instante en que se emitió una notificación de escritorio.
static LAST_NOTIFICATION: Mutex<Option<Instant>> = Mutex::new(None);

/// ¿La tasa de notificación admite una nueva? (máx 1/seg). Las líneas CLI no
/// pasan por aquí: solo se amortiguan los popups de escritorio.
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

/// Regla pura del rate limit (testeable sin tocar el estado global).
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

// ─── Orquestación desde el daemon ──────────────────────────────────────────

/// Revisar el buffer en memoria de eventos (`ApiContext.events`) y emitir
/// feedback para las intervenciones nuevas. Bloquea el mutex de eventos
/// únicamente durante el drenaje (corto y sin await interno).
pub(crate) async fn emit_interventions(
    events: &Arc<tokio::sync::Mutex<Vec<AuditEvent>>>,
    watcher: &mut InterventionWatcher,
) {
    let guard = events.lock().await;
    for event in watcher.drain_interventions(&guard) {
        send_dev_feedback(event);
    }
}

// ─── Feedback del engine (scan local) ──────────────────────────────────────

/// Mostrar feedback sobre findings al dev (modo `scan`/`test` de la CLI).
///
/// Devuelve el mensaje de feedback (si lo hay) para que el CLI lo imprima.
#[must_use]
pub(crate) fn show_feedback(findings: &[Finding], action_taken: Action) -> String {
    let feedback = RedactFeedback::from_findings(findings, action_taken);

    if !feedback.has_intervention() {
        return String::new();
    }

    let line = feedback.summary_line();

    // Mostrar en stderr para no contaminar stdout del pipeline
    eprintln!("{line}");

    // Notificación de escritorio (opt-in silencioso)
    if let Err(e) = send_notification(&feedback) {
        tracing::debug!("notification failed (non-critical): {e}");
    }

    // Mensajes detallados
    let mut output = String::new();
    for msg in &feedback.messages {
        output.push_str(msg);
        output.push('\n');
    }
    output
}

/// Enviar notificación de escritorio (baseda en el resumen del engine).
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

/// Mostrar el mensaje de bienvenida al iniciar el daemon.
#[must_use]
pub(crate) fn welcome_message(port: u16) -> String {
    format!(
        r"
╔══════════════════════════════════════════╗
║           Cerberus Local v{}            ║
║   Cortafuegos de datos sensibles        ║
║                                          ║
║   Proxy local: http://127.0.0.1:{port}  ║
║   Modo: enforce                          ║
║                                          ║
║   Configura tu agente:                   ║
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

    // ─── F4: selección y drenaje de intervenciones ─────────────────────────

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

        // Sin eventos nuevos → nada nuevo (no reprocessar lo visto).
        assert!(w.drain_interventions(&events).is_empty());

        // Nuevos eventos append: solo los no vistos (el daemon re-pasa el
        // buffer COMPLETO cada tick, nunca solo la cola).
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

        // Simula el trim del buffer por el cap (recorte del frente).
        let trimmed = events[1..].to_vec();
        let out = w.drain_interventions(&trimmed);
        assert!(out.is_empty(), "el trim no debe reproducir eventos viejos");
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

    // ─── Fase: línea de feedback ───────────────────────────────────────────

    #[test]
    fn dev_feedback_line_has_flag_and_hash_never_raw() {
        let ev = make_event("x", "block");
        let line = dev_feedback_line(&ev);
        assert!(line.contains("bloqueó"), "verb acción: {line}");
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
        assert!(line.contains("advirtió"));
        assert!(line.contains("unknown"));
        assert!(line.contains("sha256:n/a"));
    }

    #[test]
    fn title_changes_with_action() {
        assert_eq!(title_for("block"), "Cerberus bloqueó tráfico");
        assert_eq!(title_for("redact"), "Cerberus redactó un secreto");
        assert_eq!(title_for("warn"), "Cerberus advierte");
        assert_eq!(title_for("allow"), "Cerberus");
    }

    // ─── Fase: rate limit ──────────────────────────────────────────────────

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
        assert!(acquire_feedback_slot(), "primera notificación ok");
        assert!(!acquire_feedback_slot(), "segunda inmediata bloqueada por la tasa");
        reset_feedback_slot();
    }

    // ─── Feedback del engine (regresión) ──────────────────────────────────

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
        assert!(output.contains("bloqueó") || output.contains("block"));
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
