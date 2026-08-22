//! Load/performance benchmark tests.
//!
//! Verifica que el motor de escaneo cumple el presupuesto de latencia
//! (< 3-5 ms p99 para payloads ≤ 50 KB, según §5 del build plan).
//!
//! Las benchmarks corren contra el **pack por defecto real** (13 reglas,
//! fuente `cerberus_packs::default_pack::DEFAULT_PACK_JSON`) — el mismo
//! pack que shipamos en producción, no una copia inline.

use std::time::{Duration, Instant};

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::load_rules_from_str;
use cerberus_engine::rule::Rule;
use cerberus_packs::default_pack::DEFAULT_PACK_JSON;

/// Presupuesto de latencia: p99 < 5 ms (release, plan §5).
const P99_BUDGET_MS: f64 = 5.0;

/// Assert que p99 cumple el presupuesto del perfil actual.
///
/// El presupuesto de latencia p99 < 3–5 ms (plan §5) es un criterio de
/// **release**. En debug, la CPU compartida del workspace (tests en paralelo,
/// sin optimizar) hace que los presupuestos estrictos no sean reproducibles.
/// Por eso en debug **sólo registramos** el p99 (sin assert de budget): el
/// gate de release es el que decide. Aun así, en debug guardamos contra
/// comportamiento patológico no-lineal con un techo holgado (30× release).
fn assert_p99_budget(p99_ms: f64, name: &str, release_budget: f64) {
    let is_release = !cfg!(debug_assertions);
    let profile = if is_release { "release" } else { "debug" };
    if is_release {
        let budget = release_budget;
        println!("load_test_{name}: profile={profile} budget={budget:.1}ms p99={p99_ms:.3} ms");
        assert!(
            p99_ms < budget,
            "{name}: p99 {p99_ms:.3}ms exceeds {profile} budget {budget}ms"
        );
    } else {
        // Debug: techo holgado (30× release) sólo para detectar patología
        // no-lineal grotesca. El gate de perf real es release.
        let debug_ceiling = release_budget * 30.0;
        println!("load_test_{name}: profile={profile} (release gate) p99={p99_ms:.3} ms ceiling={debug_ceiling:.1}ms");
        assert!(
            p99_ms < debug_ceiling,
            "{name}: p99 {p99_ms:.3}ms exceeds debug ceiling {debug_ceiling:.1}ms (pathology guard)"
        );
    }
}

/// Cargar el pack por defecto REAL (13 reglas) — fuente única de verdad.
fn load_bench_rules() -> Vec<Rule> {
    load_rules_from_str(DEFAULT_PACK_JSON).expect("default pack must parse for benchmarks")
}

/// Generar payload sintético.
fn synthetic_payload(size_kb: usize) -> String {
    let filler = "the quick brown fox jumps over the lazy dog. ";
    let target = size_kb * 1024;
    let mut body = String::with_capacity(target);
    while body.len() < target {
        body.push_str(filler);
    }
    body.truncate(target);
    body
}

/// Generar payload con secretos intercalados.
fn payload_with_secrets(size_kb: usize) -> String {
    let secret = "my api key is sk-abcDEFghijklmnopqrstuvwxyz1234 and email is test@example.com ";
    let target = size_kb * 1024;
    let mut body = String::with_capacity(target);
    while body.len() < target {
        body.push_str(secret);
    }
    body.truncate(target);
    body
}

/// Calcular percentil p.
fn percentile(timings: &[Duration], p: f64) -> Duration {
    assert!(!timings.is_empty());
    let mut sorted = timings.to_vec();
    sorted.sort();
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}

/// Benchmark: escanear payload de N KB con el pack real completo.
#[test]
fn load_test_1kb_clean() {
    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    let payload = synthetic_payload(1);
    let mut timings = Vec::with_capacity(100);

    for _ in 0..100 {
        let start = Instant::now();
        let _result = engine.scan(&payload);
        timings.push(start.elapsed());
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "1kb_clean", P99_BUDGET_MS);
}

#[test]
fn load_test_10kb_clean() {
    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    let payload = synthetic_payload(10);
    let mut timings = Vec::with_capacity(50);

    for _ in 0..50 {
        let start = Instant::now();
        let _result = engine.scan(&payload);
        timings.push(start.elapsed());
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "10kb_clean", P99_BUDGET_MS);
}

#[test]
fn load_test_50kb_with_secrets() {
    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    // Realistic payload: mostly benign text with a few secrets sprinkled in
    let payload = format!(
        "{}\n\nmy api key is sk-abcDEFghijklmnopqrstuvwxyz1234 and email test@example.com\n\n{}",
        synthetic_payload(48),
        synthetic_payload(2)
    );
    let mut timings = Vec::with_capacity(20);

    for _ in 0..20 {
        let start = Instant::now();
        let result = engine.scan(&payload);
        timings.push(start.elapsed());
        assert!(!result.findings.is_empty(), "secrets payload should trigger findings");
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "50kb_secrets", 5.0);
}

#[test]
fn load_test_100kb_clean() {
    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    let payload = synthetic_payload(100);
    let mut timings = Vec::with_capacity(20);

    for _ in 0..20 {
        let start = Instant::now();
        let _result = engine.scan(&payload);
        timings.push(start.elapsed());
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "100kb_clean", 5.0);
}

/// Verificar que escanear sin reglas es rápido.
#[test]
fn load_test_empty_engine() {
    let engine = EngineBuilder::new(&[]).build().expect("engine build");
    let payload = synthetic_payload(10);
    let start = Instant::now();
    for _ in 0..100 {
        let _result = engine.scan(&payload);
    }
    let elapsed = start.elapsed();
    let avg_ms = elapsed.as_secs_f64() * 1000.0 / 100.0;
    // Mismo enfoque que assert_p99_budget: release = gate estricto, debug =
    // techo holgado (30×) sólo para patología grotesca.
    let is_release = !cfg!(debug_assertions);
    let profile = if is_release { "release" } else { "debug" };
    let ceiling = if is_release { 5.0 } else { 5.0 * 30.0 };
    println!("load_test_empty_engine: profile={profile} ceiling={ceiling:.1}ms avg={avg_ms:.3} ms");
    assert!(
        avg_ms < ceiling,
        "empty engine too slow: {avg_ms:.3}ms avg > {ceiling}ms ({profile})"
    );
}

/// Verificar que el decode + scan es rápido.
#[test]
fn load_test_decode_and_scan() {
    use bytes::Bytes;
    use cerberus_proxy::decoder::decode;

    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    let payload = Bytes::from(payload_with_secrets(10));
    let mut timings = Vec::with_capacity(50);

    for _ in 0..50 {
        let start = Instant::now();
        let decoded = decode(&payload, None);
        let _result = engine.scan(&decoded.text);
        timings.push(start.elapsed());
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "decode_and_scan", 5.0);
}

/// Verificar que scan + redact es rápido.
#[test]
fn load_test_scan_and_redact() {
    use cerberus_engine::redact::{apply_redaction, RedactOptions};

    let engine = EngineBuilder::new(&load_bench_rules()).build().expect("engine build");
    let payload = payload_with_secrets(10);
    let mut timings = Vec::with_capacity(50);

    for _ in 0..50 {
        let start = Instant::now();
        let output = engine.scan(&payload);
        let _redacted = apply_redaction(&payload, &output.findings, &RedactOptions::default());
        timings.push(start.elapsed());
    }

    let p99 = percentile(&timings, 99.0);
    let p99_ms = p99.as_secs_f64() * 1000.0;
    assert_p99_budget(p99_ms, "scan_and_redact", 5.0);
}

/// Sanity: el pack real carga exactamente 13 reglas (guarda contra drift).
#[test]
fn load_test_default_pack_rule_count() {
    let rules = load_bench_rules();
    assert_eq!(
        rules.len(),
        13,
        "default pack must have exactly 13 rules (drift guard), got {}",
        rules.len()
    );
}
