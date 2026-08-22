//! ReDoS fuzzing — verifica que ningún patrón cause backtracking catastrófico.
//!
//! Fuzzing sobre el **pack por defecto real** (13 reglas, fuente
//! `cerberus_packs::default_pack::DEFAULT_PACK_JSON`) — no sobre una copia
//! inline. Esto cubre el criterio de aceptación de F9:
//! "redos-fuzz(todos los packs)".
//!
//! Rust `regex` crate usa un motor de tiempo lineal (RE2-like), por lo que
//! ReDoS no es posible en teoría. Verificamos que todos los patrones del pack
//! real compilan y matchean en tiempo predecible contra entradas diseñadas
//! para causar backtracking catastrófico en motores vulnerables, incluyendo
//! los patrones multilínea (PEM / id_rsa / .env).

use std::time::{Duration, Instant};

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::load_rules_from_str;
use cerberus_engine::rule::Rule;
use cerberus_packs::default_pack::DEFAULT_PACK_JSON;

/// Tiempo máximo permitido por escaneo.
const MAX_SCAN_TIME_MS: u64 = 100;

/// Cargar todas las reglas del pack por defecto real (13 reglas).
fn load_all_rules() -> Vec<Rule> {
    load_rules_from_str(DEFAULT_PACK_JSON).unwrap_or_else(|e| panic!("default pack must parse: {e:?}"))
}

/// Generar payload adversarial clásico de backtracking.
fn backtracking_payload(length: usize) -> String {
    "a".repeat(length)
}

/// Probar que ningún patrón del pack real cause escaneo lento.
#[test]
fn redos_fuzz_short_payloads() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let payloads = vec![
        backtracking_payload(100),
        backtracking_payload(1_000),
        backtracking_payload(10_000),
    ];

    for payload in &payloads {
        let start = Instant::now();
        let result = engine.scan(payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "scan took {}ms for payload len={}: {:?}",
            elapsed.as_millis(),
            payload.len(),
            result.findings,
        );
    }
}

/// Probar cada patrón del pack real individualmente contra entrada adversarial.
#[test]
fn redos_fuzz_each_pattern() {
    let rules = load_all_rules();
    for rule in &rules {
        for pattern in &rule.patterns {
            let re = regex::Regex::new(pattern)
                .unwrap_or_else(|_| panic!("pattern '{}' (flag {}) failed to compile", pattern, rule.flag));
            let adversarial = format!("{}{}", "a".repeat(5_000), "!");
            let start = Instant::now();
            let _ = re.find(&adversarial);
            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
                "pattern '{}' (flag {}) took {}ms on adversarial input",
                pattern,
                rule.flag,
                elapsed.as_millis(),
            );
        }
    }
}

/// Probar que el engine no se cuelga con payloads vacíos.
#[test]
fn redos_fuzz_empty_input() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let start = Instant::now();
    let result = engine.scan("");
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_millis(MAX_SCAN_TIME_MS));
    assert!(result.findings.is_empty());
}

/// Probar payloads con caracteres especiales regex.
#[test]
fn redos_fuzz_special_chars() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");
    let special = vec![
        "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "\\\\\\\\",
        "[[[[[[",
        "((((((",
        "......",
        "*****?",
        "|||||",
    ];

    for payload in &special {
        let start = Instant::now();
        let _ = engine.scan(payload);
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
            "scan took {}ms for special payload '{}'",
            elapsed.as_millis(),
            payload,
        );
    }
}

/// Adversarial multiline: un bloque PEM truncado/malformado que tentaría al
/// patrón multilínea a consumir toda la entrada. Debe terminar en tiempo lineal.
#[test]
fn redos_fuzz_malformed_pem_multiline() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    // Bloque BEGIN sin END — el patrón multiline intenta matchear toda la
    // entrada; al no hallar END, debe fallar rápido (no lineal-explosivo).
    let truncated_pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{}", "A".repeat(10_000));
    let start = Instant::now();
    let result = engine.scan(&truncated_pem);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "malformed PEM scan took {}ms",
        elapsed.as_millis(),
    );
    // Sin END, no debe producir hallazgo espurio.
    assert!(
        result.findings.iter().all(|f| f.flag != "secret.pem_private_key"),
        "truncated PEM should not spuriously match pem_private_key: {:?}",
        result.findings
    );

    // Muchos bloques BEGIN anidados (caso patológico para regex multiline).
    let nested = format!(
        "{}{}",
        "-----BEGIN PRIVATE KEY-----\n".repeat(100),
        "garbage data\n".repeat(5_000)
    );
    let start = Instant::now();
    let _result = engine.scan(&nested);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "nested BEGIN scan took {}ms",
        elapsed.as_millis(),
    );
}

/// Adversarial .env: muchas líneas `KEY=value` largas — el patrón multiline
/// `(?m)^...=.{10,}` no debe degradar con input grande.
#[test]
fn redos_fuzz_env_block_large() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    let mut body = String::with_capacity(50_000);
    for i in 0..5_000 {
        body.push_str(&format!("OPENAI_API_KEY={}\n", "a".repeat(20)));
        let _ = i;
    }
    let start = Instant::now();
    let result = engine.scan(&body);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "large .env scan took {}ms",
        elapsed.as_millis(),
    );
    assert!(
        !result.findings.is_empty(),
        "large .env should trigger env_block finding"
    );
}

/// Adversarial: clave con prefijo válido pero sufijo de longitud explosiva
/// para probar el quantifier acotado `{20,}` del patrón openai.
#[test]
fn redos_fuzz_long_suffix_after_prefix() {
    let rules = load_all_rules();
    let engine = EngineBuilder::new(&rules).build().expect("engine build");

    // "sk-" + 100k chars: el patrón `\\bsk-[A-Za-z0-9]{20,}\\b` debe escanear
    // en tiempo lineal. El constraint `maxLength=128` puede descartar el
    // hallazgo (anti-FP correcto); aquí sólo verificamos latencia, no match.
    let payload = format!("openai api key sk-{}", "a".repeat(100_000));
    let start = Instant::now();
    let _result = engine.scan(&payload);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(MAX_SCAN_TIME_MS),
        "long suffix scan took {}ms",
        elapsed.as_millis(),
    );

    // Un key dentro de bounds (maxLength 128) con keyword de contexto debe
    // producir hallazgo — confirma que el setup es válido y el motor detecta.
    let valid_payload = format!("openai api key sk-{}", "a".repeat(30));
    let result = engine.scan(&valid_payload);
    assert!(
        !result.findings.is_empty(),
        "valid-length openai key with context keyword should match"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_all_rules_returns_default_pack() {
        let rules = load_all_rules();
        assert!(!rules.is_empty(), "default pack should load at least one rule");
        // El pack por defecto tiene 13 reglas; permitimos crecimiento.
        assert!(
            rules.len() >= 13,
            "default pack should have >=13 rules, got {}",
            rules.len()
        );
    }
}
