# Evidence Pack — Fase 9 / redos-fuzz
- Intento: 2    Revisor: Builder (Codex via Orca)    Veredicto: PASS

## Criterios de aceptación (§8B.6 — "redos-fuzz(todos los packs)")
| Criterio | Comando ejecutado | Salida (citada) | Resultado |
|----------|-------------------|-----------------|-----------|
| Fuzz sobre el pack real (13 reglas) | `cargo test --test redos_fuzz` | `8 passed; 0 failed` | ✅ |
| Compila todos los patrones del pack | `redos_fuzz_each_pattern` | cada patrón compila y matchea < 100 ms | ✅ |
| Payloads adversariales cortos | `redos_fuzz_short_payloads` ("a"×100/1k/10k) | < 100 ms cada scan | ✅ |
| Input vacío no se cuelga | `redos_fuzz_empty_input` | 0 findings, rápido | ✅ |
| Caracteres especiales regex | `redos_fuzz_special_chars` | < 100 ms | ✅ |
| **Multiline PEM malformado** (nuevo) | `redos_fuzz_malformed_pem_multiline` | BEGIN sin END + 100k + BEGIN×100 anidados → < 100 ms, 0 spurious match | ✅ |
| **.env grande** (nuevo) | `redos_fuzz_env_block_large` (5 000 líneas `KEY=val`) | < 100 ms, hallazgo `secret.env_block` | ✅ |
| **Sufijo largo tras prefijo** (nuevo) | `redos_fuzz_long_suffix_after_prefix` ("sk-"+100k chars) | < 100 ms; key válido dentro de bounds sí matchea | ✅ |
| Drift guard: pack tiene 13 reglas | `redos_fuzz_load_all_rules_returns_default_pack` | `rules.len() >= 13` | ✅ |

## Cambio vs intento 1
El intento 1 usaba **reglas inline hardcoded** (6 reglas en un string JSON dentro
del test). El criterio de aceptación del plan §8B.6 exige "redos-fuzz(todos los
packs)" — un revisor adversarial marcaría FAIL: el fuzz no tocaba el pack real
que shipamos (13 reglas, incl. multiline PEM/id_rsa/.env).

**Fix (intent 2):** el pack por defecto ahora vive en
`cerberus_packs::default_pack::DEFAULT_PACK_JSON` (fuente única de verdad,
consumida por el daemon y los tests). `redos_fuzz.rs` carga ese pack real y
añade 3 casos adversariales multiline/long-suffix que el intento 1 no cubría.

## Casos adversariales probados (intento de romper)
- "a"×10 000 (backtracking clásico) → lineal, < 100 ms.
- Patrón openai `\\bsk-[A-Za-z0-9]{20,}\\b` contra "sk-"+100k → lineal.
- Bloque `-----BEGIN RSA PRIVATE KEY-----` truncado (sin END) + 100k chars →
  no match espurio, < 100 ms.
- 100 bloques `BEGIN` anidados + 5 000 líneas garbage → < 100 ms.
- 5 000 líneas `OPENAI_API_KEY=aaa...` → match correcto, < 100 ms.
- Caracteres regex especiales (`\\\\`, `[[[[`, `((((`, `....`, `****?`, `||||`).

## NFR
- **Sin ReDoS:** motor `regex` crate (RE2-like, tiempo lineal) + fuzzing del
  pack real completo (13 reglas, incl. multiline) → ✅

## Archivos
- `tests/redos_fuzz.rs` (reescrito: usa pack real + 3 casos multiline nuevos)
- `crates/cerberus-packs/src/default_pack.rs` (nuevo: fuente única del pack)
- `crates/cerberus/src/packs.rs` (delegado a `cerberus_packs::default_pack`)

## Desviaciones del plan
Ninguna. El fuzz ahora cubre "todos los packs" (el pack por defecto real) como
exige el plan.
