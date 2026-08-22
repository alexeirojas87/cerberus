# Evidence Pack — f0/integration-gate
- Intento: 1    Revisor: revisor-integracion (independiente)    Veredicto: PASS
- Fecha: 2026-08-16    Worktree: cerberus-wt-f0-integration-gate (detached HEAD @ 22ced1f)

## Criterios de aceptación de la fase (§8 F0)

> "spikes demuestran escaneo < objetivo y overhead de proxy < objetivo; motor de matching decidido
> y presupuesto de latencia validado por escrito."

| Criterio | Comando ejecutado | Salida (citada) | Resultado |
|----------|-------------------|-----------------|-----------|
| Build integrado (dev) | `cargo build --workspace` | `Finished dev profile in 9.01s`, 0 errores | ✅ |
| Build integrado (release) | `cargo build --release --workspace` | `Finished release profile in 14.02s`, 0 errores | ✅ |
| Tests integrados | `cargo test --workspace` | **40 passed; 0 failed** (ver desglose abajo) | ✅ |
| Lint integrado | `cargo clippy --workspace --all-targets -- -D warnings` | `Finished dev profile`, 0 errores | ✅ |
| Formato integrado | `cargo fmt --check` | `FMT_EXIT=0`, 0 diffs | ✅ |
| Escaneo integrado < 1 ms | `cargo run --release --bin spike-scan -- --patterns 300 --payload-size 100 --iterations 500` | `scan_p99_ms: 0.625` (p50 0.486), 227 matches, 210.6 mbps | ✅ |
| Proxy integrado < 3–5 ms | `cargo run --release --bin spike-proxy -- --bench --payload-kb 50 --iterations 500` | `overhead p99: 0.061 ms` (run1), `0.072 ms` (run2) | ✅ |
| Reproducibilidad escaneo (p50 Δ < 20%) | bench scan ×2 | p50 0.486 → 0.481 ms (**Δ 1.0%**) | ✅ |
| Decisiones de fase | `evidence/f0/decision-motor-matching.md` existe | Decisión §9 #3 escrita: **regex crate + Aho-Corasick** | ✅ |
| Presupuesto validado por escrito | `evidence/f0/budget-validation.md` existe | PASS con números (proxy 0.066–0.158 ms; scan 0.595–0.635 ms) | ✅ |
| Evidence packs de las 4 unidades | `evidence/f0/` listado | 13 packs + raw (ver tabla §6) | ✅ |

## Desglose de tests integrados (40 total, 0 failed)

| Crate | Suite | Passed |
|---|---|---|
| benchkit | lib unit | 6 |
| cerberus-core | lib unit | 1 |
| spike-proxy | lib unit | 3 |
| spike-proxy | integration (e2e HTTP real) | 4 |
| spike-scan | lib unit | 7 |
| spike-scan | main unit | 11 |
| spike-scan | integration (binario/edge/schema) | 8 |
| **Total** | | **40 passed; 0 failed; 0 ignored** |

Doc-tests: 0 en los 4 crates (0 failed). Ningún crate huérfano: los 4 son members de `crates/*` y
todos build + test + clippy + fmt.

## Números de latencia reproducidos (verificación del revisor de integración)

- **Escaneo (hybrid AC+regex, 300 patrones, 99 KB, 500 iter, release):**
  run1: p50 = **0.486 ms**, p99 = **0.625 ms**, 210.6 mbps → objetivo §5 < 1 ms ✅ (margen ~1.6×)
  run2: p50 = **0.481 ms**, p99 = 0.656 ms → Δp50 = **1.0%** (< 20% exigido)
- **Proxy (50 KB, 500 iter, release, loopback):**
  run1: overhead p99 = **0.061 ms**; run2: overhead p99 = **0.072 ms** → objetivo §5 < 3–5 ms ✅
  (margen ~50–80×). Consistente con los 0.066–0.158 ms del evidence pack.
- Los números integrados reproducen el rango consolidado de `budget-validation.md`
  (scan 0.595–0.635 ms; proxy 0.066–0.158 ms). Sin outliers de cold start en las corridas propias.

## Casos adversariales de integración probados

- **Race/limpieza:** tras cada corrida del bench de proxy, `pgrep -fl spike-proxy` = vacío (exit 1)
  y `lsof -iTCP -sTCP:LISTEN` sin sockets del proxy → **0 procesos/sockets residuales** ✅
- **Consistencia de versiones:** `Cargo.lock` commiteado (git ls-files OK); los 4 crates declaran
  `version = "0.1.0"` consistente entre manifests y lock; sin versiones duplicadas de crates propios ✅
- **Reproducibilidad:** scan bench ×2 → Δp50 1.0%, Δp99 5.0% (0.625→0.656), ambos < 20% ✅
- **Workspace completo:** `cargo test --workspace` cubre los 4 crates; `crates/*` glob en
  `Cargo.toml:3` sin miembros huérfanos; CI (`ci.yml`) refleja exactamente los mismos comandos
  (fmt, clippy -D warnings, test, build release) con matrix 3 OS ✅
- **Fix `--engine invalid` presente:** confirmado en `main.rs:80-87` (`eprintln!` + `exit(1)`),
  acorde a lo verificado por `budget-validation-review-correctness-v2.md:68` (commit 7f5cfb6) ✅

## Estado de los evidence packs de unidad (existencia + PASS)

| Unidad (§8B.6) | Pack | Veredicto declarado |
|---|---|---|
| scaffold+CI | `evidence/f0/scaffold-ci.md` | ✅ PASS (Intento 1) |
| spike-escaneo (correctness) | `spike-escaneo-correctness-v2.md` | ❌ FAIL pre-fix → **corregido** (ver hallazgo 1) |
| spike-escaneo (fixer) | `spike-escaneo-fix.md` | ✅ PASS (Intento 2) |
| spike-escaneo (performance) | `spike-escaneo-performance-v2.md` | ✅ PASS (Intento 2, 1 observación no bloqueante) |
| spike-escaneo (security) | `spike-escaneo-security-v2.md` | ✅ PASS (Intento 2) |
| spike-proxy (correctness) | `spike-proxy-correctness.md` | ✅ PASS (1 bug reportado → F3) |
| spike-proxy (performance) | `spike-proxy-performance.md` | ✅ PASS |
| spike-proxy (security) | `spike-proxy-security.md` | ✅ PASS |
| presupuesto-latencia (correctness) | `budget-validation-review-correctness-v2.md` | ✅ PASS (Intento 2) |
| presupuesto-latencia (performance) | `budget-validation-review-performance-v2.md` | ✅ PASS (Intento 2) |
| presupuesto-latencia (security) | `budget-validation-review-security-v2.md` | ✅ PASS |
| presupuesto-latencia (consolidación) | `budget-validation.md` | ✅ PASS |
| decisión §9 #3 | `decision-motor-matching.md` | ✅ Decisión escrita (regex crate + AC) |

Panel de unidad **spike-escaneo** (alto riesgo → mayoría): correctness FAIL→fix→re-verificado en
budget-correctness, performance PASS, security PASS → mayoría alcanzada.

## Hallazgos de integración

1. **Trail de correctness de spike-escaneo incompleto (observación, no bloqueante):**
   `spike-escaneo-correctness-v2.md` quedó documentado como **FAIL** (falla real del gauntlet por
   `--engine invalid`, `main.rs:80-83` pre-fix) y el commit de cierre se llama "panel PASS v2 + v3"
   pero no existe un pack `correctness-v3` con re-verificación propia. La re-verificación del fix
   quedó absorbida por `spike-escaneo-fix.md` (PASS) y `budget-validation-review-correctness-v2.md`
   (§2 verifica el fix contra código, commit 7f5cfb6). El veredicto de la fase es sólido: el fix está
   en el código (verificado por este revisor en `main.rs:80-87`) y las cifras de latencia se
   reproducen. Se recomienda para fases futuras cerrar siempre cada FAIL con un pack de re-verificación
   explícito del mismo panelista.
2. **Margen de scan ajustado (~1.5×)** reproducido (0.625 ms vs 1.0 ms de presupuesto) — es la
   restricción limitante del sistema, ya documentado y propagado a F1/F3 en `budget-validation.md`.
3. **Proxy sin 502 ante upstream caído** (bug de spike-proxy, `spike-proxy-correctness.md:41-51`)
   propagado a F3; no afecta criterios de latencia de F0.

## NFRs aplicables

- Latencia proxy: overhead p99 = 0.061–0.072 ms (reproducido; presupuesto < 3–5 ms) → ✅ PASS
- Throughput escaneo: scan_p99 = 0.625–0.656 ms (presupuesto < 1.0 ms) → ✅ PASS
- Seguridad: `unsafe_code = "forbid"` en workspace (`Cargo.toml:8`) → ✅ PASS
- Reproducibilidad: Δp50 1.0% (exigido < 20%) → ✅ PASS

## Si FAIL: qué falla y cómo reproducirlo

No aplica — todos los criterios de aceptación de la fase §8 F0 se cumplen en estado integrado y los
números de latencia se reproducen de forma independiente.

## Conclusión

**VEREDICTO DE FASE 0: PASS** ✅ — El workspace integrado (4 crates) builda dev+release sin errores,
pasa 40/40 tests, clippy -D warnings y fmt limpios; el escaneo híbrido AC+regex corre a p99 = 0.625 ms
(< 1 ms) y el overhead del proxy a p99 = 0.061–0.072 ms (< 3–5 ms) con reproducibilidad < 20%; el
motor de matching está decidido por escrito (regex crate + Aho-Corasick) y el presupuesto de latencia
validado por escrito con números. Los 13 evidence packs de las 4 unidades existen y declaran PASS
(salvo el FAIL pre-fix de correctness que quedó corregido y re-verificado). Fase 0 lista para
aprobar el gate §8B.7 y abrir F1.
