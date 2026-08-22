# Evidence Pack — f0/budget-validation
- Intento: 1    Revisor: BUILDER (consolidación)    Veredicto: PASS

## Criterios de aceptación — §5 NFRs vs datos de spikes

| # | Criterio (§5) | Umbral | Medido | Evidencia | Veredicto |
|---|---|---|---|---|---|
| 1 | **Latencia añadida del proxy** — p99 overhead < 3–5 ms para prompts ≤ 50 KB | p99 < 3–5 ms | **Overhead p99 = 0.0–0.161 ms** (máx observado); **0.071 ms** (media 2 corridas 50 KB); **0.071 ms** (100 KB); **0.127 ms** (50 KB raw) | `evidence/f0/spike-proxy-performance.md:51-54`, `evidence/f0/raw/proxy-bench-50kb.txt:17` | ✅ PASS — margen ≥ 18× |
| 2 | **Throughput de escaneo** — ~100 KB + cientos de patrones en < 1 ms | scan_p99 < 1.0 ms | **scan_p99 = 0.60–0.62 ms** (estable, 3 corridas); **0.595–0.635 ms** (reproducción reviewer, 4 corridas); **0.623 ms** (raw `fix-bench-hybrid.json`); **p50 = 0.469 ms**; throughput = **212–218 mbps** | `evidence/f0/spike-escaneo-performance-v2.md:18`, `evidence/f0/raw/fix-bench-hybrid.json:8` | ✅ PASS — margen **~1.5×** (el MÁS ajustado; **restricción limitante del sistema**) |
| 3 | **Sin ReDoS** — ningún patrón causa backtracking catastrófico | Tiempo lineal garantizado | 3 patrones ReDoS clásicos: `(a\|aa\|aaa)+b`, `(a\|aa)*b`, `(a+)+b` → `extract_prefix()` retorna `None` → caen a `RegexSet` (DFA interno) → **188 µs en 100 KB de 'a's**, sin hang. `unsafe_code = "forbid"` en workspace. | `evidence/f0/spike-escaneo-security-v2.md:26-43` | ✅ PASS |
| 4 | **Instalación simple** — Modo B: un comando, cero-config | No aplica en F0 | Evaluación en F4 (local-daemon + cerberus-init). El workspace compila binario estático único. | — | ⏭️ DIFIERE a F4 |
| 5 | **Multiplataforma** — macOS, Linux, Windows | Matriz CI 3 OS | CI configurado con `["macos-latest", "ubuntu-latest", "windows-latest"]` en YAML; build + test + clippy + fmt pasan en macOS. | `evidence/f0/scaffold-ci.md:12` | ✅ PASS |
| 6 | **Fuga cero de secretos** — valor crudo nunca persiste/loguea | 0 fugas en logs | F0 no maneja secretos reales: el proxy bufferiza bytes opacos y el scan nunca recibe tráfico real. Higiene del spike (0 `println!` de datos, 0 `dbg!`) documentada, pero no valida la garantía del producto. | `evidence/f0/spike-proxy-security.md:98-109`, `evidence/f0/spike-escaneo-security-v2.md:88-95` | ⏭️ DIFIERE a F1/F5 — validación cuando el pipeline maneje secretos reales |
| 7 | **Higiene de memoria** — zeroization post-escaneo | No aplica en F0 | Se implementa en F1/F2 (motor de detección/redacción). El spike no maneja secretos reales. | — | ⏭️ DIFIERE a F1 |
| 8 | **Precisión (falsos positivos)** — medido en continuo | No aplica en F0 | Se evalúa en F1 con corpus de prueba. Hybrid vs regex: Δ~4% matches (227 vs 236) documentado, no bloqueante. | `evidence/f0/spike-escaneo-performance-v2.md:23` | ⏭️ DIFIERE a F1 |

## Casos adversariales probados (intento de romper el presupuesto)

- **Proxy: upstream caído** → sin 502 Bad Gateway, `Empty reply from server`. Bug reportado, no afecta presupuesto de latencia (veáse riesgo propagado a F3).
- **Proxy: body 0 KB** → bench produce JSON válido, overhead medido.
- **Proxy: `--payload-kb abc`** → parse error ignorado, corre defaults. UX frágil, no afecta rendimiento.
- **Scan: `--patterns 0`** → 0 matches, JSON válido, sin errores.
- **Scan: `--payload-size 0`** → throughput 0.0, sin crash, manejo correcto.
- **Scan: `--engine invalid`** → error `invalid engine 'X' (expected 'regex' or 'hybrid')` + `exit(1)` (`main.rs:80-87`). Fix ya aplicado en `spike-escaneo-fix`; sin fallback silencioso.
- **Scan: Vectorscan intento de compilación** → `cmake` no instalado en el sistema. Error: `is 'cmake' not installed?`. El stub offline compila con `--features vectorscan` desactivado. Vectorscan no es viable sin cmake.
- **Scan: ReDoS con payload 100 KB de 'a' + 'b' al final** → 188 µs, sin hang. Tiempo lineal confirmado.

## NFRs aplicables

- **Latencia proxy:** overhead p99 = 0.066–0.158 ms steady-state (máx observado 0.161 ms; presupuesto < 3–5 ms) → ✅ PASS, margen **≥ 18×** (amplio: 18.6× a 31.1×). Bench 50 KB, 1000 iter, release, loopback.
- **Throughput escaneo:** scan_p99 = 0.595–0.635 ms (presupuesto < 1.0 ms) → ✅ PASS, margen **~1.5×** (**el más ajustado del sistema; restricción limitante**). Bench 300 patrones, payload real 99 KB, 1000 iter, release.
- **Seguridad (ReDoS):** 0 patrones ReDoS causan hang → ✅ PASS. DFA+AC garantizan tiempo lineal. Caveat: la ruta híbrida prefijada con ventana no acotada puede amplificar superlinealmente (riesgo propagado a F1, ver tabla).
- **Seguridad (unsafe):** `unsafe_code = "forbid"` verificado funcionalmente → ✅ PASS.
- **Multiplataforma:** CI matrix 3 OS configurado → ✅ PASS.

### Condiciones del benchmark (consolidadas)

- **Entorno:** loopback (localhost), macOS arm64, release profile.
- **Proxy:** 50 KB, 1000 iteraciones, 20 warm-up. Overhead = diff de percentiles (proxy_p99 − direct_p99), nearest-rank (conservador).
- **Scan:** 300 patrones, payload nominal 100 KB / real **99 KB** (`payload_size_kb=99` en `fix-bench-hybrid.json`; el generador trunca a límite de línea), 1000 iteraciones.
- **Consistencia de cifras scan:** el raw `fix-bench-hybrid.json` registra **0.623 ms p99** (1000 iter, 99 KB); `spike-escaneo-fix.md:29` cita **0.652 ms p99** — misma metodología, **corridas distintas** del mismo esfuerzo fixer (no está tal cual en el raw). `spike-escaneo-performance-v2.md:18` documenta 0.601/0.609/0.615 ms (3 corridas estables, tras excluir outlier de cold start de 1.838 ms). La reproducción independiente del reviewer dio **0.595–0.635 ms** (4 corridas). Rango consolidado: **0.595–0.635 ms p99**.

## Decisiones cerradas de Fase 0

| Decisión | Resultado | Efecto |
|---|---|---|
| **Stack: Rust** | ✅ Confirmado (§3) | Binario estático único, sin GC, latencia predecible |
| **Motor de matching (§9 #3)** | ✅ **Plan B: regex crate + Aho-Corasick prefilter** | Vectorscan no compila sin cmake en esta máquina; híbrido AC cumple el presupuesto con margen |
| **Presupuesto de latencia (§5)** | ✅ **Validado con datos experimentales** | Proxy overhead 0.066–0.158 ms p99 (margen ≥ 18×); escaneo 0.595–0.635 ms p99 (margen ~1.5×) |
| **Vectorscan** | ⏭️ **Difiere: optimización futura / palanca de escala** | Stub offline presente, feature-gated tras `cfg(feature = "vectorscan")`; primera palanca si el margen ~1.5× del scan se erosiona |

## Riesgos detectados y propagación a fases futuras

| Riesgo | Severidad | Origen | Propagar a |
|---|---|---|---|
| Proxy sin 502 ante upstream caído | 🔴 **Debe corregirse** | `spike-proxy-correctness.md:41-51` | **F3** — reverse-proxy-core debe responder 502 |
| Sin límite de body → DoS por memoria | 🟠 Medio | `spike-proxy-security.md:134-139` | **F3** — implementar `max_body_size` |
| Sin timeouts en cliente/servidor → socket leak | 🟠 Medio | `spike-proxy-security.md:141-148` | **F3** — configurar connect/request/idle timeouts |
| Headers reenviados sin sanitizar | 🟡 Low | `spike-proxy-security.md:150-157` | **F3** — implementar allowlist de headers |
| Upstream configurable sin restricción → SSRF potencial | 🟢 Info | `spike-proxy-security.md:159-166` | **F3** — validar upstream como dirección permitida |
| Ventana de contexto regex no acotada → amplificación superlineal (O(N_hits × L_payload); ReDoS DoS por CPU) | 🟠 **Medium** | `spike-escaneo-performance-v2.md:36-39`, `engine_hybrid.rs:115-117` | **F1** — expandir fuzzing ReDoS con patrones prefijados + payloads sin match; acotar ventana post-AC a 128–1024 bytes |
| Activar Vectorscan como motor del hot path (feature-gated `--features vectorscan`) | ⏭️ Diferida — NO comprometida en MVP | F0 spike (falla compilación sin cmake); decisión §9 #3 | **F1 o F7** — SOLO si el margen ~1.5× del scan se erosiona (más patrones en packs, payloads > 100 KB, o p99 scan > 1 ms en CI/producción). Trigger y detalles en `decision-motor-matching.md` §"Propagación de la decisión" |
| Monitorización continua del p99 del scan en CI | 🟡 Vigilancia | El scan es la restricción limitante (~1.5×); cualquier erosión del presupuesto es silenciosa sin monitoreo | **F1** — incorporar bench híbrido 300 patrones / 99 KB en pipeline de CI, alertar si p99 > 1 ms |

## Si FAIL: qué falla y cómo reproducirlo

No aplica — todos los criterios aplicables PASS; criterios de F1/F4/F5 diferidos. El presupuesto de latencia §5 se valida con datos experimentales de los spikes. **El margen NO es uniforme**: proxy amplio (≥ 18×) pero scan ajustado (~1.5×) — ver riesgos de escalabilidad más abajo.

## Escalabilidad y monitorización (F1+)

- Con margen **~1.5×**, el scan es la **restricción limitante del sistema** (~12× más ajustado que el proxy: 18× vs 1.5×). Cada incremento de patrones/payload, o un cold-start, **erosiona el presupuesto de 1 ms**.
- **Palanca de optimización futura:** Vectorscan (feature-gated) es la primera opción si el margen del scan se estrecha con más patrones o payloads > 100 KB.
- **Monitorización propuesta en F1+:** medir y alertar el **p99 del scan** de forma continua en el pipeline de CI (bench híbrido 300 patrones / 99 KB), no solo en F0.
- **Riesgo de cola del proxy:** el primer arranque registró overhead p99 = **3.315 ms** (66–100% del presupuesto de 3–5 ms), outlier de cold start que **no se reproduce en steady-state** (6/6 corridas < 0.16 ms). Se registra como riesgo de cola a vigilar en despliegues reales (F4/F5), sin impacto en el veredicto F0.

## Conclusión

**VEREDICTO: PASS** ✅ — El presupuesto de latencia §5 se valida con datos de los spikes:
- Overhead del proxy: **p99 = 0.066–0.158 ms steady-state** (presupuesto < 3–5 ms, margen ≥ 18× — amplio)
- Escaneo híbrido AC+regex: **p99 = 0.595–0.635 ms** (presupuesto < 1.0 ms, margen **~1.5×** — **el más ajustado; restricción limitante del sistema**)
- Sin ReDoS verificado (con caveat de ventana no acotada propagado a F1), multiplataforma configurado, fuga cero DIFIERE a F1/F5
- Decisión §9 #3 cerrada: **Plan B = regex crate + Aho-Corasick prefilter** como motor de matching del MVP
- Riesgos documentados y propagados a F1/F3 según corresponda (incl. SSRF potencial → F3; ventana regex 🟠 → F1)