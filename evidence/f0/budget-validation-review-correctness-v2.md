# Evidence Pack — f0/budget-validation (REVISOR 1 · correctness · v2)
- Intento: 2    Revisor: REVISOR 1 (correctness, independiente)    Veredicto: **PASS**
- Fecha: 2026-08-16    Worktree: `cerberus-wt-f0-budget-rv2-correctness`
- Objeto: revisión del doc corregido `evidence/f0/budget-validation.md` (commit `7c2e4e4`)

---

## Veredicto

**PASS** ✅ — Las correcciones del fixer (7c2e4e4) cierran todos los hallazgos de la
revisión security rv1 y de la revisión performance rv1. Los números citados son
coherentes con los raw y con las reproducciones independientes. Sin contradicciones
internas. Decisión §9 #3 sigue bien respaldada.

---

## 1. Verificación numérica — números citados vs raw

### 1.1 Overhead proxy p99 (steady-state 0.066–0.158 ms)

| Cifra citada (doc) | Valor raw / fuente | ¿Coincide? |
|---|---|---|
| "0.066–0.158 ms steady-state" (L30,77) | Reproducción reviewer rv1: 6 corridas = 0.066, 0.072, 0.076, 0.076, 0.100, 0.158 ms | ✅ |
| "máx observado 0.161 ms" (L30) | `spike-proxy-performance.md:41` — 0.161 ms de corrida anterior | ✅ |
| "0.127 ms (50 KB raw)" (L8) | `raw/proxy-bench-50kb.txt:16` — overhead p99 = 0.127667 | ✅ (valor; cita línea 17, off-by-one, ver §4) |
| "0.071 ms (media 2 corridas 50 KB)" (L8) | `spike-proxy-performance.md:40` — RUN1=0.000, RUN2=0.142 → media 0.071 | ✅ |
| "0.071 ms (100 KB)" (L8) | `raw/proxy-bench-100kb.txt` — overhead p99 = 0.071459 | ✅ |
| "0.0–0.161 ms (máx observado)" (L8) | Rango full incl. corrida clipped a 0 (RUN1) y máx 0.161 | ✅ |

### 1.2 Margen proxy ≥ 18×

- `3 ms / 0.161 = 18.6×`; `5 ms / 0.161 = 31.1×` → doc declara "18.6× a 31.1×" y "≥ 18×". ✅

### 1.3 Scan p99 (0.595–0.635 ms)

| Cifra citada (doc) | Valor raw / fuente | ¿Coincide? |
|---|---|---|
| "0.595–0.635 ms (reproducción reviewer, 4 corridas)" (L9,41) | Reviewer rv1: 0.595, 0.610, 0.624, 0.635 ms | ✅ |
| "0.623 ms (raw fix-bench-hybrid.json)" (L9,41) | `raw/fix-bench-hybrid.json` — scan_p99_ms = 0.623 | ✅ (valor; cita línea 8, off-by-one, ver §4) |
| "p50 = 0.469 ms" (L9) | `fix-bench-hybrid.json` — scan_p50_ms = 0.469 | ✅ |
| "throughput = 212–218 mbps" (L9) | raw hybrid = 218.548; reviewer rv1 scan = 211.5–213.1 | ✅ |
| "0.60–0.62 ms (estable, 3 corridas)" (L9) | `spike-escaneo-performance-v2.md:14-16` — 0.601/0.609/0.615 | ✅ |
| "0.652 ms (spike-escaneo-fix.md:29)" (L41) | `spike-escaneo-fix.md:29` = 0.652; no está tal cual en raw — doc lo declara explícitamente como "corridas distintas" | ✅ (transparencia correcta) |

### 1.4 Margen scan ~1.5×

- `1.0 / 0.623 = 1.60×`; `1.0 / 0.652 = 1.53×` → "~1.5×" ✅ (L9,31,78)

### 1.5 Payload 99–100 KB

- `fix-bench-hybrid.json` registra `payload_size_kb: 99` (nominal `--payload-size 100`, el generador trunca a límite de línea). Doc L31,40 lo declara como "payload real 99 KB / nominal 100 KB". ✅

### 1.6 Otras cifras

- Outlier frío proxy p99 = 3.315 ms (L72) — `budget-validation-review-performance.md:40` ✅
- ReDoS 188 µs en 100 KB de 'a's (L10) — `spike-escaneo-security-v2.md:39` ✅
- "6/6 corridas < 0.16 ms" (L72) — reviewer rv1: runs B–G = 0.066–0.158, todas < 0.16 ✅
- "~12× más ajustado" (L69): 18.6/1.6 ≈ 11.6 ≈ 12 ✅

---

## 2. Verificación de las correcciones del fixer

| Corrección requerida | Estado en doc v2 | ¿Aplicada? |
|---|---|---|
| "Fuga cero" PASS → DIFIERE | L13: `⏭️ DIFIERE a F1/F5` + justificación (F0 no maneja secretos reales) | ✅ |
| SSRF en tabla de riesgos → F3 | L60: fila "Upstream configurable sin restricción → SSRF potencial | 🟢 Info | ...spike-proxy-security.md:159-166 | **F3**" | ✅ |
| `--engine invalid` stale eliminado/actualizado | L24 adversarial case actualizado a "error `invalid engine 'X'` + `exit(1)` (main.rs:80-87)"; fila eliminada de tabla de riesgos | ✅ — verificado contra código: `main.rs:80-87` hace `eprintln!` + `std::process::exit(1)` (commit 7f5cfb6) |
| Ventana regex severidad 🟠 Medium | L61: `🟠 **Medium**` con riesgo explícito (O(N_hits × L_payload), ReDoS DoS por CPU) + acción F1 expandida (fuzzing con prefijados + acotar ventana 128–1024 B) | ✅ |
| Margen scan como restricción limitante | L9, L31, L69, L78: "el MÁS ajustado / restricción limitante del sistema", "~12× más ajustado que el proxy" | ✅ |
| Condiciones de bench (loopback, macOS arm64) | L38: "loopback (localhost), macOS arm64, release profile"; L39-40 detalle proxy/scan | ✅ |
| Sección escalabilidad/monitorización | L67-72: palanca Vectorscan, monitorización p99 scan en CI F1+, riesgo de cola 3.315 ms | ✅ |

---

## 3. Coherencia interna y fechas/SHAs

- **Criterio 1 (L8)** y **NFR latencia (L30)**: usan "0.0–0.161 máx" y "0.066–0.158 steady-state" respectivamente — ambos respaldados por las mismas fuentes (el 0.0 es la corrida clipped del spike, el rango steady-state excluye el cold-start 3.315). No se contradicen. ✅
- **L41** reconcilia 0.623 (raw) vs 0.652 (fixer doc) como corridas distintas — elimina la discrepancia señalada en rv1. ✅
- **Fechas/SHAs**: el doc no cita SHAs, solo commits de referencia indirecta. El commit `7c2e4e4` ("fix(f0): budget-validation rigor margen scan + riesgos security") existe en git log y su diff coincide 1:1 con las correcciones verificadas. `8db7d31` (spike-proxy) y `7f5cfb6` (--engine fix) también existen. ✅
- Referencias cruzadas (`spike-escaneo-performance-v2.md:18`, `spike-proxy-performance.md:51-54`, `spike-escaneo-security-v2.md:26-43,88-95`, `spike-proxy-security.md:98-109,134-166`, `scaffold-ci.md:12`) apuntan a líneas correctas. ✅

---

## 4. Decisión §9 #3 — ¿sigue bien respaldada?

**Sí.** ✅ La decisión "Plan B = regex crate + Aho-Corasick prefilter" sigue soportada:

- **Vectorscan no viable aquí**: `raw/scan-vectorscan-attempt.txt` muestra el error `is 'cmake' not installed?` (build script de `vectorscan-sys` requiere cmake). ✅
- **Hybrid cumple presupuesto**: scan_p99 = 0.595–0.635 ms < 1.0 ms, reproducido independientemente (4 corridas reviewer rv1). ✅
- **Margen** ~1.5× documentado como restricción limitante con Vectorscan como primera palanca (L70). ✅
- **Sin ReDoS estructural**: prefijos → AC lineal; sin prefijo → RegexSet DFA; caveat de ventana no acotada propagado a F1 como 🟠 Medium. ✅
- `decision-motor-matching.md` coherente con el doc (mismos números: 0.623/0.469/218.5 mbps/227 matches). ✅

---

## 5. Hallazgos (no bloqueantes)

1. **Off-by-one menor en dos citas de raw** (valor correcto, línea ±1): `proxy-bench-50kb.txt:17` — el p99 overhead está en la línea 16; `fix-bench-hybrid.json:8` — el `scan_p99_ms` está en la línea 7 (la 8 es throughput). No afecta la veracidad de las cifras.
2. **Trazabilidad de la reproducción reviewer**: el rango 0.595–0.635 y 0.066–0.158 proviene del artefacto de la revisión rv1 (`budget-validation-review-performance.md`), no de un raw commiteado en este worktree. Está documentado como "reproducción reviewer" en el doc; aceptable, pero un lector sin acceso al worktree rv1 no podría reproducirlo desde `evidence/f0/raw/`. Recomendación (no bloqueante): commitear los JSON de reproducción en F1+.
3. **Observación metodológica heredada** (ya aceptada en rv1, no corregible sin re-bench): el bench proxy usa diff de percentiles no interleaved; a los niveles medidos (<0.2 ms) es ruido de piso. Documentado en `spike-proxy-performance.md:70`.

---

## 6. Conclusión

El documento corregido es **internamente consistente**, todos los números citados
coinciden con los raw y las reproducciones independientes, y cada hallazgo de la
revisión rv1 (security + performance) fue aplicado correctamente: fuga-cero DIFIERE,
SSRF → F3, `--engine invalid` actualizado/eliminado, ventana regex 🟠 Medium, margen
scan ~1.5× como restricción limitante, condiciones de bench presentes, y sección de
escalabilidad/monitorización añadida. La decisión §9 #3 (regex + AC) permanece válida.

**VEREDICTO: PASS** ✅
