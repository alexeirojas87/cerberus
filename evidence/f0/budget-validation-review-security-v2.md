# Evidence Pack — f0/budget-validation-review-security-v2
- Rol: **REVISOR 3 (Security)**
- Unidad: **presupuesto-latencia** (segundo intento)
- Documentos auditados: `evidence/f0/budget-validation.md`, `evidence/f0/decision-motor-matching.md`
- Código verificado: `crates/spike-scan/src/main.rs:80-87`
- Veredicto: **PASS** ✅

## Resumen

Se verifican las 5 correcciones de seguridad solicitadas + 2 criterios adicionales.
Todas las correcciones obligatorias están presentes y correctas. 1 observación no
bloqueante sobre la documentación cuantitativa de la amplificación superlineal.

---

## 1. Correcciones de seguridad verificadas

### 1.1 "Fuga cero" → `⏭️ DIFIERE a F1/F5`

| Estado | Detalle |
|--------|---------|
| **Criterio** | La fila §5 #6 no debe ser PASS, debe diferir |
| **Doc** | `budget-validation.md:13` → `⏭️ DIFIERE a F1/F5 — validación cuando el pipeline maneje secretos reales` |
| **Código** | `spike-proxy-security.md:98-109` confirma 0 `println!` de datos, 0 `dbg!` |
| **Veredicto** | ✅ **CORRECTO** |

### 1.2 SSRF en tabla de riesgos → F3

| Estado | Detalle |
|--------|---------|
| **Criterio** | El hallazgo SSRF de `spike-proxy-security.md:159-166` debe estar en la tabla de propagación |
| **Doc** | `budget-validation.md:60` → `Upstream configurable sin restricción → SSRF potencial | 🟢 Info | spike-proxy-security.md:159-166 | F3` |
| **Veredicto** | ✅ **CORRECTO** — propagado a F3 con severidad 🟢 Info y origen |

### 1.3 `--engine invalid` stale eliminado/actualizado

| Estado | Detalle |
|--------|---------|
| **Criterio** | El `--engine invalid` con fallback silencioso a Hybrid debe estar corregido o actualizado |
| **Doc** | `budget-validation.md:24` → `error 'invalid engine 'X' (expected 'regex' or 'hybrid')' + exit(1) (main.rs:80-87). Fix ya aplicado en spike-escaneo-fix; sin fallback silencioso.` |
| **Código** | `main.rs:80-87` → `eprintln!("invalid engine '{other}' (expected 'regex' or 'hybrid')"); std::process::exit(1);` — sin catch-all, sin fallback silencioso |
| **Veredicto** | ✅ **CORRECTO** — el stale está eliminado; el código confirma el fix |

### 1.4 Ventana regex no acotada → 🟠 Medium, acción F1

| Estado | Detalle |
|--------|---------|
| **Criterio** | Severidad 🟠 Medium, acción F1: fuzzing prefijado + ventana acotada 128-1024 B |
| **Doc** | `budget-validation.md:61` → `🟠 Medium | spike-escaneo-performance-v2.md:36-39, engine_hybrid.rs:115-117 | F1 — expandir fuzzing ReDoS con patrones prefijados + payloads sin match; acotar ventana post-AC a 128–1024 bytes` |
| **Veredicto** | ✅ **CORRECTO** — severidad, origen, acción y destino correctos |

---

## 2. Criterio Sin ReDoS — honestidad del registro

| Subcriterio | Doc | Veredicto |
|---|---|---|
| Reconoce que F0 no cubrió la ruta híbrida prefijada | `budget-validation.md:32` → `Caveat: la ruta híbrida prefijada con ventana no acotada puede amplificar superlinealmente (riesgo propagado a F1, ver tabla)`. El spike (`spike-escaneo-security-v2.md:36`) confirma: los 3 patrones ReDoS testeados tienen `extract_prefix() = None` → solo cubren ruta unprefixed. | ✅ **SÍ** — caveat explícito, con referencia a la tabla de propagación |
| Amplificación superlineal como 🟠 Medium a expandir en F1 | `budget-validation.md:61` → riesgo con `O(N_hits × L_payload)`, 🟠 Medium, F1 con fuzzing prefijado + ventana acotada | ✅ **SÍ** — cualitativamente correcto |
| Números específicos (3.3 ms @100KB, 337 ms @1MB) | **No aparecen** en `budget-validation.md` ni en `spike-escaneo-performance-v2.md` ni en ningún archivo del worktree. | ⚠️ **NO** — los números no están registrados |

**Observación**: El registro del riesgo es honesto en cuanto a la existencia, severidad,
mecanismo (`O(N_hits × L_payload)`) y propagación, pero omite la evidencia cuantitativa
de la amplificación. Los números 3.3 ms @100KB y 337 ms @1MB no figuran en ningún
documento del worktree. Esto no invalida el veredicto, pero la trazabilidad cuantitativa
quedaría fortalecida si se incluyeran.

---

## 3. Decisión del motor — sin riesgo nuevo

| Aspecto | Detalle | Veredicto |
|---------|---------|-----------|
| Motor seleccionado | `regex` crate + Aho-Corasick prefilter (Plan B) | — |
| Riesgo nuevo introducido | Ninguno. El riesgo de ventana no acotada en la ruta híbrida prefijada ya está documentado en `budget-validation.md:61` y propagado a F1 | ✅ **SIN RIESGO NUEVO** |
| Vectorscan | Descartado por falta de cmake, queda como optimización futura | — |
| Decisión clara | `decision-motor-matching.md:48-54` → tabla con estados y motivos | ✅ **SÍ** |

---

## 4. Propagación de riesgos — tabla completa

| Hallazgo origen | Riesgo | Severidad | Propagar | En doc | Veredicto |
|---|---|---|---|---|---|
| `spike-proxy-correctness.md:41-51` | Proxy sin 502 ante upstream caído | 🔴 Debe corregirse | F3 | `budget-validation.md:56` | ✅ |
| `spike-proxy-security.md:134-139` | Sin límite de body → DoS por memoria | 🟠 Medium | F3 | `budget-validation.md:57` | ✅ |
| `spike-proxy-security.md:141-148` | Sin timeouts → socket leak | 🟠 Medium | F3 | `budget-validation.md:58` | ✅ |
| `spike-proxy-security.md:150-157` | Headers reenviados sin sanitizar | 🟡 Low | F3 | `budget-validation.md:59` | ✅ |
| `spike-proxy-security.md:159-166` | Upstream sin restricción → SSRF | 🟢 Info | F3 | `budget-validation.md:60` | ✅ |
| `spike-escaneo-performance-v2.md:36-39` | Ventana regex no acotada → amplificación superlineal | 🟠 Medium | F1 | `budget-validation.md:61` | ✅ |

**Todos los hallazgos del spike-proxy (5) y del spike-escaneo (1) están propagados.** ✅

---

## 5. Hallazgos adicionales

| # | Hallazgo | Severidad | Archivo |
|---|---|---|---|
| 1 | Números de amplificación superlineal (3.3 ms @100KB, 337 ms @1MB) no registrados en ningún doc del worktree — la evidencia cuantitativa del riesgo 🟠 Medium queda incompleta | 🟢 Info (observación) | `budget-validation.md:61` |
| 2 | `budget-validation.md` dice "Intento: 1" pero el task indica que es el segundo intento — inconsistencia cosmética en el encabezado | 🟢 Info | `budget-validation.md:2` |

---

## Veredicto final

**PASS** ✅ — Las 5 correcciones de seguridad requeridas están presentes y correctas:

| Criterio | Resultado |
|---|---|
| 1. Fuga cero → DIFIERE a F1/F5 | ✅ |
| 2. SSRF en tabla de riesgos → F3 | ✅ |
| 3. `--engine invalid` stale eliminado/actualizado | ✅ (código confirma fix) |
| 4. Ventana regex no acotada 🟠 Medium, acción F1 (fuzzing prefijado + ventana 128-1024 B) | ✅ |
| 5. Sin ReDoS — registro honesto del caveat (ruta prefijada no cubierta por fuzzing F0) | ✅ (con observación: faltan números 3.3/337 ms) |
| 6. Decisión del motor sin riesgo nuevo | ✅ |
| 7. Propagación de riesgos completa (6 hallazgos, 6 filas) | ✅ |

**Cierre**: El documento `budget-validation.md` y `decision-motor-matching.md` cumplen
los criterios de seguridad del Gauntlet. El riesgo de amplificación superlineal por
ventana no acotada está correctamente identificado, severizado 🟠 Medium, y propagado
a F1 con acción concreta. La omisión de los números cuantitativos (3.3/337 ms) es una
observación no bloqueante que no afecta la validez del veredicto.