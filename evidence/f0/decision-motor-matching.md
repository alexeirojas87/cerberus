# Decisión §9 #3 — Motor de matching: Vectorscan vs regex/RE2

## Contexto

El plan §3 recomendaba Vectorscan (fork portable de Hyperscan) como motor de multi-regex de alta
velocidad, con `regex` crate como plan B. La decisión debía cerrarse en Fase 0 según los datos del
spike de escaneo.

## Evidencia

### Vectorscan — no compila en esta máquina

```
$ cargo build --features vectorscan
error: failed to run custom build command for `vectorscan v0.1.0`
Caused by:
  is 'cmake' not installed?
```

`evidence/f0/raw/scan-vectorscan-attempt.txt` — cmake no está disponible en el sistema. El build
script de `vectorscan-sys` requiere cmake para compilar la librería C++ nativa de Hyperscan.
Vectorscan queda como optimización futura, activable vía `--features vectorscan`.

### Motor híbrido (Plan B) — cumple el presupuesto con margen

Benchmark: 300 patrones, 100 KB payload, 1000 iteraciones, release profile:

| Motor | scan_p50 | scan_p99 | Throughput | Matches |
|---|---|---|---|---|
| **Hybrid (AC + regex)** | **0.469 ms** | **0.623 ms** | **218.5 mbps** | 227 |
| Regex puro | 158.5 ms | 166.1 ms | 0.65 mbps | 236 |

- **Hybrid vs regex puro: ~335× más rápido en p50, ~254× en p99**
- **Hybrid p99 = 0.60–0.62 ms estable** (3 corridas), muy por debajo del umbral de 1.0 ms (§5)
- Overhead de AC con 0 prefijos: **0.088 ms p50** (sub-ms)
- Estabilidad: p50 Δ 10.6%, p99 Δ 10.3% (< 20% / < 50%)
- Sin ReDoS: patrones sin prefijo caen a `RegexSet` (DFA, tiempo lineal)

### Precisión

Hybrid: 227 matches vs Regex puro: 236 matches (Δ~4%). La diferencia corresponde a patrones sin
prefijo literal viable (ej. `\d{5}`) que `extract_prefix` no puede extraer y que el AC prefilter
no cubre. Estos patrones van directamente a `RegexSet` (unprefixed) y se escanean igual. No hay
falsos negativos estructurales — verificado en `spike-escaneo-security-v2.md:73-87`.

## Decisión

**Plan B = `regex` crate + Aho-Corasick prefilter** como motor de matching del MVP.

| Opción | Estado | Motivo |
|---|---|---|
| **Vectorscan** | ⏭️ Futura optimización (NO comprometido en MVP) | No compila sin cmake; el plan B cumple el presupuesto |
| **RE2** | ❌ Descartado | `regex` crate (DFA nativo) da el mismo resultado sin dependencia externa |
| **regex crate + AC** | ✅ **SELECCIONADO** | Cumple < 1 ms con margen ~40%; sin dependencias C++; tiempo lineal garantizado |

## Propagación de la decisión a fases futuras

> Qué significa "Vectorscan queda como optimización futura": **el motor activo del MVP es el Plan B
> (regex + AC)**. Vectorscan NO se descarta ni se compromete en el MVP; queda como **palanca de
> optimización feature-gated** (`--features vectorscan`), con stub compilable sin la feature. Se
> activa SOLO si se disparan las condiciones abajo. No es trabajo de "segunda ronda".

| Item | Qué se propaga | Trigger (condición de activación) | Destino de la fase |
|---|---|---|---|
| **Activar Vectorscan** | Reemplazar/aumentar el motor AC+regex por Vectorscan para el hot path | El margen del scan (~1.5× sobre el presupuesto < 1 ms, §5) se erosiona: más patrones en rule packs, payloads > 100 KB, o evidencia de CI/producción de p99 scan > umbral | **F1** (si el corpus de reglas crece al migrar `cerberus-detection-rules.json`) o **F7** (si un rule pack nuevo lo exige). Requisito: instalar `cmake` y verificar latencia vs presupuesto con el spike de F0 |
| **Acotar ventana post-AC** | En `engine_hybrid.rs`, limitar `shortest_match` a 128–1024 B tras un hit de prefijo para evitar amplificación superlineal O(N_hits × L_payload) | Ninguno — riesgo conocido 🟠 Medium de seguridad/DoS por CPU | **F1** (obligatorio, junto con fuzzing ReDoS de patrones prefijados) |
| **Fuzzing ReDoS de ruta prefijada** | Fuzzing con patrones que SÍ tienen prefijo literal + payloads sin match (no solo los 3 patrones ReDoS sin prefijo de F0) | Ninguno — requisito §5 "Sin ReDoS" | **F1** |
| **Monitorizar p99 del scan en CI** | Bench híbrido 300 patrones / 99 KB en el pipeline de CI, alertar si p99 > 1 ms | Ninguno — el scan es la restricción limitante del sistema | **F1** (desde la primera integración de reglas) |

Riesgo relacionado: el margen ~1.5× del scan es la **restricción limitante** (proxy tiene ≥ 18×).
Ver tabla de propagación completa en `evidence/f0/budget-validation.md`.

## Números clave

- **p99 escaneo híbrido:** 0.60–0.62 ms (presupuesto §5: < 1.0 ms)
- **Velocidad relativa vs regex puro:** 335× (p50)
- **Throughput:** 212–218 mbps @ p50
- **Compilación de patrones:** 10.3 ms (300 patrones, única vez al arrancar)
- **Overhead AC prefiltro (0 prefijos):** 0.088 ms

## Referencias

- `evidence/f0/spike-escaneo-performance-v2.md` — revisión de rendimiento
- `evidence/f0/spike-escaneo-fix.md` — implementación del fixer
- `evidence/f0/spike-escaneo-security-v2.md` — verificación de seguridad (ReDoS, unsafe)
- `evidence/f0/raw/fix-bench-hybrid.json` — raw data hybrid
- `evidence/f0/raw/scan-vectorscan-attempt.txt` — intento fallido de compilar Vectorscan
- `evidence/f0/raw/fix-bench-regex.json` — raw data regex puro