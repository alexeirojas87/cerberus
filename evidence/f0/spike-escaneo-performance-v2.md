# Evidence Pack — f0/spike-escaneo-performance-v2
- Intento: 2    Revisor: REVISOR 2 (performance)    Veredicto: PASS (con 1 observación)

## Configuración
- Máquina: macOS (darwin), release profile
- Commits aplicados: intento 2 del spike-escaneo (incluye fix F2: AC prefilter + p50 throughput)

## 1. Build
`cargo build --release --workspace 2>&1` → ✅ OK, 0 errores, `Finished release [optimized] in 5.42s`

## 2. Bench full (hybrid) — 300 patrones, 100 KB, 1000 iter
- 1ª corrida (cold start): `scan_p50_ms=0.494`, `scan_p99_ms=1.838`, `throughput_mbps=207.4`, 227 matches
- 3 corridas posteriores (estables):
  - run1: p50=0.484, p99=0.601, tp=211.8
  - run2: p50=0.483, p99=0.609, tp=211.9
  - run3: p50=0.483, p99=0.615, tp=212.0

**p99 estable ≈ 0.60-0.62 ms < 1.0 ms ✅** (el p99=1.838 de la primera corrida es outlier de cold start; 3 corridas posteriores confirman sub-ms).

## 3. Bench comparativo (regex puro) — 300 patrones, 100 KB, 200 iter
`--engine regex`: p50=158.281, p99=161.327, throughput=0.647 mbps, 236 matches
- Muy lento como se esperaba (~158-161 ms). **Diferencia hybrid vs regex puro ≈ 320x en p50.** ✅
- Nota: matches diff (227 vs 236, Δ~4%) — el hybrid pierde algo de recall por los patrones sin prefijo literal viable; documentado ya en `spike-escaneo-fix.md`, no es bloqueante para presupuesto de rendimiento.

## 4. Estabilidad — hybrid, 50 patrones, 10 KB, 100 iter, 2 corridas
| Métrica | runA | runB | Variación |
|---|---|---|---|
| p50 | 0.052 ms | 0.047 ms | **10.6%** (< 20% ✅) |
| p99 | 0.064 ms | 0.058 ms | **10.3%** (< 50% ✅) |

## 5. Prefilter overhead — 0 patrones, 100 KB, 100 iter
`scan_p50_ms=0.088`, `scan_p99_ms=0.093`, `throughput_mbps=1161.4`
- **Overhead de AC con 0 prefijos ≈ 0.09 ms (sub-ms) ✅**. El costo residual es el escaneo regex de RegexSet vacío sobre 100 KB.

## 6. Ventana de contexto (revisión de código) — `engine_hybrid.rs`
- **No hay ventana acotada**: `shortest_match(&payload[m.start()..])` escanea desde el hit del prefijo **hasta el final del payload** (engine_hybrid.rs:115-117).
- **Impacto**: correcto (nunca pierde matches), y a 100 KB/300 patrones sigue sub-ms porque `shortest_match` corta en cuanto hay match. Pero a payloads grandes (>1 MB) el coste puede crecer superlinealmente.
- **Observación (no bloqueante para F0)**: acotar la ventana a 128-1024 bytes tras el hit evitaría degradación en payloads grandes (relevante para §5 "≤ 50 KB" hoy ok, pero ojo en futuras fases).
- Nota de precisión: `\bkey\b` extrae prefijo "key" (extract_prefix conserva los boundaries `\b`) — el AC matcheará sobre "key" como substring, y el regex posterior verifica el boundary. Ventana pequeña no afectaría este caso porque el hit de AC ya está en la posición correcta.

## 7. Throughput (revisión de código) — `main.rs`
- `BenchResult::from_timings` usa `percentile(timings, 50.0)` para throughput (main.rs:210-214), **no mean** ✅ (fix F2 confirmado).
- p50 y p99 ambos derivados de percentiles; `round_val` redondea a 3 decimales.

## Comparación contra presupuesto §5
| Requisito §5 | Umbral | Medido | Estado |
|---|---|---|---|
| Escanear ~100 KB + cientos de patrones < 1 ms | scan_p99 < 1.0 ms | **p99 ≈ 0.60-0.62 ms** (cold: 1.84 outlier) | ✅ |
| Comparativo regex puro | Debe ser MUY lento | p50 ≈ 158 ms | ✅ (320x peor) |
| Estabilidad | p50 Δ<20%, p99 Δ<50% | p50 Δ10.6%, p99 Δ10.3% | ✅ |
| Overhead AC sin prefijos | sub-ms | 0.088 ms p50 | ✅ |
| Throughput con p50 | p50 (no mean) | 212 mbps @ p50 | ✅ |

## Veredicto
**PASS** — el motor híbrido (AC prefilter + regex) cumple el presupuesto §5 con margen ~40% sobre el umbral de 1 ms. Una observación para fases futuras: acotar la ventana de contexto regex tras el hit de AC en `engine_hybrid.rs` para blindar payloads grandes (>1 MB). No es bloqueante para F0.
