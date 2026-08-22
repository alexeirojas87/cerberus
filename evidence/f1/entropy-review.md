# Evidence Pack: REVISOR 3 (Security) — entropy-detector

**Fase:** 1 | **Unidad:** entropy-detector | **Revisor:** Security  
**Fecha:** 2026-08-17 | **Worktree:** `cerberus-wt-f1-review-entropy`

---

## 1. Build & Baseline

| Herramienta | Resultado | Evidencia |
|---|---|---|
| `cargo build` | ✅ PASS — 0 errors | 14.48s, sin warnings |
| `cargo test` | ✅ PASS — 166 tests | 6+1+115+11+3+0+4+7+11+8 = 166 passed |
| `cargo clippy --all-targets` | ✅ PASS — 0 warnings | Sin lint errors |
| `cargo fmt --check --all` | ✅ PASS — 0 diff | Formateo consistente tras fix inicial |

## 2. Revisión de Código — `entropy.rs`

### `shannon_entropy(text: &str) -> f64`

**Fórmula:** `H = -Σ p(x)·log₂(p(x))` — ✅ correcta matemáticamente.

- Operación a nivel de **byte** (`text.as_bytes()`, `counts[256]`)
- Casos borde: empty → 0.0, single char → ~0.0, all-256 → ~8.0
- Usa `mul_add` para precisión — ✅
- Usa `wrapping_add` para counts (overflow control) — ✅

### `detect_near_keywords(text, threshold) -> Vec<Finding>`

- Compila regex `(?i)\b(keyword1|keyword2|…)\b` — ✅ case-insensitive
- Ventana `NEAR_KEYWORD_WINDOW = 200` bytes post-keyword — ✅
- `extract_value()` filtra separadores (`=`, `:`, `"`, `'`, `,`, `;`, `}`, whitespace) — ✅
- Omite valores < `MIN_VALUE_LENGTH = 8` — ✅
- Genera `Finding` con flag `entropy.high_entropy_secret`, severity `Medium`, action `Warn`
- Hashing con `hash_value()` — ✅ no expone raw value

## 3. Pruebas Adversariales

| Input | Esperado | Real | Resultado |
|---|---|---|---|
| `"aaaa"` | H ≈ 0.0 | 0.0 | ✅ PASS |
| `"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"` (40-char) | H > 4.0 | 4.8219 | ✅ PASS |
| `"password=abc123"` | No detecta | 0 findings | ✅ PASS |
| `"password=J8sK2m9x…"` (30-char) | Detecta | 1 finding | ✅ PASS |
| Short value `"key=abc"` (< 8) | No detecta | 0 findings | ✅ PASS |
| All 256 bytes | H ≈ 8.0 | 8.0 | ✅ PASS |
| 100k repeticiones `'a'` | H ≈ 0.0 | 0.0 | ✅ PASS |

## 4. Integración en el Scan

- `engine.rs:246`: `crate::entropy::detect_near_keywords(text, self.entropy_threshold)` se invoca SIEMPRE como regla virtual — no depende de listados de reglas.
- Findings se mezclan con findings de regex.
- `action_overall` se computa como el máximo de todas las acciones — ✅ correcto.

## 5. HALLAZGOS DE SEGURIDAD

### 🔴 CRÍTICO: Duplicación de `shannon_entropy` byte-level vs char-level

- `entropy.rs:47`: usa **bytes** (`text.as_bytes()`) → matriz fija `[u64; 256]`
- `validator.rs:185`: usa **chars** (`s.chars()`) → `HashMap<char, usize>`
- **Problema:** para texto multi-byte (UTF-8), ambos dan resultados DIFERENTES:
  - Un emoji repetido 4× → byte-level: H=2.0, char-level: H=0.0
  - Esto puede causar **falsos positivos** o resultados inconsistentes entre el detector interno y el sistema de validación.
  - **Riesgo:** un atacante podría inyectar texto multi-byte para evadir la detección o, peor, generar falsos positivos para ocultar un verdadero secreto entre alarmas.

### 🟡 MEDIO: Sin normalización Unicode

- El detector opera a nivel de bytes, no de caracteres. Un atacante puede usar:
  - Homoglifos Unicode (ej. `pαssword` con alpha en lugar de 'a')
  - Normalización NFC/NFD distinta
  - Secuencias de escape UTF-8
- **Impacto:** un secreto con caracteres Unicode puede tener entropía inflada artificialmente (falso positivo) o no ser detectado si el keyword usa variantes Unicode.

### 🟡 MEDIO: Ventana post-keyword fija (200 bytes)

- Un secreto válido > 200 bytes después del keyword no se detecta.
- **Riesgo bajo** en práctica (secrets típicos son < 200 chars), pero un atacante podría colocar el secreto más allá de la ventana.
- **Recomendación:** considerar ventana configurable o escaneo multilínea.

### 🟢 BAJO: Sin separadores no estándar en `extract_value`

- `SKIP_CHARS` no incluye `|`, `\`, `@`, `#`, `` ` ``, `~`
- Si un secreto usa separadores exóticos, `extract_value` podría no parsear correctamente.
- **Riesgo:** muy bajo en entornos estándar (JSON, YAML, env, config).

### 🟢 BAJO: `wrapping_add` en offsets de bytes

- `kw_end.wrapping_add(NEAR_KEYWORD_WINDOW)` y `kw_end.wrapping_add(value_offset)` pueden wrappear en textos extremadamente largos (>2GB).
- **Riesgo:** puramente teórico en esta fase.

---

## Veredicto

```
╔════════════════════════════════════════╗
║            VEREDICTO: FAIL             ║
║                                        ║
║   ❌ 1 CRÍTICO (duplicación shannon)   ║
║   ⚠️  2 MEDIO   (Unicode, ventana fija)║
║   ℹ️  2 BAJO    (separadores, wrapping)║
╚════════════════════════════════════════╝
```

**Hallazgo bloqueante:** La duplicación de `shannon_entropy` con implementaciones byte-level vs char-level (DRY y divergencia funcional) debe resolverse antes de avanzar a Fase 2.

**Recomendaciones:**
1. Unificar ambas implementaciones en una sola función en `entropy.rs` y re-exportarla desde `validator.rs` o viceversa.
2. Elegir byte-level (consistente con hashing, análisis de contenido raw) o char-level (semánticamente correcto para humanos) — documentar la decisión.
3. Agregar normalización NFC para inputs Unicode.
4. Agregar test adversarial con emoji/Unicode mixto.
5. Hacer `NEAR_KEYWORD_WINDOW` configurable.
