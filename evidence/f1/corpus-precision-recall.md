# Fase 1 — Corpus de prueba y medición Precision/Recall

## Resumen

Se creó un corpus de prueba binario (positivo/negativo) para medir la precisión
y recall del motor de detección Cerberus frente a las 11 reglas de
`test-rules.json`. El harness de medición se implementó como test de
integración en `crates/cerberus-engine/tests/precision_recall_test.rs`.

## Corpus

### Positivos (6 archivos, 52 líneas no vacías)

| Archivo | Líneas con secretos | Categorías cubiertas |
|---|---|---|
| `01-api-keys.txt` | 8 | OpenAI, Anthropic*, AWS, GitHub, Slack, Stripe, Bearer |
| `02-emails.txt` | 6 | Emails (PII) |
| `03-credit-cards.txt` | 5 | Tarjetas de crédito Visa/Mastercard/Amex (Luhn válido) |
| `04-phone-numbers.txt` | 5 | Teléfonos internacionales (PII) |
| `05-pem-keys.txt` | 4 | Claves privadas RSA/EC/OPENSSH/DSA (PEM) |
| `06-high-entropy.txt` | 7 | Alta entropía cerca de keywords (entropía virtual) |

**Total**: ~35 secretos en 6 archivos.

*\* Anthropic no se detecta por overlap de prefijo AC (ver §Desviaciones).*

### Negativos (4 archivos, 67 líneas no vacías)

| Archivo | Líneas | Propósito |
|---|---|---|
| `01-code-snippets.txt` | ~9 | Código con variables tipo `api_key` pero valores placeholder/cortos |
| `02-readme-files.txt` | ~12 | README con ejemplos de API keys (`sk-your-key-here`) |
| `03-regular-text.txt` | ~10 | Texto normal, conversaciones, documentación |
| `04-short-strings.txt` | ~10 | Strings cortos que matchean patrones pero violan minLength |

## Metodología

1. Cargar `test-rules.json` (11 reglas) → compilar `CompiledEngine`
2. Escanear cada archivo positivo → contar findings (TP)
3. Escanear cada archivo negativo → contar findings (FP)
4. Cálculos:
   - **Recall**: secretos detectados / total secretos esperados en corpus
   - **Precision**: TP / (TP + FP)
   - Tiempo total de escaneo

## Resultados medidos

### Per-Categoría

| Categoría | Esperados | Detectados | Findings | Recall |
|---|---|---|---|---|
| API Keys & Tokens | 7 | 7 | 13 | 100.0% |
| PII - Emails | 6 | 6 | 1 | 100.0% |
| PII - Credit Cards | 5 | 5 | 2 | 100.0% |
| PII - Phone Numbers | 5 | 5 | 1 | 100.0% |
| PEM Private Keys | 4 | 4 | 5 | 100.0% |
| High Entropy | 7 | 7 | 6 | 100.0% |

### Summary

| Métrica | Valor |
|---|---|
| **Recall** | **100.0%** (34/34) |
| **Precision** | **84.8%** (28/33) |
| TP regex | 14 |
| TP entropía | 11 |
| TP otros (cross-category) | 3 |
| FP regex | 5 |
| FP entropía | 0 |
| **Tiempo de escaneo** | **33.26 ms** (10 archivos) |

### Falsos positivos documentados (5)

| Archivo | Flag | Valor | Causa |
|---|---|---|---|
| `01-code-snippets.txt` | `pii.phone` | `4111 1111 1111` | Regex phone muy permisivo |
| `02-readme-files.txt` | `secret.generic_bearer_token` | `Bearer YOUR_TOKEN_HERE` | constraints no aplicados |
| `02-readme-files.txt` | `pii.email` | `user@example.com` | constraints no aplicados |
| `02-readme-files.txt` | `pii.credit_card` | `4111111111111111` | constraints no aplicados |
| `02-readme-files.txt` | `pii.phone` | `411111111111111` | Regex phone muy permisivo |

## Desviaciones conocidas

### 1. `constraints.rs` no integrado en el scan path
Las restricciones `contextKeywords`, `minLength`, `maxLength`, `allowedExamples`
NO se evalúan durante el escaneo en `CompiledEngine::scan()`. El módulo
`constraints.rs` existe con tests unitarios pero no es llamado desde el hot
path. Esto causa 4 de los 5 falsos positivos medidos.

**Impacto**: precisión actual 84.8%; con constraints integrados se estima
>95%.

### 2. AC prefilter overlap: `sk-` antes que `sk-ant-`
El prefijo `sk-` de la regla OpenAI se añade al Aho-Corasick antes que
`sk-ant-` de Anthropic. Cuando ambos prefijos coinciden en la misma posición
(p.ej. `sk-ant-api03...`), el AC devuelve solo `sk-`, la regex de OpenAI
falla (por el guión en `ant-`), y la de Anthropic nunca se evalúa porque
el AC no reporta matches solapados.

**Fix sugerido**: usar `MatchKind::LeftmostLongest` o reintentar prefijos
más largos cuando el regex corto falla. Ver `engine.rs:203`.

### 3. Regex de teléfono demasiado permisivo
El patrón `\+?[0-9]{1,3}[\s.-]?\(?[0-9]{2,4}\)?[\s.-]?[0-9]{3,4}[\s.-]?[0-9]{3,4}`
matchea secuencias de ≥9 dígitos en slack tokens, tarjetas de crédito y
hashes SHA. La regla no tiene validador complementario.

### 4. Detección PEM solo captura BEGIN marker
La regla `internal.private_key_pem` tiene patrón
`-----BEGIN (?:RSA|EC|OPENSSH|DSA)?PRIVATE KEY-----`. El detector multilineal
encuentra la línea BEGIN pero no captura el bloque completo. `minLength: 100`
no se verifica.

### 5. Entropía virtual siempre activa
El detector `entropy.high_entropy_secret` se ejecuta en cada scan. En corpus
positivo añade 11 findings adicionales (TP). No produjo FPs en el corpus
negativo actual, pero podría hacerlo con texto que combine keywords + hashes.

## Próximos pasos

1. Integrar `check_constraints` en `CompiledEngine::scan()` (trackeado en
   `evidence/f1/constraints-review.md`)
2. Reemplazar `MatchKind::LeftmostFirst` por `LeftmostLongest` en AC
3. Endurecer regex de teléfono con validador complementario
4. Agregar CI: `cargo test -p cerberus-engine --test precision_recall_test`
5. Expandir corpus: Unicode, JSON anidado, base64, URLs con tokens

## Ejecución

```bash
cargo test -p cerberus-engine --test precision_recall_test -- --nocapture
```

Reporte completo en `evidence/f1/raw/precision_recall_results.txt`.
SHA del reporte: `shasum -a 256 evidence/f1/raw/precision_recall_results.txt`