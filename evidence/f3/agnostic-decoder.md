# Evidence Pack — Fase 3 / agnostic-decoder
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| Decodificar JSON object extrae strings | `test::decode_json_object` | Pass | ✅ |
| Decodificar JSON array extrae contenido | `test::decode_json_array` | Pass | ✅ |
| JSON anidado extrae texto profundo | `test::decode_json_nested` | Pass | ✅ |
| Plain text pasa igual | `test::decode_plain_text` | Pass | ✅ |
| Body vacío → string vacío | `test::decode_empty_body` | Pass | ✅ |
| Números/bools no generan texto falso | `test::decode_json_ignores_numbers_and_bools` | Pass | ✅ |
| UTF-8 inválido no panic (lossy fallback) | `test::decode_invalid_utf8_fallback` | Pass | ✅ |

## Casos adversariales probados
- JSON con solo números → texto vacío
- Array de objetos anidados → texto extraído recursivamente
- Bytes inválidos → no panic, lossy fallback
- Content type hint ignorado (decodificación autodetected)

## NFR aplicables
- N/A

## Archivos
- `crates/cerberus-proxy/src/decoder.rs`

## Desviaciones del plan
Ninguna. Agnostic by construction: extrae todo el texto de cualquier JSON.