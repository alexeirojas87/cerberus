# Evidence Pack — Fase 3 / schema-adapters
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test -p cerberus-proxy` | `cargo test -p cerberus-proxy` | 46 passed; 0 failed | ✅ |
| OpenAI extrae messages[].content | `test::openai_extracts_messages_content` | Pass | ✅ |
| OpenAI extrae prompt field | `test::openai_extracts_prompt` | Pass | ✅ |
| OpenAI sin match → None | `test::openai_no_match_returns_none` | Pass | ✅ |
| Anthropic extrae messages[].content | `test::anthropic_extracts_messages` | Pass | ✅ |
| Anthropic sin match → None | `test::anthropic_no_match` | Pass | ✅ |
| try_adapt prefiere OpenAI sobre Anthropic | `test::try_adapt_prefers_openai` | Pass | ✅ |
| try_adapt fallback a None | `test::try_adapt_fallback_to_agnostic` | Pass | ✅ |

## Casos adversariales probados
- JSON sin messages/prompt → None (no forzar falso positivo)
- Múltiples messages → contenido concatenado
- Adaptador desconocido → no se aplica
- Orden de adaptadores: OpenAI primero (más común)

## NFR aplicables
- N/A

## Archivos
- `crates/cerberus-proxy/src/adapters.rs`

## Desviaciones del plan
Ninguna. Schema adapters son opcionales y se aplican antes del decoder agnóstico.