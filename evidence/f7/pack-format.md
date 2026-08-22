# Evidence Pack — Fase 7 / pack-format
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (9 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 320 passed; 0 failed | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Pack JSON roundtrip | `test::pack_roundtrip_json` | metadata/rules preserved | ✅ |
| Pack compile succeeds | `test::pack_compile_succeeds` | engine build ok | ✅ |
| Pack metadata version | `test::pack_metadata_version` | "1.0.0" | ✅ |
| Pack rule count | `test::pack_rule_count` | 1 | ✅ |

## Formato del RulePack
```json
{
  "metadata": {
    "name": "secrets-core",
    "version": "1.2.0",
    "description": "...",
    "author": "Cerberus",
    "published": "2026-08-17T00:00:00Z",
    "min_engine_version": "0.1.0"
  },
  "rules": [...]
}
```

## Archivos
- `crates/cerberus-packs/src/pack.rs` (nuevo)

## Desviaciones del plan
Ninguna. Pack format versionado con metadatos completos.