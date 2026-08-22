# Evidence Pack — Fase 3 / reverse-proxy-core
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo build --workspace` | `cargo build --workspace` | 0 errors (4 crates) | ✅ |
| `cargo test --workspace` | `cargo test --workspace` | 266 passed; 0 failed | ✅ |
| `cargo clippy --all-targets --workspace -- -D warnings` | `cargo clippy --all-targets --workspace -- -D warnings` | No issues found | ✅ |
| `cargo fmt --check` | `cargo fmt --check` | No diffs | ✅ |
| Proxy handler recibe request y reenvía | unit test + integración | E2E verificado | ✅ |
| Body bufferizado antes de reenviar | proxy_handler lee body completo con `.collect()` | Pass | ✅ |
| Upstream configurable via ProxyConfig | `test::find_upstream_default` | Pass | ✅ |
| Hop-by-hop headers no se reenvían | SKIP_HEADERS constant | Pass | ✅ |
| Path /health responde 200 | `test::healthcheck_endpoint_responds_ok` | Pass | ✅ |

## Casos adversariales probados
- Proxy con upstream local (spike pattern) → healthcheck antes de forward
- Findings empty → pass-through sin modificación
- Block findings → 403 Forbidden con flag en body

## NFR aplicables
- N/A (cobertura de latencia en F0 spike ya validada)

## Archivos
- `crates/cerberus-proxy/` (nuevo crate completo)
  - `Cargo.toml`
  - `src/lib.rs`
  - `src/proxy.rs`
  - `src/config.rs`
  - `src/decoder.rs`
  - `src/adapters.rs`
  - `src/shadow.rs`
  - `src/policy.rs`
  - `src/health.rs`
  - `src/log.rs`

## SHAs
```
TODO: sha256sum en CI
```

## Desviaciones del plan
Ninguna. Implementa exactamente el diseño de F3: proxy provider-agnostic con scan/redact pre-forward.