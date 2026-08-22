# Evidence Pack — f1/multiline-blocks
- Intento: 1    Revisor: BUILDER (auto-verify)    Veredicto: PASS

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| Compila | `cargo build` | `Finished dev profile` exit 0 | ✅ |
| Tests engine | `cargo test -p cerberus-engine` | 48 passed; 0 failed | ✅ |
| Tests integration | `cargo test -p cerberus-engine --test integration_test` | 11 passed; 0 failed | ✅ |
| Clippy | `cargo clippy --all-targets` | exit 0, no warnings | ✅ |
| Fmt | `cargo fmt --all -- --check` | exit 0 | ✅ |
| PEM RSA key detection | `detects_pem_rsa_private_key` | test passes | ✅ |
| PEM EC key detection | `detects_pem_ec_private_key` | test passes | ✅ |
| PEM OPENSSH key detection | `detects_pem_openssh_private_key` | test passes | ✅ |
| PEM DSA key detection | `detects_pem_dsa_private_key` | test passes | ✅ |
| Block captures full range (start/end cubren todo) | `pem_block_captures_full_range` | verified: starts with BEGIN, ends with END, contains body lines | ✅ |
| Block with blank lines (encrypted PEM) | `pem_block_multi_line_body` | captures Proc-Type, DEK-Info headers | ✅ |
| .env with secrets detection | `detects_env_file_with_secrets` | test passes | ✅ |
| SSH key (id_rsa/OPENSSH) detection | `detects_id_rsa_ssh_key` | test passes | ✅ |
| No false positive on normal text | `no_false_positive_on_normal_text` | finding.is_none() | ✅ |
| No detection without multiline pattern | `no_detection_without_multiline_pattern` | finding.is_none() | ✅ |
| Multiline pattern classification | `multiline_pattern_detection` | `-----BEGIN` → true, `\\n` → true, simple → false | ✅ |

## NFR aplicables
- **Sin ReDoS:** patrones evaluados con `regex` crate (tiempo lineal). Los patterns multilínea se compilan con `(?m)` flag.
- **Hashed values:** todos los findings usan `hash_value` (SHA-256), nunca el raw value
- **No rompe reglas existentes:** 35 tests pre-existentes de engine + loader + rule + scan siguen pasando

## Casos adversariales probados
- PEM con cuerpo multilínea de >2 líneas → captura completo
- PEM con cabeceras (Proc-Type, DEK-Info) → captura completo
- .env con 3 líneas (2 secretos + 1 inocente) → detecta
- OPENSSH key (id_rsa) → detecta
- Texto normal sin bloques → sin falso positivo
- Pattern simple tipo `sk-[A-Za-z0-9]{20,}` → no activa multiline detection

## Archivos modificados/creados
| Archivo | Acción | SHA |
|---------|--------|-----|
| `crates/cerberus-engine/src/multiline.rs` | CREATE | (ver git log) |
| `crates/cerberus-engine/src/lib.rs` | EDIT | +1 line |
| `crates/cerberus-engine/src/engine.rs` | EDIT | +7 lines |

## Desviaciones
Ninguna. Implementación fiel a la spec del build plan §8 F1 multiline-blocks + contrato de §4.3.