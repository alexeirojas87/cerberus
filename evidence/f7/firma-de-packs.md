# Evidence Pack — Fase 7 / firma-de-packs
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 320 passed; 0 failed | ✅ |
| Firma y verificación | `test::pack_sign_and_verify` | verify OK | ✅ |
| Pack manipulado → verificación falla | `test::pack_tampered_signature_fails` | verify error | ✅ |
| Extract verifica firma + deserializa | `test::pack_extract_verifies_and_deserializes` | RulePack válido | ✅ |
| Clave diferente → verificación falla | `test::different_key_fails_verification` | verify error | ✅ |

## Esquema de firma
- Algoritmo: **Ed25519** (ed25519-dalek v2)
- Formato: `SignedRulePack { pack_json, signature_hex, signer_public_key_hex }`
- Verificación: `verify_strict` antes de deserializar
- Serialización: JSON completo del RulePack, firmado antes de cualquier transformación

## Archivos
- `crates/cerberus-packs/src/pack.rs` (SignedRulePack)

## Desviaciones del plan
Ninguna. Firma Ed25519 con verificación estricta.