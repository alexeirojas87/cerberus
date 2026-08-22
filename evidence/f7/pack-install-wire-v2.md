# Evidence Pack — f7/pack-install-wire-v2
- Intento: FIX 1    Revisor: worker `task_47c1514d5bc0`    Veredicto: PASS

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida citada | Resultado |
|---|---|---|---|
| Handler HTTP acepta wire v2 con bytes | `cargo test -p cerberus-proxy pack_install_wire_v2_accepts_bytes_and_never_opens_legacy_path` | `1 passed; 0 failed`; el fake worker recibió exactamente el JSON firmado y `origin_name=demo.json` | ✅ |
| Forma legada `{"path": ...}` rechazada | mismo test | HTTP `400`; error menciona `wire v1`; el worker conservó exactamente una request (la v2) | ✅ |
| El servidor no interpreta filesystem remoto | mismo test | incluso apuntando a un pack válido visible en disco, la forma `path` se rechaza antes del worker | ✅ |
| Parser wire fail-safe | `cargo test -p cerberus-packs wire` | `8 passed; 0 failed` | ✅ |
| Cliente CLI transporta bytes, no path | `cargo test -p cerberus --test pack_cli_via_api` | `4 passed; 0 failed` | ✅ |
| Suite de packs | `cargo test -p cerberus-packs` | `59 passed; 0 failed` | ✅ |
| Workspace completo (corrida previa de esta unidad) | `cargo test --workspace` | `532 passed; 0 failed`; preservada como historia, no como cifra final | ✅ |
| Workspace completo (estado final v6.1) | `cargo test --workspace` | `534 passed; 0 failed` (32 suites, 2026-08-21; incluye la paridad dashboard→wire v2) | ✅ |
| Lints estrictos | `cargo clippy --workspace --all-targets -- -D warnings` | `No issues found` | ✅ |

## Casos adversariales probados

- Body vacío, no UTF-8, oversize, versión desconocida, pack incompleto y `origin_name` inseguro son rechazados por el parser wire.
- Un archivo válido existe en el path legado enviado por HTTP; el handler responde `400` sin producir un segundo comando de install. Por tanto, la frontera servidor/worker sólo recibe contenido wire v2 validado, nunca una ruta.
- El CLI canonicaliza y lee localmente, transporta bytes exactos y no filtra directorios del cliente en el body.

## Riesgos residuales

- El test demuestra la ausencia de resolución de paths por contrato y por no invocación del worker; no instrumenta syscalls del proceso con `dtrace`/`strace`.
- La verificación criptográfica definitiva sigue ocurriendo en el worker contra el trust root del daemon; el parser wire sólo valida estructura y cotas antes de encolarlo.
