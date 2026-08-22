# Evidence Pack — f0/spike-proxy (REVISOR 1 · correctness)
- Intento: 1    Revisor: Revisor-1-correctness (independiente, adversarial, contexto fresco)    Veredicto: **PASS (con 1 bug reportado)**
- Fecha: 2026-08-16    Worktree: `cerberus-wt-f0-proxy-review-correctness` (detached HEAD `8db7d31`)
- Misión: romper la unidad. Todas las verificaciones se ejecutaron de cero, sin confiar en la evidencia del builder.

## Criterios de aceptación

| Criterio | Comando ejecutado | Salida (citada/adjunta) | Resultado |
|----------|-------------------|-------------------------|-----------|
| Build workspace 0 errores | `cargo build --workspace` | `Finished dev profile ... 111 crates compiled` | ✅ |
| Tests spike-proxy: 7 pass (3 unit + 4 integration) | `cargo test -p spike-proxy` | `3 passed; 0 failed` (lib) + `4 passed; 0 failed` (tests/integration.rs) = **7 passed; 0 failed** | ✅ |
| Clippy 0 errores (`-D warnings`) | `cargo clippy -p spike-proxy --all-targets -- -D warnings` | `Finished dev ... no warnings emitted` | ✅ |
| fmt 0 diffs | `cargo fmt --check` | sin salida (0 diffs) | ✅ |
| E2E: reenvío POST → 200 + body upstream | `curl -i -X POST http://127.0.0.1:18090/v1/chat/completions -d '{"prompt":"hello"}'` | `HTTP/1.1 200 OK`, body `{"body_len":18,"method":"POST","ok":true,"path":"/v1/chat/completions",...}` con `x-upstream: spike-upstream` | ✅ |
| E2E: propagación de status | `curl -o /dev/null -w "%{http_code}" http://127.0.0.1:18090/notfound` | `200` (upstream sintético responde 200 a todo; status se propaga 1:1) | ✅ |
| E2E: body íntegro (5000 B) | `curl -X POST http://127.0.0.1:18090/test -d "$(python3 -c "print('x'*5000)")"` → `json.body_len` | `5000` (exacto) | ✅ |
| E2E: query string + headers + GET | curl a `/v1/chat?model=...`, header `x-test-header`, GET `/health` | path/method/header/body_len correctos | ✅ |
| Bench JSON schema | `--bench --payload-kb 1 --iterations 50` → assert keys | `schema OK`; overhead `{'p50_ms':0.0986,'p99_ms':0.0}` | ✅ |
| Edge case `--payload-kb 0` | `--bench --payload-kb 0 --iterations 20` | JSON válido, direct/proxy medidos | ✅ |
| Edge case `--iterations 1` | `--bench --payload-kb 1 --iterations 1` | JSON válido, overhead `{'p50_ms':0.125,'p99_ms':0.125}` | ✅ |

## Casos adversariales probados (intento de romper)

- **Upstream caído** → `curl` contra el proxy con el upstream muerto: **NO devuelve HTTP**, la conexión se cierra con `Empty reply from server` (código `000`), y el log del proxy muestra `proxy connection error: error from user's Service`. Un proxy correcto debería responder `502 Bad Gateway`. **→ BUG (ver abajo)**.
- `/notfound` → `200` (esperado: el upstream sintético siempre responde 200; la propagación de status es fiel, no hay rutas "not found" en el upstream).
- Body 5000 B (`x`*5000 y `y`*5000) → `body_len` exacto = 5000 en ambos. Sin truncación ni corrupción.
- Query string `?model=gpt-4o&stream=true` → reenviado (path correcto en upstream).
- Header custom `x-test-header` → llega al upstream (`test_header = cerberus-spike`).
- GET sin body → `GET /health 0`, sin pánico.
- `--payload-kb abc` (no numérico) → NO falla con error: **ejecuta los 4 tamaños por defecto silenciosamente** (parse error ignorado). UX frágil, no rompe la funcionalidad.
- `--iterations abc` → silenciosamente cae a default 1000 (mismo patrón).
- Bench default sin `--payload-kb` → array de 4 objetos [1,10,50,100] KB, todos los keys presentes.

## NFR aplicables
- Latencia: no es el foco de este revisor (lo cubre el panel de performance). Observación: en la corrida de 1 KB x50 el overhead p99 salió `0.0` porque el clamp `max(0.0)` del overhead recorta diferencias negativas por jitter; p50 = ~0.1 ms (bien bajo presupuesto).
- Seguridad: fuera de alcance del revisor de correctness.

## Si FAIL: qué falla y cómo reproducirlo
No aplica: la unidad pasa todos los criterios explícitos. Bug reportado para FIX (ver abajo).

## BUG REPORTADO (no bloqueante para los criterios de la tarea, pero real)
**Proxy sin 502 ante upstream caído.** `proxy_handler` (`crates/spike-proxy/src/proxy.rs:155-157`) propaga el error del `client.request(...)` como `Err(String)`; hyper lo convierte en cierre de conexión sin respuesta HTTP, en vez de un `502 Bad Gateway`.

Reproducción:
```bash
# 1) arrancar upstream + proxy (ver §E2E)
# 2) matar el upstream
pkill -f "spike-proxy --upstream"
curl -sv -X POST http://127.0.0.1:18090/v1/chat/completions -d '{"prompt":"hello"}'
# → * Empty reply from server  (code 000)
```
Impacto: cliente recibe fallo de conexión en vez de un status HTTP accionable; relevante para el comportamiento esperado de un proxy real (F3 reverse-proxy-core). En el spike F0 la decisión de stack/overhead no se ve afectada.
