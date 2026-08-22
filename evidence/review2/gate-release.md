# Evidence Pack — Review 2: Gate Release

**Fecha:** 2026-08-20
**Revisor:** código (corridas en vivo, salida cruda capturada; sin modificar árbol)
**Método:** ejecución literal de los 7 pasos del gate, captura de salida, conteo agregado.
**Árbol:** working tree con cambios de subtareas (ver `git status` al final).

---

## Resumen de resultados

| # | Comando | Resultado | Verdict |
|---|---------|-----------|---------|
| 1 | `cargo fmt --all -- --check` | EXIT=0, 0 diffs | **PASS** |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | EXIT=0, sin warnings | **PASS** |
| 3 | `cargo test --workspace --all-targets` | 407 passed, 0 failed | **PASS** |
| 4 | `cargo test --release --workspace --all-targets` | 407 passed, 0 failed | **PASS** |
| 5 | determinismo packs (x3, release, 16 threads) | 37/37/37, 0 failed (idéntico) | **PASS** |
| 6 | determinismo cerberus-proxy / cerberus (release, 8 threads) | 58+17 / 24+2, 0 failed | **PASS** |
| 7 | mutex estático en tests con set_var (license.rs, pack.rs) | ENV_LOCK presente, todos los accesos guardados | **PASS** |

**Dictamen único del gate release: PASA.**

- Conteo total de tests en release: **407 passed, 0 failed** (0 ignored, 0 filtered).
- La carrera de `std::env` reportada en la revisión previa (v3) queda **eliminada**: 3 corridas idénticas del crate cerberus-packs bajo `--test-threads=16`.

---

## 1. `cargo fmt --all -- --check`

```
salida: (vacía — no imprime nada cuando sale limpio)
EXIT=0
```

"debe salir 0 diffs" → **0 diffs, EXIT=0, PASS**.

## 2. `cargo clippy --workspace --all-targets -- -D warnings`

```
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.56s
EXIT=0
```

"debe salir 0 errores" → **0 errores/warnings, EXIT=0, PASS**. (`-D warnings` eleva warnings a error; nada reportado.)

## 3. `cargo test --workspace --all-targets` (debug)

Todos los `test result` recolectados (grep), los 22 targets:

```
ok. 6 passed;   0 failed
ok. 24 passed;  0 failed
ok. 2 passed;   0 failed
ok. 1 passed;   0 failed
ok. 175 passed; 0 failed
ok. 15 passed;  0 failed
ok. 5 passed;   0 failed
ok. 0 passed;   0 failed
ok. 6 passed;   0 failed
ok. 7 passed;   0 failed
ok. 5 passed;   0 failed
ok. 0 passed;   0 failed
ok. 37 passed;  0 failed
ok. 58 passed;  0 failed
ok. 17 passed;  0 failed
ok. 16 passed;  0 failed
ok. 3 passed;   0 failed
ok. 0 passed;   0 failed
ok. 4 passed;   0 failed
ok. 7 passed;   0 failed
ok. 11 passed;  0 failed
ok. 8 passed;   0 failed
```

**Total: 407 passed, 0 failed.** PASS.

## 4. `cargo test --release --workspace --all-targets`

Mismas 22 suites en release. Resumen de `test result` (conteo por binario):

`6+24+2+1+175+15+5+0+6+7+5+0+37+58+17+16+3+0+4+7+11+8`

```
test result: ok. 6 passed;  0 failed  (benchkit)
test result: ok. 24 passed; 0 failed  (cerberus main)
test result: ok. 2 passed;  0 failed  (license_cli_integration)
test result: ok. 1 passed;  0 failed  (cerberus_core)
test result: ok. 175 passed;0 failed  (cerberus_engine)
test result: ok. 15 passed; 0 failed  (engine integration)
test result: ok. 5 passed;  0 failed  (precision_recall)
test result: ok. 0 passed;  0 failed  (cerberus_hardening lib_stub)
test result: ok. 6 passed;  0 failed  (failsafe)
test result: ok. 7 passed;  0 failed  (load_test)
test result: ok. 5 passed;  0 failed  (redos_fuzz)
test result: ok. 0 passed;  0 failed  (spike_proxy main)
test result: ok. 37 passed; 0 failed  (cerberus_packs ✅ p99-race target)
test result: ok. 58 passed; 0 failed  (cerberus_proxy)
test result: ok. 17 passed; 0 failed  (smoke_harness)
test result: ok. 16 passed; 0 failed  (cerberus_store)
test result: ok. 3 passed;  0 failed  (spike_proxy lib)
test result: ok. 0 passed;  0 failed  (spike_proxy main)
test result: ok. 4 passed;  0 failed  (integration spike_proxy)
test result: ok. 7 passed;  0 failed  (spike_scan lib)
test result: ok. 11 passed; 0 failed  (spike_scan main)
test result: ok. 8 passed;  0 failed  (integration spike_scan)
```

**Total: 407 passed, 0 failed, EXIT=0.** PASS.

## 5. Determinismo cerberus-packs (release, `--test-threads=16`, x3)

Comando exacto (x3 seguidos):
```
cargo test --release -p cerberus-packs --all-targets -- --test-threads=16
```

| Corrida | resultado |
|---------|-----------|
| 1 | `test result: ok. 37 passed; 0 failed` |
| 2 | `test result: ok. 37 passed; 0 failed` |
| 3 | `test result: ok. 37 passed; 0 failed` |

**3/3 idénticas (37/0). La carrera reportada está eliminada.** PASS.

## 6. Determinismo cerberus-proxy / cerberus (release, 8 threads)

```
cargo test --release -p cerberus-proxy --all-targets -- --test-threads=8
→ ok. 58 passed; 0 failed   (lib)   +   ok. 17 passed; 0 failed (smoke_harness)

cargo test --release -p cerberus --all-targets -- --test-threads=8
→ ok. 24 passed; 0 failed   (main)   +   ok. 2 passed; 0 failed  (license_cli_integration)
```

Sin carreras nuevas. PASS (informativo).

## 7. Serialización por mutex estático de los tests con set_var en cerberus-packs

Búsqueda: `static ENV_LOCK: Mutex<()>` (grep en `crates/cerberus-packs/src/*.rs`).

**license.rs** — `crates/cerberus-packs/src/license.rs`:
- L302: `static ENV_LOCK: Mutex<()> = Mutex::new(());` (dentro de `mod tests`, con `use std::sync::Mutex;` L297).
- Todos los tests que escriben/borran env **toman el guard**:
  - L369 `license_without_trust_root_rejected` → guard + `remove_var("CERBERUS_LICENSE_PUBLIC_KEY")` L382.
  - L391+403 `license_from_file_signed_with_env_root` → guard + `set_var("CERBERUS_LICENSE_PUBLIC_KEY")` (el único `set_var` de todo el crate).
  - L413+435 `license_rejects_owner_key_as_untrusted_root` → guard + `remove_var`.
- Patrón: `let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);` — protege contra pánico-poisoning.

**pack.rs** — `crates/cerberus-packs/src/pack.rs`:
- L193: `static ENV_LOCK: Mutex<()> = Mutex::new(());`.
- L264 `pack_extract_requires_trust_root` → guard + `remove_var("CERBERUS_PACK_TRUST_ROOT")` L271.
- Sole repair: `pack_extract_verifies_and_deserializes` usa `extract_with_root` con root pasado por parámetro (sin tocar env).

**Determinismo:` test2` --test-threads=16 x3 sin rachas (ver paso 5) => la serialización funciona y no queda acceso env sin guardia en cerberus-packs.**

PASS — solo 1 `set_var` sobreviva en el crate, y sus 4 puntos de mutación de env están todos bajo el mutex.

---

## Alcance extra (fuera de tu pedido, no tocado)

Encontré un crate adicional con mutación de `std::env` en tests: `crates/cerberus/src/daemon.rs` (L478-479 `set_var`, L491/505/508/515/516 `removeVar`), con **su propio** `ENV_LOCK` estático (L419 `static ENV_LOCK: Mutex<()> = Mutex::new(())`) tomado en los 2 tests que tocan env (L472, L512). Además en `crates/cerberus/tests/license_cli_integration.rs` L57-58/L92 se usa `.env()` en binario hijo via `std::process::Command` (no carrera: env del proceso hijo, no del proceso test).

Ese crate pasa release determinístico en el paso 6. Divers parasites en este repo usan el sabor de huérfano correcto (cada crate su `ENV_LOCK` scoped propio). **No hay ningún otro crate con env-race sin guardia** (grep `env::(set_var|remove_var)` sin match fuera de cerber-packs y de cerberus/daemon.rs).

## Nota metodológica
- No se modificó ningún archivo fuente; solo ran los comandos y escribí este archivo.
- Salida cruda completa: capturada en la sesión; acá el mínimo esencial (contadores `test result`, EXIT codes).
- `git status` al momento de la corrida muestra working tree con cambios sin commitear (Cargo.lock, license.rs, pack.rs, updater.rs, daemon.rs, main.rs, proxy/*, store.rs, tests, docker-compose, etc.). El gate se corrió sobre ese árbol.