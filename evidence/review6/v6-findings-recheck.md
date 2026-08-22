# Hallazgo 6 — Re-verificación adversarial (revisor loop, no modificó código)

- Worktree: `v6-findings2` (commit `12bc776`)
- Alcance: EXCLUSIVAMENTE hallazgo 6 (Pro-gate) + tear rápido del gate
- Rol: revisor adversarial independiente (viene de ciclo de loop)

---

## Tabla del hallazgo 6

| # | Hallazgo | Código | Chequeo estático (file:line) | Test | Veredicto |
|---|----------|--------|------------------------------|------|-----------|
| 6 | `pack_rollback` (modo local) no gateaba Pro ante rehidratar/rollback | `crates/cerberus/src/daemon.rs` — `pack_rollback()` | `require_pro_for_pack_ops(&license)` en **daemon.rs:592**, ANTES de `load_installed_from_dir` (daemon.rs:595) y `rollback()` (daemon.rs:597) | `pack_rollback_requires_pro_license` verde (falla SIN Pro) + `require_pro_gate_for_pack_ops` verde | **PASS** |

### Chequeo estático detallado

1. **Rollback local (`pack_rollback`, sin daemon)** — `daemon.rs:588-600`
   - `load_license(...)` (591) → `require_pro_for_pack_ops(&license)` (592) → falla Free ANTES de rehidratar/rollback. Correcto: el guard (592) precede a `load_installed_from_dir` (595) y `rollback()` (597).
2. **Worker HTTP — rollback** — `daemon.rs:374-376` gate Pro vía `require_pro_for_pack_ops` (falla `pack rollback aborted via control plane`).
3. **Worker HTTP — install** — `daemon.rs:347-349` gate Pro vía `require_pro_for_pack_ops`.
4. **Boot omite packs en Free** — `daemon.rs:306-314`: `if !license.is_pro()` → warn y omite hidratación; engine base (default rules) arranca.
5. **List libre** — `daemon.rs:512` (`pack_list`) sin gate Pro. OK.
   - helper `require_pro_for_pack_ops` definido en `daemon.rs:555` → `Result<(), String>`.

---

## Evidencia de corridas

| Comando | Resultado |
|---------|-----------|
| `cargo test -p cerberus --bin cerberus require_pro` | `1 passed; 0 failed` (`require_pro_gate_for_pack_ops ... ok`) |
| `cargo test -p cerberus --test pack_cli_e2e pack_rollback_requires_pro_license` | `1 passed; 0 failed` (falla SIN Pro, aserciones no vacías) |
| `cargo test -p cerberus --test pack_cli_e2e` (completo) | `3 passed; 0 failed` (`pack_install_requires_pro_license`, `pack_rollback_requires_pro_license`, `pack_cli_install_list_rollback_e2e` — el e2e Pro pasa rollback) |
| `cargo build --workspace` | `Finished dev profile ... in 5.39s` (sin errores) |
| `cargo clippy -p cerberus --all-targets -- -D warnings` | `Finished dev profile ... in 12.49s` (sin warnings) |

### El test adversarial NO es vacuo (evidencia de aserción)
`crates/cerberus/tests/pack_cli_e2e.rs:215-258`:
- Primero instala con licencia Pro → `install.status.code() == 0` (233).
- Luego rollback SIN Pro (`env_remove` license) → assert `status.code() != 0` (247-251) y `stderr` contiene `Pro`/`open-core`/`licencia` (252-254).

---

## Dictamen final

**HALLAZGO 6 = PASS**

Fix confirmado: el gate Pro en `pack_rollback` modo local (`daemon.rs:592`) está correctamente colocado ANTES de rehidratar/rollback, y el test adversarial `pack_rollback_requires_pro_license` realmente aserció el fallo bajo Free. Cobertura worker (install/rollback/boot/list) íntegra. Nada del fix rompió el gate (build workspace y clippy limpios; require_pro y suite pack_cli_e2e todos verdes).

Riesgos: ninguno detectado dentro del alcance pedido.