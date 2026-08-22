# F8 Revisión adversarial — a04a84d

- reviewer identity: f8-review-adv
- worktree aislado: `/var/folders/l8/v1pj_5ms6xb73t26kn85l7h80000gn/T/opencode/f8-reviewer`
- commit revisado: `a04a84d` — feat(F4/F8): abrir fases 4 y 8 del gauntlet — windows, MITM wiring, feedback dev, installers, Helm, telemetría opt-in
- host real: darwin/arm64 (macos/aarch64). No se modificó código fuente ni tests.

---

## 1. `tools/release/brew.rb` — Homebrew formula template

- `ruby -c tools/release/brew.rb` -> `Syntax OK`.
- Template con placeholders: `version "{{VERSION}}"` (brew.rb:24), y `CERBERUS_MACOS_X86_64_SHA256 = "{{SHA256_MACOS_X86_64}}"` etc. (brew.rb:26-29).
- URLs en GitHub releases con template `v#{version}` + `#{version}`, por plataforma (brew.rb:33,36,43,46): `https://github.com/alexeirojas87/cerberus/releases/download/v#{version}/cerberus-#{version}-{macos|linux}-{aarch64|x86_64}.tar.gz`, cada una con su `sha256`.
- `install` = `bin.install "cerberus"` (brew.rb:52); `test` = `system "#{bin}/cerberus", "--version"` (brew.rb:65).

**Dictamen: PASS**

---

## 2. `tools/release/fill_brew_formula.sh`

- `bash -n tools/release/fill_brew_formula.sh` -> OK.
- `sha_for()` extrae de `--platforms` (dist/SHA256SUMS) con `awk 'index($0,needle){print $1; exit}'`; needle = nombre exacto del artefacto `cerberus-<v>-<os>-<arch>.tar.gz` (lineas 42-53).
- Sustitución de los 5 placeholders vía `sed` hacia `$OUT` (default `dist/cerberus.rb`; `--install` -> `contrib/homebrew/cerberus.rb`, linea 31).

Ejecución real:
```
./tools/release/fill_brew_formula.sh --version 0.1.0 --platforms dist/SHA256SUMS --out dist/cerberus.rb
warning: no hay sha256 para 'cerberus-0.1.0-macos-x86_64.tar.gz' (placeholder cero)   (x3)
✔  Formula generada en dist/cerberus.rb
   sha256 macos-aarch64 : 0d2b076bf7eed6dc…
ruby -c dist/cerberus.rb  ->  Syntax OK
```
- `macos-aarch64` rellenado con el sha real `0d2b076bf7eed6dc…f2470120` desde SHA256SUMS; plataformas ausentes -> `000…0` con **warning (no aborta)**; comportamiento documentado (lineas 40-41, 47-49).

**Dictamen: PASS**

---

## 3. `install.sh` (raiz)

- `sh -n install.sh` -> OK.
- Detecta OS/arch (lineas 16-26): `Darwin->macos`, `Linux->linux`, `x86_64|amd64->x86_64`, `aarch64|arm64->aarch64`; else exit 1.
- `BINARY="cerberus-${VERSION}-${OS}-${ARCH}.tar.gz"`, URL `.../download/v${VERSION}/${BINARY}` (lineas 33-34) — coincide con artefacto REAL `dist/cerberus-0.1.0-macos-aarch64.tar.gz`.
- Extrae binario `cerberus` de la raiz del tar -> `$INSTALL_DIR/cerberus`, chmod +x (lineas 69-74); layout verificado con `tar tzf` (solo `cerberus`).
- Checksum: `if [ -n "${CERBERUS_SHA256:-}" ]` compara `(shasum -a 256 || sha256sum) < f` contra la var; mismatch -> `exit 1` (lineas 56-62). Probada la logica en vivo: `CHECKSUM-DETECT OK 1aecf10…e42` + fallback `sha256sum` OK. Sin env -> `⚠️ warning` no bloqueante.

**Dictamen: PASS**

---

## 4. `tools/release/build_release.sh`

- `bash -n` -> OK.
- Ejecución real: `bash tools/release/build_release.sh 0.1.0` -> `Finished release profile` (27.34s) -> `==> Empaquetado dist/cerberus-0.1.0-macos-aarch64.tar.gz` (5 433 257 bytes) y `dist/SHA256SUMS` con `0d2b076bf7eed6dc5abd8f8babc3f437f34659a856a2f5dbe79ef9fab2470120`.
- `tar tzf dist/cerberus-0.1.0-macos-aarch64.tar.gz` -> `cerberus` (binario en raiz; lo esperan install.sh y brew.rb).
- Windows: `[ "$OS" = "windows" ] && EXT="zip"` (linea 77); zip con `+j` o python zipfile con `cerberus.exe`.

**Dictamen: PASS** — con nota adversarial: `SHA256SUMS` se sobrescribe con `>` (linea 127), no se agrega `>>`; un multi-plataforma en la misma carpeta `dist/` deja solo la ultima suma (fill_brew_formula lo tolera con cero+warning). Riesgo de proceso CI.

---

## 5. `packaging/deb` + `packaging/rpm/cerberus.spec`

- `sh -n packaging/deb/postinst` -> OK (y `prerm`).
- `deb/control`: placeholders `{{VERSION}}`/`{{ARCH}}` resueltos por `packaging/deb/build_deb.sh` (sed -> dpkg-deb); `postinst` chmod 755/daemon manual.
- `cerberus.spec`: `install -D -m 0755 cerberus -> %{buildroot}%{_bindir}`, `%files %{_bindir}/cerberus`, `%post/%preun/%postun` con `cerberus --version`/`stop`; `Source0` = mismo tarball naming.

**Dictamen: PASS** — nota adversarial: `BuildArch: x86_64` hardcodeado mientras el comentario menciona aarch64 (spec linea 6); rpm aarch64 exige editar a mano.

---

## 6. `packaging/winget/`

| Manifest | Parse | Contenido clave |
|---|---|---|
| `alexeirojas87.Cerberus.installer.yaml` | python yaml -> OK | `PackageIdentifier: alexeirojas87.Cerberus`, `PackageVersion: 0.1.0`, `InstallerType: msi`, `InstallerUrl: https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-windows-x86_64.msi` |
| `alexeirojas87.Cerberus.version.yaml` | OK | PackageIdentifier + PackageVersion |
| `alexeirojas87.Cerberus.locale.en-US.yaml` | OK | PackageIdentifier + PackageVersion + metadatos |

Comandos: `python3 -c "import yaml; yaml.safe_load(open('<file>'))"` -> `OK` × 3.

**Dictamen: FAIL (punto 6)** —
- `InstallerUrl` apunta a **`.msi`** (`cerberus-0.1.0-windows-x86_64.msi`), mientras el pipeline (`build_release.sh` linea 77 + `release.yml` linea 68 `ext: zip`) produce **`.zip`**. El MSI no se genera en ningun job: en `release.yml` `wix` aparece **0** veces (`grep -c wix release.yml` = 0), y los READMEs (`tools/release/README_F8.md:116-118`, `packaging/winget/README.md:69-72`) lo dejan como "manual/out-of-band" subido a mano al release.
- `InstallerSha256` = placeholder `000…0` (rechazado por winget-pkgs mientras no se rellene).
- La expectativa del enunciado (`…/cerberus-0.1.0-windows-*.zip`) NO se cumple.

---

## 7. HELM `deploy/helm/cerberus/`

- `which helm` -> no encontrado. **Helm ausente; validado solo YAML** (documentado, segun §7).

| Check | Resultado |
|---|---|
| `values.yaml`, `values-prod.yaml`, `Chart.yaml` | `yaml.safe_load` -> OK |
| templates (`configmap.yaml`, `deployment.yaml`...) | parseo falla por braces Go `{{…}}` (esperado sin helmand) |
| `configmap.yaml` | materializa `listen: 0.0.0.0:{{targetPort}}` -> 8080 default; `mode: enforce`; `fail_policy: closed`; `upstreams`: openai/anthropic/gemini/default; `telemetry.enabled: false`, `interval_secs: 86400` |
| `deployment.yaml` | args `start --port 8080`; volumeMounts config -> `/root/.cerberus/config.yaml` (subPath, readOnly)+ emptyDir data -> `/root/.cerberus`; env `CERBERUS_ADMIN_TOKEN` via `secretKeyRef …-admin/admin-token` (si token no vacio) |
| `secret.yaml` | `required "config.admin.token is REQUIRED…"` cuando `config.admin.enabled=true` (default `true`) -> sin token el install FALLA el `required` (estatico); secret con `b64enc` |
| Nota | daemon corre como root en el pod (documentado en values.yaml); env reutilizado por K8s |

- `cargo test -p cerberus-packs telemetry` -> **12 passed, 53 filtered out**.

**Dictamen: PASS (estatico)** — helm no instalado; estructura del chart valida, configmap/secret/deployment cumplen lo descrito; sin token no instala por `required`.

---

## 8. Telemetría (`crates/cerberus-packs/src/telemetry.rs`)

| Check | Evidencia |
|---|---|
| Timeout | `TELEMETRY_TIMEOUT_SECS: u64 = 5` (telemetry.rs:23) -> `Client::builder().timeout(…)` (lineas 236-244) |
| No red si disabled/sin endpoint | `send_inner` (lineas 251-259): `if !config.enabled { return Ok(()) }` y `let Some(endpoint) = effective_endpoint(…) else { return Ok(()) }`; el POST solo existe en `post_json` (lineas 278-288), alcanzable SOLO tras ambos guards. `send_background` (151-160) tampoco spawn sin enabled+endpoint. |
| Payload | `TelemetryPayload` (lineas 76-91): `version, uptime_secs, rule_count, event_count, license_tier, os, install_id` — sin secretos, sin rutas, sin findings |
| `install_id` | uuid v4 (`generate_install_id`, 204-206); persistencia `~/.cerberus/install_id` (`install_id_file` 163-171, `load_or_generate_id` 173-187). HOME `/root` -> contenedor K8s |
| Tests | `cargo test -p cerberus-packs telemetry` -> 12 passed (mock TCP `TcpListener`, `mpsc`, ENV_LOCK) |

**Dictamen: PASS** — red solo con `enabled && endpoint`; timeout 5s; payload anonimo sin datos sensibles; install_id uuid persistente; tests verdes con mock TCP.

---

## 9. Adversarial

| Caso | Dictamen | Evidencia |
|---|---|---|
| fill_brew_formula sin `--version` | fallo limpio | `falta --version` + `exit 1` (linea 36); no escribe formula |
| fill_brew_formula sin `--platforms` | formula con sha `000…0` | escribe `000…0` + warning (lineas 44, 47-49); `ruby -c` Syntax OK pero brew rechazaria el fetch; comportamiento documentado, riesgoso si se publica por error |
| Naming cross-OS | gap real | windows: build_release produce `.zip`; winget pide `.msi` (fuera de linea, sin job WIX en release.yml) |
| install.sh en Windows | coherente | install.sh es unix: en MSYS/MINGW `uname -s` no matchea `Linux|Darwin` -> "Unsupported OS" exit 1 (lineas 16-19); cubierto por winget/MSI |

---

## 10. Gates previos

| Gate | Resultado | Evidencia |
|---|---|---|
| `cargo clippy --workspace --all-targets -- -D warnings` | 0 | `No issues found`, exit 0 |
| `cargo fmt --all -- --check` | 0 diffs | salida vacia, exit 0 |
| `cargo test -p cerberus-packs --all-targets` | 65/65 | `65 passed (1 suite, 0.03s)` |

**Dictamen: PASS** — 0 clippy, 0 fmt, 65/65 tests.

---

## Juicio del revisor

- **FAIL**: §6 winget — `InstallerUrl` `.msi` no coincide con el `.zip` que si produce el pipeline; job WIX inexistente en `release.yml`; `InstallerSha256` placeholder `0000…0`.
- **NOTA (riesgo, no FAIL)**: SHA256SUMS se sobrescribe por build; formula `brew` puede quedar con sha `000…0` si se publica sin agregar sumas; `BuildArch` x86_64 fijo en rpm.
- **PASS**: resto (brew.rb, fill_brew, install.sh, build_release, deb/rpm, helm-validate-estatico, telemetria, gates).

Sin modificaciones a código fuente; pruebas exclusivamente en dist/ y temps.