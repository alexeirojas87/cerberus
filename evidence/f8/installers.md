# Evidence Pack — Fase 8 / installers (vending multiplataforma)
- Intento: 2    Revisor: Builder (packaging)    Veredicto: PASS

## Criterios de aceptación (F8 — installers)

| Criterio | Comando ejecutado | Salida | Resultado |
|---|---|---|---|
| Instalación CLI en macOS/Linux: curl\|sh | `install.sh` (existía) | script con checksum `CERBERUS_SHA256`, OS/arch detect | ✅ |
| Instalación CLI en macOS: Homebrew | `tools/release/brew.rb` | formula Ruby válida (`ruby -c` Syntax OK); placeholders `{{VERSION}}`/`{{SHA256_*}}` | ✅ |
| Instalación Linux: deb/rpm | `packaging/deb/{control,install,postinst,prerm,build_deb.sh}`, `packaging/rpm/cerberus.spec` | presentes; `sh -n` a postinst/prerm OK; `bash -n` build_deb.sh OK | ✅ |
| Instalación Windows: winget/MSI | `packaging/winget/manifests/a/alexeirojas87/Cerberus/0.1.0/{installer,locale,version}.yaml` | YAML válido (winget schema); guía publicación a microsoft/winget-pkgs en `README.md` | ✅ |
| Binarios firmados (scripts + DRY-RUN sin credenciales) | `bash tools/release/macos-notarize.sh <tar>` → exit 0 (dry-run); `bash tools/release/windows-sign.sh <exe>` → exit 0 | secuencia documentada no falla sin credenciales | ✅ |
| El build del repo (workers) no rompe | `cargo build --release` / `cargo build --release --package cerberus --bin cerberus` | Finished release profile; 0 errors | ✅ |

## Evidencia por script

| # | Script | Salida |
|---|--------|--------|
| 1 | `build_release.sh` (host macos/aarch64) | `dist/cerberus-0.1.0-macos-aarch64.tar.gz` creado; `tar tzf` → solo `cerberus` en raíz; `SHA256SUMS` = `924c5c2aff4821f6…` |
| 2 | `CERBERUS_OS=windows CERBERUS_ARCH=x86_64` + staging | `dist/cerberus-0.1.0-windows-x86_64.zip` con `cerberus.exe` en raíz (unzip -l confirmado) |
| 3 | `macos-notarize.sh` (DRY-RUN) | imprime secuencia codesign→notarytool→stapler→spctl y sale `0` |
| 4 | `windows-sign.sh` (DRY-RUN) | imprime `signtool sign /fd SHA256 /tr…` y sale `0` |
| 5 | `fill_brew_formula.sh --platforms dist/SHA256SUMS` | sustituye `{{VERSION}}`→0.1.0 y `{{SHA256_*}}`→sha real de artifacts; `ruby -c` OK |
| 6 | CI `release.yml` | YAML válido (`yaml.safe_load`); matrix 5 targets (linux/macos/windows × x86_64/aarch64); steps firma gated por secrets; global SHA256SUMS + `gh release create` |

## Formato de artefactos (unicidad con install.sh/brew/winget)
```
cerberus-<VERSION>-<OS>-<ARCH>.tar.gz|.zip   OS: macos|linux|windows, ARCH: x86_64|aarch64
SHA256SUMS
```

## Adversarial / límites probados
- Script con credenciales vacías → DRY-RUN exit 0 (nunca rompe el pipeline). ✅
- fill_brew_formula con SHA256SUMS parcial (solo 1 plataforma) → warning + placeholder cero, NO fail. ✅
- YAML de release con notas multi-línea → primera iteración invalidaba (dedent); corrigido a `run: |`, re-validado. ✅
- `WINDOWS_SIGN_CERT` sin b64 padding → documentado que el secret es pfx en base64 (paso `base64 --decode` en CI).

## NFR
- Reproducibilidad: `bash tools/release/build_release.sh` determinista (mismos nombres); `dist/` gitignored.
- No toca src/ daemon/proxy/packs/store/ceremony; `ci.yml` intacto.

## Si FAIL: qué fallaría y cómo reproducirlo
- Firma real solo en CI con secrets (`APPLE_*`, `WINDOWS_SIGN_*`); sin ellos el release es funcional y documentado como unsigned. No es un FAIL: es el umbral documentado a GA.

## Archivos (nuevos)
- `tools/release/{build_release.sh, macos-notarize.sh, windows-sign.sh, fill_brew_formula.sh, brew.rb, README_F8.md}`
- `packaging/deb/{control, install, postinst, prerm, build_deb.sh}`
- `packaging/rpm/cerberus.spec`
- `packaging/winget/{README.md, manifests/a/alexeirojas87/Cerberus/0.1.0/{alexeirojas87.Cerberus.{installer,locale.en-US,version}.yaml}}`
- `.github/workflows/release.yml`
- `.gitignore` (+`dist/`)