# F8 — Cadena de release multiplataforma (vending)

Aquí SOLO los instaladores/empaquetado para macOS, Linux y Windows. Helm y la
firma de packs los cubre otro agente (no se tocan en este directorio).

## 1. Qué produce cada cosa

| Plataforma | Método de instalación | Artefacto | Dónde se produce |
|---|---|---|---|
| macOS / Linux | `curl … \| sh` | `install.sh` (con checksum `CERBERUS_SHA256`) | repo `install.sh` |
| macOS | Homebrew | formula `tools/release/brew.rb` (+ `contrib/homebrew/cerberus.rb` para el tap) | release CI + tap |
| Linux | `.deb` (Debian/Ubuntu) | `packaging/deb/*` + `build_deb.sh` | release CI (ubuntu) |
| Linux | `.rpm` (Fedora/RHEL) | `packaging/rpm/cerberus.spec` | release CI (opcional) |
| Windows | winget/MSI | `packaging/winget/manifests/…` + README de publicación | winget-pkgs PR |
| Todos | GitHub Release | `.tar.gz`/`.zip` + `SHA256SUMS` | `.github/workflows/release.yml` |

El esquema de nombres es canónico y lo comparte `install.sh`, la fórmula y el
manifest de winget:

```
cerberus-<VERSION>-<OS>-<ARCH>.tar.gz      OS: macos|linux
cerberus-<VERSION>-<OS>-<ARCH>.zip         OS: windows     (contiene cerberus.exe)
SHA256SUMS
```

## 2. Flujo de release (local, sin credenciales — reproducible)

```bash
# 0) prerequisitos: rustup stable + target(s) para cross
rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu \
                 aarch64-apple-darwin x86_64-apple-darwin

# 1) artefactos del host actual → dist/
./tools/release/build_release.sh                 # detecta OS/arch
CERBERUS_OS=linux CERBERUS_ARCH=aarch64 TARGET=aarch64-unknown-linux-gnu \
  ./tools/release/build_release.sh

# 2) firmas (transparente si no hay credenciales: DRY-RUN que no falla)
./tools/release/macos-notarize.sh dist/cerberus-0.1.0-macos-aarch64.tar.gz
./tools/release/windows-sign.sh dist/exe/cerberus.exe          # solo en Windows/signtool

# 3) brew: llenar la fórmula con hashes reales y validar
./tools/release/fill_brew_formula.sh --version 0.1.0 --platforms dist/SHA256SUMS --out dist/cerberus.rb
ruby -c dist/cerberus.rb
brew audit --strict --new dist/cerberus.rb      # con tag publicado y sha reales

# 4) .deb (requiere dpkg-deb, opcional en CI)
./packaging/deb/build_deb.sh dist/cerberus-0.1.0-linux-x86_64.tar.gz 0.1.0 --arch amd64

# 5) .rpm (requiere rpmbuild; ver cerberus.spec)
rpmbuild -ba packaging/rpm/cerberus.spec
```

## 3. Firma y notarización — qué ocurre en CI (con secretos)

Los secretos NO viven en el repo. Se inyectan en `.github/workflows/release.yml`:

- **macOS**: `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`,
  `APPLE_IDENTITY` → job `macos-sign` ejecuta:
  `codesign --options runtime --timestamp` → `notarytool submit --wait` →
  `stapler staple` → `spctl --assess` → re-empaqueta + regenera SHA256SUMS.
  Sin credenciales: el step se omite (binario sin firmar, notarizado no se).
- **Windows**: `WINDOWS_SIGN_CERT` (pfx en base64) + `WINDOWS_SIGN_PASSWORD`
  → `signtool sign /fd SHA256 /tr …` sobre `cerberus.exe`, re-zip + sumas.
  Sin credenciales: step omitido.

> Como local no hay credenciales, los scripts entran en **DRY-RUN**: muestran la
> secuencia exacta y terminan con código 0 (nunca rompen el pipeline).

## 4. Publicar el release

1. Commitear con tag semver: `git tag v0.1.0 && git push origin v0.1.0`.
2. `.github/workflows/release.yml` construye los 5 targets, sube artefactos
   como GitHub Actions artifacts, haz la firma si hay secretos y crea el
   GitHub Release con `SHA256SUMS` global.
3. Homebrew: `tools/release/fill_brew_formula.sh --version 0.1.0
   --platforms <SHA256SUMS del release> --install` (escribe
   `contrib/homebrew/cerberus.rb`) y se hace PR al tap
   de Homebrew (o `brew tap` local).
4. winget: seguir `packaging/winget/README.md` (PR a `microsoft/winget-pkgs`).
5. verificar: `install.sh`, `brew install`, `apt install ./cerberus_*.deb`,
   `rpm -i`, `winget install Cerberus.Cerberus`.

## 5. Cómo se convierten en artefactos reales

- **`build_release.sh`** → `dist/` con los tarballs/zip + `SHA256SUMS`. Nombres
  exactamente iguales a los que usa `install.sh` (`.tar.gz` con `cerberus` en
  la raíz; `.zip` con `cerberus.exe`).
- **CI `release.yml`** → por cada target: el script, sanity, subida de
  artefactos; luego `release` job: download merge, `SHA256SUMS` global,
  `gh release create`.
- **brew**: el fill transforma los placeholders con los sha reales → una
  fórmula válida → `brew install`.

## 6. Verificación del pipeline (integridad, F8)

```bash
bash -n tools/release/build_release.sh
bash -n tools/release/macos-notarize.sh
bash -n tools/release/windows-sign.sh
bash -n tools/release/fill_brew_formula.sh
ruby -c tools/release/brew.rb
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')+glob.glob('packaging/winget/manifests/**/*.yaml',recursive=True)]"
cargo build --release          # el workspace sigue verde
```

Los pasos que requieren credenciales (firma/notarización reales) SOLO ocurren
en CI con secretos; la matriz actual de CI (`ci.yml`) queda intacta
(build/test/lint).

## 7. Notas operativas

- Sin credenciales de firma real el release es funcional pero los binarios no
  llevan sello de notarización/Authenticode: documentado en las notas del
  release. Requisito previo para GA: credenciales + steps de CI habilitados.
- El MSI de winget se produce con WiX (`dotnet tool install --global wix`);
  hasta fijar el toolchain se sube manualmente al release con el mismo nombre
  `cerberus-<v>-windows-x86_64.msi` y se rellena `InstallerSha256`.
- No se tocan: `src/`, daemon, proxy, packs, store, ceremony, CI actual.