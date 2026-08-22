# F8 Review Adversarial — Re-verificación del punto 6 (winget)

Rol: revisor adversarial F8. Contexto: el worktree estaba en `a04a84d` (DETACHED) sin el fix;
el fix se aplicó en /Users/alexeirojas/Work/Personal/Cerberus (repo principal, SIN commitear).
Verificación hecha sobre el archivo corregido, no sobre el commit del worktree.

## Tabla punto 6 — winget manifest

| Ítem | Criterio | Resultado | Nota |
|---|---|---|---|
| InstallerType | `zip` (no msi) | **PASS** | `alexeirojas87.Cerberus.installer.yaml:5` → `InstallerType: zip`. Gana el comentario +1312 que explica por qué no MSI (GUID fake rechazado por winget-pkgs). |
| InstallerUrl | `.../cerberus-0.1.0-windows-x86_64.zip` | **PASS** | `alexeirojas87.Cerberus.installer.yaml:16`, exacto. |
| Coherencia `tools/release/build_release.sh` | versión 0.1.0, OS windows, arch x86_64 → `.zip` | **PASS** | `build_release.sh:77` EXT=zip si OS=windows; `:78` patrón `cerberus-${VERSION}-${OS}-${ARCH}.${EXT}` = `cerberus-0.1.0-windows-x86_64.zip`. URL v0.1.0 coincide con tag de release estandar (`releases/download/v0.1.0/`). |
| Validez YAML | parse + InstallerType==「zip」 | **PASS** | `python3 yaml.safe_load` → `OK zip`. Schema 1.6.0 `ManifestType: installer`. |
| InstallerSha256 | placeholder `0000...` (rellenado por CI) | **PASS (con nota)** | Valor all-zeros (64 hex) en `:17`. Aceptable como placeholder para CI/release automation. |

**Resultado global punto 6: PASS.**

## Nota sobre `winget validate` y sha placeholder

- El placeholder `0000…` es éticamente **no válido** como checksum real: `winget validate`
  (y la pipeline de winget-pkgs) no puede verificar integridad frente a un blob de zeros y
  el PR lo **rechazaría** si llegara tal cual al repo community. `winget validate` verifica
  que el suma exista y coincida con el URL descargable; ceros extras → rechazo.
- Mitigation sugerida (NO aplicada — no cambia nada): que el CI calcule `InstallerSha256`
  real desde el artifact (`shasum -a 256 dist/cerberus-0.1.0-windows-x86_64.zip`, ya deriva en
  `SHA256SUMS` por `build_release.sh:125-127`) e inyecte el valor en el manifest antes de
  abrir el PR a winget-pkgs. Recomendado explícitamente en el pipeline de publicación.
- Instalación comprometida: hacia con `Installers[0].InstallerSha256` real, `Installers[1]`
  para aarch64 si aplica, y `PackageIdentifier`/`PackageVersion` ya correctas.

## Evidencia cruda

```
$ python3 -c "import yaml; d=yaml.safe_load(open('.../alexeirojas87.Cerberus.installer.yaml')); assert d['InstallerType']=='zip'; print('OK zip')"
OK zip
$ ... InstallerUrl -> https://github.com/alexeirojas87/cerberus/releases/download/v0.1.0/cerberus-0.1.0-windows-x86_64.zip
  ...
```

(comandos complet in evidencia: parseo OK, url correct, sha=0000...).

## Veredicto F8

**PASS** — el punto 6 (winget) queda **CORREGIDO**: `InstallerType: zip`, URL y nombre del
artifact coherentes con `build_release.sh`, YAML válido. Única salvedad documentada: sha
placeholder `0000…` que el CI debe rellenar antes del PR a winget-pkgs.