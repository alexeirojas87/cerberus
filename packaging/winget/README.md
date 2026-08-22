# winget — instalación de Cerberus en Windows

El camino soportado por MVP para Windows es el manifest de winget con
`.zip` (el `.msi`/WiX queda como nota futura). Este directorio contiene
el manifest que se publica en
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs).

## Qué hay aquí

```
packaging/winget/manifests/c/Cerberus/0.1.0/
├── Cerberus.Cerberus.installer.yaml       # tipo zip, URL + sha256 del artefacto
├── Cerberus.Cerberus.locale.en-US.yaml     # metadatos (description, moniker, tags)
└── Cerberus.Cerberus.version.yaml          # version del manifest (canonical)
```

El **layout de path** (`manifests/c/Cerberus/0.1.0/…`) es el que exige
`winget validate` / `wingetcreate update` / la PR a winget-pkgs.

## 0. Volver a publicar la versión N

1. Publicar el release en GitHub con el artefacto zip:
   `cerberus-<VERSION>-windows-x86_64.zip` (ver `tools/release/README_F8.md`).
2. Copiar `packaging/winget/manifests/.../0.1.0/` a `<VERSION>/` y rellenar los
   `placeholder` del `.installer.yaml`:

```bash
# calcular el sha256 del zip REAL
shasum -a 256 cerberus-0.1.0-windows-x86_64.zip
# → sustituir InstallerSha256 en Cerberus.Cerberus.installer.yaml
```

3. Validar con las herramientas oficiales:

```powershell
winget validate --manifest ./packaging/winget/manifests/c/Cerberus/0.1.0
winget install --manifest ./packaging/winget/manifests/c/Cerberus/0.1.0   # prueba local
```

## 1. Cómo publicar en microsoft/winget-pkgs

> Documentación oficial: https://learn.microsoft.com/en-us/windows/package-manager/package/repository

1. Clonar `microsoft/winget-pkgs`.
2. Sustituir el árbol `manifests/c/Cerberus/0.1.0/` por el de aquí (con
   el SHA real del `.zip`).
3. Crear una PR con título `New version: Cerberus.Cerberus version 0.1.0`.
   Los bots de validación (Azure Pipelines `winget-pkgs-automation`) la revisan:
   - **manifest-validation**: verifica el esquema YAML, los tipos y la
     consistencia entre los 3 archivos.
   - **installer-validation**: descarga el `.zip` de `InstallerUrl`, computa su
     SHA256 y comprueba `UpgradeBehavior`, ProductCode, elevación...
4. Mergue cuando los checks estén verdes. En pocas horas aparece en la CDN.
5. Confirmar: `winget search cerberus` y `winget install Cerberus.Cerberus`.

## Preguntas frecuentes

- **¿InstallerType `msi` o `zip`?** Para el MVP se publica el `.zip`
  (`InstallerType: zip`), que winget soporta nativamente. Un futuro
  `.msi`/WiX es opcional y requeriría un ProductCode real.
- **ProductCode**: si se migra a MSI, es el GUID del MSI (en WiX, el
  `Product/@Id`). Debe ser estable entre builds del mismo programa para
  que el `UpgradeBehavior: install` funcione.
- **Autor**: el PackageVersion del path (`0.1.0`) y el de los YAML deben
  coincidir, y el nombre de fichero en winget-pkgs lleva `Cerberus.Cerberus.*`
  exacto (con la mayúscula de `Cerberus`).

## División de trabajo con CI

Esta tarea cubre el manifest + la guía de publicación. El `.zip` real se genera
durante el release con `tools/release/build_release.sh`. Hasta que el CI
esté configurado, el `.zip` se produce localmente y se adjunta al release como
artefacto, sustituyendo el `InstallerSha256` de este manifest.
