# winget — Cerberus installation on Windows

The MVP-supported path for Windows is the winget manifest with
`.zip` (the `.msi`/WiX is left as a future note). This directory contains
the manifest that is published to
[`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs).

## What is here

```
packaging/winget/manifests/c/Cerberus/0.1.0/
├── Cerberus.Cerberus.installer.yaml       # zip type, URL + sha256 of the artifact
├── Cerberus.Cerberus.locale.en-US.yaml     # metadata (description, moniker, tags)
└── Cerberus.Cerberus.version.yaml          # manifest version (canonical)
```

The **path layout** (`manifests/c/Cerberus/0.1.0/…`) is the one required by
`winget validate` / `wingetcreate update` / the PR to winget-pkgs.

## 0. Re-publishing version N

1. Publish the release on GitHub with the zip artifact:
   `cerberus-<VERSION>-windows-x86_64.zip` (see `tools/release/README_F8.md`).
2. Copy `packaging/winget/manifests/.../0.1.0/` to `<VERSION>/` and fill in the
   `placeholder` values of the `.installer.yaml`:

```bash
# compute the sha256 of the REAL zip
shasum -a 256 cerberus-0.1.0-windows-x86_64.zip
# -> replace InstallerSha256 in Cerberus.Cerberus.installer.yaml
```

3. Validate with the official tools:

```powershell
winget validate --manifest ./packaging/winget/manifests/c/Cerberus/0.1.0
winget install --manifest ./packaging/winget/manifests/c/Cerberus/0.1.0   # local test
```

## 1. How to publish to microsoft/winget-pkgs

> Official documentation: https://learn.microsoft.com/en-us/windows/package-manager/package/repository

1. Clone `microsoft/winget-pkgs`.
2. Replace the `manifests/c/Cerberus/0.1.0/` tree with the one here (with
   the real SHA of the `.zip`).
3. Open a PR with the title `New version: Cerberus.Cerberus version 0.1.0`.
   The validation bots (Azure Pipelines `winget-pkgs-automation`) review it:
   - **manifest-validation**: verifies the YAML schema, the types and the
     consistency across the 3 files.
   - **installer-validation**: downloads the `.zip` from `InstallerUrl`, computes its
     SHA256 and checks `UpgradeBehavior`, ProductCode, elevation...
4. Merge once the checks are green. Within a few hours it shows up in the CDN.
5. Confirm: `winget search cerberus` and `winget install Cerberus.Cerberus`.

## Frequently asked questions

- **InstallerType `msi` or `zip`?** For the MVP the `.zip` is published
  (`InstallerType: zip`), which winget supports natively. A future
  `.msi`/WiX is optional and would require a real ProductCode.
- **ProductCode**: if migrated to MSI, it is the MSI GUID (in WiX, the
  `Product/@Id`). It must be stable across builds of the same program so
  that `UpgradeBehavior: install` works.
- **Author**: the PackageVersion in the path (`0.1.0`) and the one in the
  YAMLs must match, and the file name in winget-pkgs uses the exact
  `Cerberus.Cerberus.*` (with the capital `Cerberus`).

## Division of work with CI

This task covers the manifest + the publishing guide. The real `.zip` is
generated during the release with `tools/release/build_release.sh`. Until CI
is configured, the `.zip` is produced locally and attached to the release as
an artifact, replacing the `InstallerSha256` of this manifest.
