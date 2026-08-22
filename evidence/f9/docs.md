# Evidence Pack — Fase 9 / docs
- Intento: 2    Revisor: Builder (Codex via Orca)    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| Guía de usuario existe | `ls docs/user-guide.md` | file exists | ✅ |
| Guía de operador existe | `ls docs/operator-guide.md` | file exists | ✅ |
| Guía de seguridad existe | `ls docs/security-guide.md` | file exists | ✅ |
| Threat model documentado | `grep "Threat Model" docs/security-guide.md` | sección presente | ✅ |
| Guía "tus secretos no salen" | `grep "Zero Leak" docs/security-guide.md` | sección presente | ✅ |
| MITM opt-in documentado | `grep "MITM" docs/user-guide.md docs/operator-guide.md` | secciones presentes | ✅ |
| Windows install documentado | `grep "winget" docs/user-guide.md` | sección presente | ✅ |
| Telemetría opt-in documentada | `grep "Telemetry" docs/security-guide.md` | §6 "Telemetry Privacy" | ✅ |
| Helm documentado | `grep "helm" docs/operator-guide.md` | sección presente | ✅ |
| Feedback UX documentado | `grep "Dev Feedback" docs/user-guide.md` | sección presente | ✅ |

## Documentación incluida (actualizada con features F4/F8)
| Doc | Contenido |
|-----|-----------|
| `docs/user-guide.md` | Install (brew/curl/Docker/**winget**), quick start, **MITM opt-in**, commands table (mitm/pack/license), modes, fail policy, **dev feedback**, **telemetry opt-in**, **license tiers** |
| `docs/operator-guide.md` | Arquitectura (con MITM/telemetry/feedback), deploy Docker/**Helm**, config, **platform notes (Windows)**, API endpoints (upstreams/packs), **MITM forward proxy**, logging, monitoring |
| `docs/security-guide.md` | Threat model, **Zero Leak** (incl. telemetry + feedback), No ReDoS (pack real), Fail-closed default, Break-glass, **MITM opt-in & scoped**, **Telemetry Privacy** (exact payload), config security, **rule pack security (Ed25519)** |

## Cambio vs intento 1
El intento 1 documentaba sólo F1–F5 (install básico, sin MITM/Windows/telemetría/
feedback/Helm/packs/licensing). Las features F4/F8 no estaban reflejadas. El
intent 2 añade todas las secciones F4/F8 a las tres guías.

## Archivos
- `docs/user-guide.md` (actualizado)
- `docs/operator-guide.md` (actualizado)
- `docs/security-guide.md` (actualizado)

## Desviaciones del plan
Ninguna.
