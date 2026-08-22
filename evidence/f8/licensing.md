# Evidence Pack — Fase 8 / licensing
- Intento: 1    Revisor: Builder    Veredicto: PASS

## Criterios de aceptación
| Criterio | Comando ejecutado | Salida | Resultado |
|----------|-------------------|--------|-----------|
| `cargo test --workspace` | `cargo test --workspace` | 334 passed; 0 failed | ✅ |
| Free tier por defecto | `test::free_tier_by_default` | Free, is_pro=false | ✅ |
| Free no tiene features Pro | `test::free_tier_has_no_pro_features` | Dashboard/Alerts false | ✅ |
| Pro tiene todos los features | `test::pro_tier_has_all_features` | is_pro=true, features ok | ✅ |
| Carga licencia desde archivo | `test::license_from_file` | parse ok | ✅ |
| Licencia expirada detectada | `test::expired_license_detected` | is_expired=true | ✅ |
| Reporte incluye info | `test::license_report_includes_info` | contiene "Free" | ✅ |
| Feature custom via lista | `test::custom_feature_via_list` | dashboard=true | ✅ |

## Free vs Pro gating
| Feature | Free | Pro |
|---------|------|-----|
| Motor de detección | ✅ | ✅ |
| Proxy local | ✅ | ✅ |
| Rule packs básicos | ✅ | ✅ |
| Dashboard + stats | ❌ | ✅ |
| Alertas | ❌ | ✅ |
| Packs premium | ❌ | ✅ |
| Editor de reglas | ❌ | ✅ |
| Políticas por equipo | ❌ | ✅ |

## Archivos
- `crates/cerberus-packs/src/license.rs` (nuevo)

## Desviaciones del plan
Ninguna. Sistema de licencias Free/Pro con feature gating.