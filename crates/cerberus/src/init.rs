//! Inicialización y autodetección de agentes (`cerberus init`).
//!
//! Detecta agentes instalados (Claude Code, Codex, opencode, pi) y
//! configura sus `*_BASE_URL` para que apunten al proxy Cerberus local.

use std::fmt::Write as _;
use std::path::Path;

use cerberus_engine::engine::EngineBuilder;
use cerberus_engine::loader::load_rules_from_str;

use crate::packs::default_rules_json;

/// Un agente detectado.
#[derive(Debug, Clone)]
pub(crate) struct DetectedAgent {
    /// Nombre del agente.
    pub name: String,
    /// Variable de entorno para la base URL.
    pub env_var: String,
    /// Ruta al binario (si se encuentra).
    pub binary_path: Option<String>,
    /// ¿Está configurado para usar Cerberus?
    pub configured: bool,
}

/// Agentes conocidos con sus variables de entorno.
const KNOWN_AGENTS: &[(&str, &str, &[&str])] = &[
    ("Claude Code", "CLAUDE_CODE_BASE_URL", &["claude", "claude-code"]),
    ("Codex", "CODEX_BASE_URL", &["codex"]),
    ("opencode", "OPENCODE_BASE_URL", &["opencode"]),
    ("pi", "PI_BASE_URL", &["pi"]),
    ("Continue (Cursor)", "CONTINUE_BASE_URL", &["continue", "cursor"]),
];

/// Ejecutar `cerberus init`.
///
/// # Errors
///
/// Devuelve error si no se puede crear el directorio de configuración.
pub(crate) fn run_init(config_dir: &str) -> Result<String, String> {
    let cfg_path = Path::new(config_dir);
    std::fs::create_dir_all(cfg_path).map_err(|e| format!("cannot create config dir: {e}"))?;

    let agents = detect_agents();

    let mut report = String::from("✦ Cerberus Init ✦\n\n");
    writeln!(report, "Configuración: {config_dir}").ok();
    writeln!(report, "Reglas: {} cargadas", load_rule_count()).ok();
    report.push_str("\n📋 Agentes detectados:\n");

    let mut configured = 0;
    for agent in &agents {
        let status = if agent.configured {
            configured += 1;
            "✅ configurado"
        } else if agent.binary_path.is_some() {
            "⚠️  detectado, requiere configurar var de entorno"
        } else {
            "❌ no encontrado"
        };
        writeln!(report, "  {:<20} {status}", agent.name).ok();
    }

    writeln!(report, "\nResumen: {configured}/{} agentes configurados", agents.len()).ok();

    let yaml = init_config_yaml();
    let config_path = cfg_path.join("config.yaml");
    std::fs::write(&config_path, yaml).map_err(|e| format!("cannot write config: {e}"))?;

    if !agents.iter().any(|a| a.configured) {
        report.push_str("\n💡 Tip: configura manualmente la variable de entorno de tu agente:\n");
        for agent in &agents {
            if agent.binary_path.is_some() {
                writeln!(report, "  export {}=http://127.0.0.1:8787", agent.env_var).ok();
            }
        }
    }

    report.push_str("\n▶ Siguientes pasos (operación real):\n");
    report.push_str("  1. cerberus start --port 8787\n");
    report.push_str("     (ya hay upstreams por defecto: openai → api.openai.com, anthropic → api.anthropic.com;\n");
    report.push_str(
        "      no necesitas CERBERUS_UPSTREAM_URL en el primer arranque — edita config.yaml si cambias de proveedor)\n",
    );
    report.push_str("  2. export <TU_AGENTE>_BASE_URL=http://127.0.0.1:8787  (ej: OPENCODE_BASE_URL)\n");

    Ok(report)
}

/// Config YAML de arranque por defecto (cero-config, F4): upstreams EXPLÍCITOS
/// para openai/anthropic → `cerberus start` arranca sin `CERBERUS_UPSTREAM_URL`.
/// El operador puede editar `URLs`/`path_prefix` en `config.yaml` sin tocar
/// código.
#[must_use]
const fn init_config_yaml() -> &'static str {
    "listen: 127.0.0.1:8787\nmode: enforce\nfail_policy: closed\nupstreams:\n  anthropic:\n    url: https://api.anthropic.com\n  openai:\n    url: https://api.openai.com\n"
}

/// Detectar agentes instalados en el sistema.
#[must_use]
pub(crate) fn detect_agents() -> Vec<DetectedAgent> {
    KNOWN_AGENTS
        .iter()
        .map(|(name, env_var, bins)| {
            let binary_path = bins.iter().find_map(|bin| find_binary(bin));
            let configured = if binary_path.is_some() {
                std::env::var(env_var).is_ok()
            } else {
                false
            };
            DetectedAgent {
                name: name.to_string(),
                env_var: env_var.to_string(),
                binary_path,
                configured,
            }
        })
        .collect()
}

/// Buscar un binario en el PATH.
///
/// La constante global `KNOWN_AGENTS` guarda nombres **sin** extensión; aquí se
/// añade `.exe` como candidato prioritario en Windows (nunca en la constante).
fn find_binary(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            for candidate in binary_candidates(name) {
                let full_path = dir.join(&candidate);
                if full_path.is_file() && is_executable_candidate(&full_path) {
                    return Some(full_path.to_string_lossy().to_string());
                }
            }
            None
        })
    })
}

/// Nombres de archivo a probar para un binario: en Windows `name.exe` primero
/// (evita falsos positivos de un archivo sin extensión) y luego `name`; en el
/// resto de plataformas solo `name`.
fn binary_candidates(name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![format!("{name}.exe"), name.to_string()]
    }
    #[cfg(not(windows))]
    {
        vec![name.to_string()]
    }
}

/// Comprobar que `path` es un candidato ejecutable (bit de ejecución en unix;
/// en Windows basta con que el archivo exista).
fn is_executable_candidate(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// Cargar reglas y devolver el conteo.
fn load_rule_count() -> usize {
    load_rules_from_str(&default_rules_json()).map_or(0, |rules| rules.len())
}

/// Escanear un archivo (modo dry-run).
///
/// # Errors
///
/// Devuelve error si no se puede leer el archivo.
pub(crate) fn scan_file(path: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read file: {e}"))?;
    Ok(scan_text(&content))
}

/// Escanear texto (modo dry-run).
#[must_use]
pub(crate) fn scan_text(text: &str) -> String {
    let rules_json = default_rules_json();
    let rules = match load_rules_from_str(&rules_json) {
        Ok(r) => r,
        Err(e) => return format!("error loading rules: {e}"),
    };
    let engine = match EngineBuilder::new(&rules).build() {
        Ok(e) => e,
        Err(e) => return format!("engine build error: {e}"),
    };

    let output = engine.scan(text);
    if output.findings.is_empty() {
        return "✓ No se detectaron datos sensibles.".to_string();
    }

    let mut report = String::from("🔍 Hallazgos de escaneo:\n\n");
    for f in &output.findings {
        // Nunca exponer el valor crudo en pantalla (P1-12): solo flag, acción,
        // posición y hash del valor detectado.
        writeln!(
            report,
            "  [{:>8}] {} (pos {}..{}) hash={}",
            f.action, f.flag, f.start, f.end, f.hashed_value
        )
        .ok();
    }
    writeln!(report, "\nAcción global: {}", output.action_overall).ok();
    report
}

/// Diagnóstico del sistema.
#[must_use]
pub(crate) fn doctor() -> String {
    let mut report = String::new();
    report.push_str("✦ Cerberus Doctor ✦\n\n");

    writeln!(report, "Daemon: {}", crate::daemon::status()).ok();

    let rules_count = load_rule_count();
    writeln!(report, "Reglas cargadas: {rules_count}").ok();

    report.push_str("\nAgentes:\n");
    for agent in detect_agents() {
        let status = if let Some(_path) = &agent.binary_path {
            if agent.configured {
                "✅ listo"
            } else {
                "⚠️  no configurado"
            }
        } else {
            "❌ no instalado"
        };
        writeln!(report, "  {:<20} {status}", agent.name).ok();
    }

    let cfg_dir = crate::daemon::config_dir();
    writeln!(
        report,
        "\nConfig dir: {} {}",
        cfg_dir.display(),
        if cfg_dir.exists() { "✅" } else { "❌ no existe" }
    )
    .ok();

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guard para serializar los tests que mutan `std::env` y el PATH.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn detect_agents_returns_vec() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let agents = detect_agents();
        assert!(agents.len() >= 4);
    }

    /// F4 multiplataforma: `find_binary` descubre un binario real en un PATH
    /// aislado. En Windows prefiere el candidato `.exe` y un archivo sin
    /// extensión no basta; en unix exige bit de ejecución.
    #[test]
    fn find_binary_discovers_executable_only() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");

        let real = dir.path().join(if cfg!(windows) { "opencode.exe" } else { "opencode" });
        std::fs::write(&real, "fake binary").expect("write real");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&real).expect("metadata").permissions();
            perms.set_mode(0o755); // ejecutable
            std::fs::set_permissions(&real, perms).expect("chmod");
        }

        #[cfg(windows)]
        {
            // Falso positivo: archivo SIN extensión no debe ganar al .exe.
            let plain = dir.path().join("opencode");
            std::fs::write(&plain, "not a real exe").expect("write plain");
        }

        let prev_path = std::env::var_os("PATH");
        std::env::set_var("PATH", dir.path());

        assert_eq!(
            find_binary("opencode").as_deref(),
            Some(real.to_string_lossy().as_ref())
        );

        match prev_path {
            Some(path) => std::env::set_var("PATH", path),
            None => std::env::remove_var("PATH"),
        }
    }

    #[test]
    fn scan_empty_text_returns_clean() {
        let report = scan_text("sin contraseñas aquí");
        assert!(report.contains("No se detectaron"));
    }

    #[test]
    fn scan_with_skey_detects() {
        // "openai" es un contextKeyword de la regla secret.openai_api_key →
        // con constraints aplicadas, se detecta.
        let report = scan_text("my openai api key is sk-abcDEFghijklmnopqrstuvwxyz1234");
        assert!(report.contains("Hallazgos"));
    }

    #[test]
    fn scan_nonexistent_file_returns_error() {
        let result = scan_file("/tmp/cerberus_nonexistent_XX_test.txt");
        assert!(result.is_err());
    }

    // ─── F4: cero-config — init deja upstreams por defecto explícitos ──────

    #[test]
    fn init_writes_config_with_default_upstreams() {
        let dir = std::env::temp_dir().join(format!(
            "cercerberus_init_upstream_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let yaml = init_config_yaml();
        let parsed = cerberus_proxy::config::ProxyConfig::parse(yaml).expect("default yaml parses");
        assert!(parsed.upstreams.contains_key("openai"), "openai por defecto requerido");
        assert!(
            parsed.upstreams.contains_key("anthropic"),
            "anthropic por defecto requerido"
        );
        assert_eq!(
            parsed.upstreams["openai"].url, "https://api.openai.com",
            "sin env, el primer arranque debe llegar a OpenAI"
        );

        // `cerberus init` en un dir aislado escribe ese YAML en config.yaml.
        let report = run_init(dir.to_str().expect("utf8")).expect("init");
        assert!(
            report.contains("no necesitas CERBERUS_UPSTREAM_URL"),
            "el init debe anunciar cero-config: {report}"
        );
        let written = std::fs::read_to_string(dir.join("config.yaml")).expect("config escrita por init");
        assert!(
            written.contains("https://api.openai.com"),
            "la config escrita debe preservar los upstreams: {written}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
