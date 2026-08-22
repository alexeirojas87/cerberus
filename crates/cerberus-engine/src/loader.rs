//! Loaders that deserialize [`Rule`]s from JSON/YAML files or strings.

use std::fmt;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::rule::Rule;

/// Error produced while loading or parsing rule sets.
#[derive(Debug)]
pub enum LoadError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The content could not be parsed as JSON.
    Json(serde_json::Error),
    /// The content could not be parsed as YAML.
    Yaml(serde_yaml::Error),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read rules file: {e}"),
            Self::Json(e) => write!(f, "invalid rules JSON: {e}"),
            Self::Yaml(e) => write!(f, "invalid rules YAML: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

/// Load a rule set from a JSON file on disk.
///
/// The file must contain either a JSON array of rules or an object with a
/// `rules` array.
///
/// # Errors
///
/// Returns [`LoadError`] if the file cannot be read or parsed.
pub fn load_rules_from_json<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>, LoadError> {
    let content = fs::read_to_string(path.as_ref()).map_err(LoadError::Io)?;
    parse_rules(&content, FileFormat::Json)
}

/// Load a rule set from a YAML file on disk.
///
/// The file must contain either a YAML sequence of rules or a mapping with a
/// `rules` key.
///
/// # Errors
///
/// Returns [`LoadError`] if the file cannot be read or parsed.
pub fn load_rules_from_yaml<P: AsRef<Path>>(path: P) -> Result<Vec<Rule>, LoadError> {
    let content = fs::read_to_string(path.as_ref()).map_err(LoadError::Io)?;
    parse_rules(&content, FileFormat::Yaml)
}

/// Parse a JSON rule set from a string.
///
/// Accepts either a JSON array of rules or an object with a `rules` array.
///
/// # Errors
///
/// Returns [`LoadError`] if the string is not valid rules JSON.
pub fn load_rules_from_str(json: &str) -> Result<Vec<Rule>, LoadError> {
    parse_rules(json, FileFormat::Json)
}

#[derive(Clone, Copy)]
enum FileFormat {
    Json,
    Yaml,
}

fn parse_rules(content: &str, format: FileFormat) -> Result<Vec<Rule>, LoadError> {
    let text = content.trim();
    let parsed = match format {
        FileFormat::Json => parse_json(text),
        FileFormat::Yaml => parse_yaml(text),
    }?;
    Ok(parsed)
}

fn parse_json(text: &str) -> Result<Vec<Rule>, LoadError> {
    if text.starts_with('[') {
        serde_json::from_str::<Vec<Rule>>(text).map_err(LoadError::Json)
    } else {
        let file: RulesFile = serde_json::from_str(text).map_err(LoadError::Json)?;
        Ok(file.rules)
    }
}

fn parse_yaml(text: &str) -> Result<Vec<Rule>, LoadError> {
    if text.starts_with('-') {
        serde_yaml::from_str::<Vec<Rule>>(text).map_err(LoadError::Yaml)
    } else {
        let file: RulesFile = serde_yaml::from_str(text).map_err(LoadError::Yaml)?;
        Ok(file.rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Action;

    #[test]
    fn load_from_json_array_string() {
        let json = r#"[{"flag":"a","category":"secrets","severity":"low"}]"#;
        let rules = load_rules_from_str(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].flag, "a");
    }

    #[test]
    fn load_from_json_object_string() {
        let json = r#"{"rules":[{"flag":"a","category":"secrets","severity":"low"}]}"#;
        let rules = load_rules_from_str(json).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn malformed_json_returns_error() {
        let err = load_rules_from_str("{ not json }").unwrap_err();
        assert!(err.to_string().contains("invalid rules JSON"));
    }

    #[test]
    fn missing_required_field_returns_error() {
        let err = load_rules_from_str(r#"[{"flag":"a","category":"secrets"}]"#).unwrap_err();
        assert!(err.to_string().contains("invalid rules JSON"));
    }

    #[test]
    fn defaults_applied_when_loading() {
        let json = r#"[
            {"flag":"a","category":"secrets","severity":"low"},
            {"flag":"b","category":"pii","severity":"high","action":"block","patterns":["x"]}
        ]"#;
        let rules = load_rules_from_str(json).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].action, Action::Warn);
        assert!(rules[0].patterns.is_empty());
        assert_eq!(rules[1].action, Action::Block);
        assert_eq!(rules[1].patterns, vec!["x"]);
    }

    #[test]
    fn load_from_json_file_roundtrip() {
        let json = r#"[{"flag":"a","category":"secrets","severity":"low","action":"block"}]"#;
        let path = std::env::temp_dir().join("cerberus_rule_loader_test.json");
        std::fs::write(&path, json).unwrap();
        let rules = load_rules_from_json(&path).unwrap();
        assert_eq!(rules[0].flag, "a");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_from_yaml_string() {
        let yaml = "- flag: a\n  category: secrets\n  severity: low\n";
        let rules = parse_rules(yaml, FileFormat::Yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].flag, "a");
    }

    #[test]
    fn load_from_yaml_object_string() {
        let yaml = "rules:\n  - flag: a\n    category: secrets\n    severity: low\n";
        let rules = parse_rules(yaml, FileFormat::Yaml).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn missing_file_returns_io_error() {
        let err = load_rules_from_json("/nonexistent/cerberus/does-not-exist.json").unwrap_err();
        assert!(err.to_string().contains("cannot read rules file"));
    }
}
