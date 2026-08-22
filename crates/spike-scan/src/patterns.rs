use std::fs;
use std::path::Path;

use rand::Rng;
use rand::SeedableRng;

/// Template groups for synthetic pattern generation.
const SIMPLE_PATTERNS: &[&str] = &[
    r"password",
    r"PASSWORD",
    r"secret",
    r"SECRET",
    r"token",
    r"TOKEN",
    r"api.key",
    r"API_KEY",
    r"apikey",
    r"credential",
    r"CREDENTIAL",
    r"private.key",
    r"PRIVATE.KEY",
    r"auth.token",
    r"AUTH_TOKEN",
    r"bearer",
    r"BEARER",
    r"session",
    r"SESSION",
    r"login",
    r"LOGIN",
    r"\bkey\b",
    r"\bsecret\b",
    r"\btoken\b",
    r"\bauth\b",
    r"\bcert\b",
];

const MEDIUM_PATTERNS: &[&str] = &[
    r"sk-[A-Za-z0-9]{20,}",
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9]{36,}",
    r"ghs_[A-Za-z0-9]{36,}",
    r"ghu_[A-Za-z0-9]{36,}",
    r"gho_[A-Za-z0-9]{36,}",
    r"ghr_[A-Za-z0-9]{36,}",
    r"xox[bpras]-[A-Za-z0-9]{10,}",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    r"https?://[A-Za-z0-9./?=&_%#-]+",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    r"[0-9a-f]{32}",
    r"[A-Za-z0-9+/]{40,}",
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    r"sk_live_[0-9a-zA-Z]{24,}",
    r"rk_live_[0-9a-zA-Z]{24,}",
    r"whsec_[A-Za-z0-9]{16,}",
    r"AC[A-Z0-9]{15}",
    r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}",
    r"[Pp]assword\s*[:=]\s*\S+",
    r"[Tt]oken\s*[:=]\s*\S+",
    r"[Ss]ecret\s*[:=]\s*\S+",
    r"[Aa]pi[_.]key\s*[:=]\s*\S+",
    r"mongodb(?:\+srv)?://[^\s]+",
    r"postgres(?:ql)?://[^\s]+",
    r"redis://[^\s]+",
    r"mysql://[^\s]+",
];

const COMPLEX_PATTERNS: &[&str] = &[
    r"-----BEGIN (RSA |EC |DSA |)PRIVATE KEY-----",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"-----BEGIN CERTIFICATE-----",
    r"arn:aws:[a-z]+:[a-z0-9-]+:\d{12}:[a-zA-Z0-9/_-]+",
    r"github_pat_[0-9a-zA-Z_]{36,}",
    r"export\s+\w+=[A-Za-z0-9_\-]{20,}",
    r"export\s+\w+=[A-Za-z0-9_\-]{20,}",
    r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    r"auths.*auth.*[A-Za-z0-9+/=]{20,}",
    r"BEGIN (RSA |EC |DSA |)PRIVATE KEY.*?END.*?PRIVATE KEY",
    r"-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----",
    r"(?i)(api|secret|private)[_-](key|token|credential)\s*(=|:)\s*\S+",
];

/// Generate `n` synthetic patterns and matching example strings.
///
/// Patterns are drawn cyclically from simple/medium/complex templates
/// with a 50/30/20 ratio. Each pattern has a corresponding example
/// string that should produce a match.
#[must_use]
pub fn generate(n: usize) -> (Vec<String>, Vec<String>) {
    let rng_seed: u64 = 42;
    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

    let mut patterns = Vec::with_capacity(n);
    let mut examples = Vec::with_capacity(n);

    let total_templates = SIMPLE_PATTERNS.len() + MEDIUM_PATTERNS.len() + COMPLEX_PATTERNS.len();

    for i in 0..n {
        let idx = i % total_templates;
        let (pat, ex) = if idx < SIMPLE_PATTERNS.len() {
            let t = SIMPLE_PATTERNS[idx];
            (t.to_string(), generate_simple_example(t, &mut rng))
        } else if idx < SIMPLE_PATTERNS.len() + MEDIUM_PATTERNS.len() {
            let t = MEDIUM_PATTERNS[idx - SIMPLE_PATTERNS.len()];
            (t.to_string(), generate_medium_example(t, &mut rng))
        } else {
            let t = COMPLEX_PATTERNS[idx - SIMPLE_PATTERNS.len() - MEDIUM_PATTERNS.len()];
            (t.to_string(), generate_complex_example(t, &mut rng))
        };
        patterns.push(pat);
        examples.push(ex);
    }

    (patterns, examples)
}

/// Load patterns from a JSON file (array of strings) or plain text (one per line).
pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<String>, String> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| format!("Cannot read file: {e}"))?;
    let trimmed = content.trim();
    if trimmed.starts_with('[') {
        serde_json::from_str::<Vec<String>>(trimmed).map_err(|e| format!("Invalid JSON array: {e}"))
    } else {
        Ok(trimmed
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }
}

pub(crate) fn generate_simple_example(pattern: &str, _rng: &mut impl Rng) -> String {
    match pattern {
        r"password" | r"PASSWORD" | r"secret" | r"SECRET" | r"token" | r"TOKEN" | r"credential" | r"CREDENTIAL"
        | r"session" | r"SESSION" | r"login" | r"LOGIN" | r"bearer" | r"BEARER" | r"\bkey\b" | r"\bsecret\b"
        | r"\btoken\b" | r"\bauth\b" | r"\bcert\b" => {
            pattern.trim_start_matches(r"\b").trim_end_matches(r"\b").to_string()
        }
        r"api.key" => "api.key".to_string(),
        r"API_KEY" => "API_KEY".to_string(),
        r"apikey" => "apikey".to_string(),
        r"private.key" => "private.key".to_string(),
        r"PRIVATE.KEY" => "PRIVATE.KEY".to_string(),
        r"auth.token" => "auth.token".to_string(),
        r"AUTH_TOKEN" => "AUTH_TOKEN".to_string(),
        _ => pattern.to_string(),
    }
}

pub(crate) fn generate_medium_example(pattern: &str, rng: &mut impl Rng) -> String {
    match pattern {
        p if p.starts_with("sk-[") => {
            format!("sk-{}", random_alphanum(rng, 32))
        }
        p if p.starts_with("AKIA") => {
            format!("AKIA{}", random_alphanum_upper(rng, 16))
        }
        p if p.starts_with("ghp_") => {
            format!("ghp_{}", random_alphanum(rng, 36))
        }
        p if p.starts_with("ghs_") => {
            format!("ghs_{}", random_alphanum(rng, 36))
        }
        p if p.starts_with("ghu_") => {
            format!("ghu_{}", random_alphanum(rng, 36))
        }
        p if p.starts_with("gho_") => {
            format!("gho_{}", random_alphanum(rng, 36))
        }
        p if p.starts_with("ghr_") => {
            format!("ghr_{}", random_alphanum(rng, 36))
        }
        p if p.starts_with("xox") => {
            format!("xoxb-{}", random_alphanum(rng, 12))
        }
        p if p.contains('@') => "user@example.com".to_string(),
        p if p.contains("https?://") => "https://api.example.com/v1/endpoint".to_string(),
        p if p.contains(r"\d{1,3}\.") => "192.168.1.1".to_string(),
        p if p.starts_with("[0-9a-f]{32}") => random_hex(rng, 32),
        p if p.starts_with("[A-Za-z0-9+/]{40,}") => random_base64(rng, 44),
        p if p.contains("[0-9a-f]{8}-[0-9a-f]{4}") => {
            format!(
                "{}-{}-{}-{}-{}",
                random_hex(rng, 8),
                random_hex(rng, 4),
                random_hex(rng, 4),
                random_hex(rng, 4),
                random_hex(rng, 12)
            )
        }
        p if p.starts_with("eyJ") => {
            format!(
                "eyJhbGciOiJIUzI1NiJ9.{}.{}",
                random_base64url(rng, 20),
                random_base64url(rng, 27)
            )
        }
        p if p.starts_with("sk_live_") => {
            format!("sk_live_{}", random_alphanum(rng, 24))
        }
        p if p.starts_with("rk_live_") => {
            format!("rk_live_{}", random_alphanum(rng, 24))
        }
        p if p.starts_with("whsec_") => {
            format!("whsec_{}", random_alphanum(rng, 16))
        }
        p if p.starts_with("AC") && p.len() < 20 => {
            format!("AC{}", random_alphanum_upper(rng, 15))
        }
        p if p.starts_with("SG.") => {
            format!("SG.{}.{}", random_alphanum(rng, 22), random_alphanum(rng, 27))
        }
        _ => {
            let len = rng.gen_range(8..24);
            random_alphanum(rng, len)
        }
    }
}

pub(crate) fn generate_complex_example(pattern: &str, rng: &mut impl Rng) -> String {
    match pattern {
        p if p.contains("PRIVATE KEY-----") => {
            let body = random_base64(rng, 256);
            format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----")
        }
        p if p.contains("OPENSSH PRIVATE KEY") => {
            let body = random_base64(rng, 256);
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----")
        }
        p if p.contains("CERTIFICATE-----") => {
            let body = random_base64(rng, 128);
            format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----")
        }
        p if p.contains("arn:aws:") => {
            format!(
                "arn:aws:s3:us-east-1:{}:my-bucket",
                rng.gen_range(100_000_000_000u64..999_999_999_999)
            )
        }
        p if p.contains("github_pat_") => {
            format!("github_pat_{}", random_alphanum(rng, 36))
        }
        p if p.contains("hooks.slack.com") => {
            format!(
                "https://hooks.slack.com/services/T{}/B{}/{}",
                random_upper(rng, 8),
                random_upper(rng, 8),
                random_alphanum(rng, 16)
            )
        }
        p if p.contains("export") => {
            format!("export MY_SECRET_KEY=\"{}\"", random_alphanum(rng, 32))
        }
        p if p.contains("PGP") => {
            let body = random_base64(rng, 128);
            format!("-----BEGIN PGP PUBLIC KEY BLOCK-----\n{body}\n-----END PGP PUBLIC KEY BLOCK-----")
        }
        _ => format!("{}={}", random_word(rng), random_alphanum(rng, 32)),
    }
}

fn random_alphanum(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_alphanum_upper(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_hex(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"0123456789abcdef";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_base64(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_base64url(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_upper(rng: &mut impl Rng, len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_word(rng: &mut impl Rng) -> String {
    const WORDS: &[&str] = &[
        "api_key",
        "secret_key",
        "password",
        "token",
        "auth",
        "credential",
        "access_key",
        "private_key",
        "session_token",
        "refresh_token",
        "db_password",
        "jwt_secret",
        "hmac_key",
        "ssh_key",
        "pgp_key",
    ];
    WORDS[rng.gen_range(0..WORDS.len())].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_expected_count() {
        let (pats, exs) = generate(100);
        assert_eq!(pats.len(), 100);
        assert_eq!(exs.len(), 100);
    }

    #[test]
    fn generate_returns_non_empty_patterns() {
        let (pats, exs) = generate(50);
        assert!(pats.iter().all(|p| !p.is_empty()));
        assert!(exs.iter().all(|e| !e.is_empty()));
    }

    #[test]
    fn load_from_json_array() {
        let json = r#"["foo","bar","baz"]"#;
        let tmp = std::env::temp_dir().join("test_patterns.json");
        std::fs::write(&tmp, json).unwrap();
        let pats = load_from_file(&tmp).unwrap();
        assert_eq!(pats, vec!["foo", "bar", "baz"]);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_from_jsonl_fallback() {
        let text = "pattern1\npattern2\npattern3\n";
        let tmp = std::env::temp_dir().join("test_patterns.txt");
        std::fs::write(&tmp, text).unwrap();
        let pats = load_from_file(&tmp).unwrap();
        assert_eq!(pats, vec!["pattern1", "pattern2", "pattern3"]);
        let _ = std::fs::remove_file(&tmp);
    }
}
