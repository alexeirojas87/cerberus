use rand::Rng;
use rand::SeedableRng;

/// Generate a synthetic payload of approximately `size_kb` kilobytes.
///
/// Embeds a subset of `examples` as matching strings interleaved with
/// random filler text. Returns the generated payload.
#[must_use]
pub fn generate(size_kb: usize, examples: &[String]) -> String {
    let target_bytes = size_kb * 1024;
    let rng_seed: u64 = 42;
    let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

    let mut parts: Vec<String> = Vec::new();
    let mut total: usize = 0;

    // Determine how many examples to embed (at most 20% of them, but at least 3)
    let num_embedded = std::cmp::max(3, examples.len() / 5);
    let embedded_count = std::cmp::min(num_embedded, examples.len());

    // Create preamble
    let preamble =
        "# Synthetic Secret Detection Test Payload\n# This payload contains synthetic secrets for benchmarking.\n\n";
    parts.push(preamble.to_string());
    total += preamble.len();

    // Interleave examples with context lines and noise
    let noise_lines = std::cmp::max(embedded_count * 2, 10);

    for i in 0..std::cmp::max(embedded_count, noise_lines) {
        if total >= target_bytes {
            break;
        }

        // Add a noise line
        if i < noise_lines {
            let noise = generate_noise_line(&mut rng);
            let line = format!("{noise}\n");
            total += line.len();
            if total <= target_bytes {
                parts.push(line);
            } else {
                total -= line.len();
                break;
            }
        }

        // Add a matching example with context
        if i < embedded_count {
            let ctx = generate_context_line(&examples[i % examples.len()], &mut rng);
            let line = format!("{ctx}\n");
            total += line.len();
            if total <= target_bytes {
                parts.push(line);
            } else {
                total -= line.len();
                break;
            }
        }
    }

    // If we still need more bytes, fill with random sentences
    while total < target_bytes {
        let remaining = target_bytes - total;
        let line = if remaining > 80 {
            generate_random_line(&mut rng)
        } else {
            generate_short_line(&mut rng, remaining)
        };
        let text = format!("{line}\n");
        total += text.len();
        if total <= target_bytes {
            parts.push(text);
        } else {
            break;
        }
    }

    // Trim to exact target if slightly over
    let mut result: String = parts.concat();
    result.truncate(target_bytes);
    result
}

#[allow(clippy::literal_string_with_formatting_args)]
fn generate_context_line(example: &str, rng: &mut impl Rng) -> String {
    const TEMPLATES: &[&str] = &[
        "export MY_{key}=\"{example}\"",
        "{key} = \"{example}\"",
        "const {key} = '{example}';",
        r#""{key}": "{example}""#,
        "set {key}={example}",
        "{key}: {example}",
        "{key} = {example}",
        "Authorization: Bearer {example}",
        "token: \"{example}\"",
    ];

    let keys = [
        "API_KEY",
        "SECRET_KEY",
        "PASSWORD",
        "AUTH_TOKEN",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "SESSION_TOKEN",
        "DB_PASSWORD",
        "JWT_SECRET",
        "SSH_KEY",
    ];

    let tmpl = TEMPLATES[rng.gen_range(0..TEMPLATES.len())];
    let key = keys[rng.gen_range(0..keys.len())];
    tmpl.replace("{key}", key).replace("{example}", example)
}

fn generate_noise_line(rng: &mut impl Rng) -> String {
    const WORDS: &[&str] = &[
        "config",
        "user",
        "module",
        "value",
        "param",
        "setting",
        "option",
        "var",
        "field",
        "entry",
        "record",
        "item",
        "prop",
        "attribute",
        "property",
        "data",
    ];
    const ACTIONS: &[&str] = &[
        "set", "get", "update", "delete", "create", "read", "write", "sync", "load", "save",
    ];

    let a = ACTIONS[rng.gen_range(0..ACTIONS.len())];
    let b = WORDS[rng.gen_range(0..WORDS.len())];
    let c = rng.gen_range(100..9999);
    format!("{a}_{b}_{c}")
}

fn generate_random_line(rng: &mut impl Rng) -> String {
    const TOKENS: &[&str] = &[
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "consectetur",
        "adipiscing",
        "elit",
        "sed",
        "do",
        "eiusmod",
        "tempor",
        "incididunt",
        "ut",
        "labore",
        "et",
        "dolore",
        "magna",
        "aliqua",
        "ut",
        "enim",
        "ad",
        "minim",
        "veniam",
        "quis",
        "nostrud",
        "exercitation",
        "ullamco",
        "laboris",
        "nisi",
        "aliquip",
        "ex",
        "ea",
        "commodo",
        "consequat",
        "duis",
        "aute",
        "irure",
        "dolor",
        "in",
        "reprehenderit",
        "voluptate",
        "velit",
        "esse",
        "cillum",
        "dolore",
        "eu",
        "fugiat",
        "nulla",
        "pariatur",
        "excepteur",
        "sint",
        "occaecat",
        "cupidatat",
        "non",
        "proident",
        "sunt",
        "culpa",
        "qui",
        "officia",
        "deserunt",
        "mollit",
        "anim",
        "id",
        "est",
        "laborum",
    ];
    let count = rng.gen_range(5..15);
    let words: Vec<&str> = (0..count).map(|_| TOKENS[rng.gen_range(0..TOKENS.len())]).collect();
    words.join(" ")
}

fn generate_short_line(rng: &mut impl Rng, max_len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    if max_len < 4 {
        return "x".repeat(max_len);
    }
    let len = rng.gen_range(2..std::cmp::min(max_len, 40));
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_payload_size_within_tolerance() {
        let examples: Vec<String> = (0..10).map(|i| format!("sk-test-key-{i}")).collect();
        let payload = generate(10, &examples);
        let target = 10 * 1024;
        // Allow up to target bytes (we truncate)
        assert!(payload.len() <= target, "payload {} > target {}", payload.len(), target);
        // Allow some minimum
        assert!(
            payload.len() >= target.saturating_sub(200),
            "payload {} < target {} - 200",
            payload.len(),
            target
        );
    }

    #[test]
    fn generate_payload_contains_examples() {
        let examples: Vec<String> = vec!["should-be-present".to_string()];
        let payload = generate(1, &examples);
        assert!(
            payload.contains("should-be-present"),
            "payload should contain embedded example"
        );
    }

    #[test]
    fn generate_payload_handles_small_size() {
        let examples: Vec<String> = vec!["test".to_string()];
        let payload = generate(1, &examples);
        assert!(!payload.is_empty());
    }
}
