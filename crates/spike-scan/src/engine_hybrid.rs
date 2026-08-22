use std::collections::HashMap;
use std::time::Duration;

use aho_corasick::AhoCorasick;
use regex::Regex;
use regex::RegexSet;

const MIN_PREFIX_LEN: usize = 2;

fn extract_prefix(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut i = 0;
    let mut prefix = String::new();
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    break;
                }
                match bytes[i + 1] {
                    b'b' | b'B' => {
                        i += 2;
                    }
                    b'p' | b'P' | b'd' | b'D' | b'w' | b'W' | b's' | b'S' | b'h' | b'H' | b'v' | b'V' | b'n' | b'r'
                    | b't' | b'f' | b'e' | b'x' | b'u' | b'U' | b'A' | b'z' | b'Z' | b'R' | b'0' => {
                        break;
                    }
                    _ => {
                        prefix.push(bytes[i + 1] as char);
                        i += 2;
                    }
                }
            }
            b'(' | b')' | b'[' | b']' | b'.' | b'?' | b'*' | b'+' | b'|' | b'^' | b'$' | b'{' | b'}' => {
                break;
            }
            _ => {
                prefix.push(bytes[i] as char);
                i += 1;
            }
        }
    }
    if prefix.len() >= MIN_PREFIX_LEN {
        Some(prefix)
    } else {
        None
    }
}

pub(crate) struct HybridEngine {
    ac: AhoCorasick,
    prefixed_regexes: Vec<(Regex, usize)>,
    prefixed_groups: Vec<Vec<(usize, usize)>>,
    unprefixed_set: RegexSet,
    unprefixed_indices: Vec<usize>,
    num_total: usize,
}

impl HybridEngine {
    pub(crate) fn new(patterns: &[String]) -> Result<Self, String> {
        let mut ac_patterns: Vec<Vec<u8>> = Vec::new();
        let mut prefix_to_ac_id: HashMap<String, usize> = HashMap::new();
        let mut prefixed_regexes: Vec<(Regex, usize)> = Vec::new();
        let mut prefixed_groups: Vec<Vec<(usize, usize)>> = Vec::new();
        let mut unprefixed_snippets: Vec<String> = Vec::new();
        let mut unprefixed_indices: Vec<usize> = Vec::new();
        let num_total = patterns.len();

        for (i, pat) in patterns.iter().enumerate() {
            if let Some(prefix) = extract_prefix(pat) {
                let ac_id = *prefix_to_ac_id.entry(prefix.clone()).or_insert_with(|| {
                    let id = ac_patterns.len();
                    ac_patterns.push(prefix.as_bytes().to_vec());
                    prefixed_groups.push(Vec::new());
                    id
                });
                let regex = Regex::new(pat).map_err(|e| format!("Regex compile error for pattern {i}: {e}"))?;
                let reg_idx = prefixed_regexes.len();
                prefixed_regexes.push((regex, i));
                prefixed_groups[ac_id].push((reg_idx, i));
            } else {
                unprefixed_snippets.push(pat.clone());
                unprefixed_indices.push(i);
            }
        }

        let ac = AhoCorasick::builder()
            .build(&ac_patterns)
            .map_err(|e| format!("Aho-Corasick build error: {e}"))?;

        let unprefixed_set =
            RegexSet::new(&unprefixed_snippets).map_err(|e| format!("RegexSet (unprefixed) compilation error: {e}"))?;

        Ok(Self {
            ac,
            prefixed_regexes,
            prefixed_groups,
            unprefixed_set,
            unprefixed_indices,
            num_total,
        })
    }

    pub(crate) fn scan(&self, payload: &str) -> (Duration, usize) {
        let start = std::time::Instant::now();
        let mut matched = vec![false; self.num_total];
        let payload_bytes = payload.as_bytes();

        for m in self.ac.find_iter(payload_bytes) {
            let ac_id = m.pattern().as_usize();
            for &(reg_idx, pat_idx) in &self.prefixed_groups[ac_id] {
                if matched[pat_idx] {
                    continue;
                }
                if self.prefixed_regexes[reg_idx]
                    .0
                    .shortest_match(&payload[m.start()..])
                    .is_some()
                {
                    matched[pat_idx] = true;
                }
            }
        }

        let set_matches = self.unprefixed_set.matches(payload);
        for (set_idx, &pat_idx) in self.unprefixed_indices.iter().enumerate() {
            if set_matches.matched(set_idx) {
                matched[pat_idx] = true;
            }
        }

        let count = matched.iter().filter(|&&m| m).count();
        (start.elapsed(), count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_prefix_sk() {
        assert_eq!(extract_prefix(r"sk-[A-Za-z0-9]{20,}"), Some("sk-".to_string()));
    }

    #[test]
    fn extract_prefix_ak() {
        assert_eq!(extract_prefix(r"AKIA[0-9A-Z]{16}"), Some("AKIA".to_string()));
    }

    #[test]
    fn extract_prefix_none_for_class() {
        assert_eq!(extract_prefix(r"\d{5}"), None);
        assert_eq!(extract_prefix(r"[0-9a-f]{32}"), None);
        assert_eq!(extract_prefix(r"\bkey\b"), Some("key".to_string()));
    }

    #[test]
    fn extract_prefix_pem() {
        assert_eq!(
            extract_prefix("-----BEGIN RSA PRIVATE KEY-----"),
            Some("-----BEGIN RSA PRIVATE KEY-----".to_string())
        );
    }

    #[test]
    fn hybrid_scan_empty_patterns() {
        let engine = HybridEngine::new(&[]).unwrap();
        let (dur, count) = engine.scan("test payload");
        assert_eq!(count, 0, "zero patterns -> zero matches");
        assert!(dur.as_nanos() > 0);
    }

    #[test]
    fn hybrid_scan_empty_payload() {
        let patterns = vec![r"sk-[A-Za-z0-9]+".to_string()];
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("");
        assert_eq!(count, 0, "empty payload -> zero matches");
    }

    #[test]
    fn hybrid_scan_simple_match() {
        let patterns = vec![r"secret".to_string()];
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("this is a secret key");
        assert_eq!(count, 1);
    }

    #[test]
    fn hybrid_scan_prefixed_match() {
        let patterns = vec![r"sk-[A-Za-z0-9]{20,}".to_string()];
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("api key: sk-abcDEFghijklmnopqrstuvwxyz1234");
        assert_eq!(count, 1);
    }

    #[test]
    fn hybrid_scan_no_false_positive() {
        let patterns = vec![r"sk-[A-Za-z0-9]{20,}".to_string()];
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("just random text with no secrets");
        assert_eq!(count, 0);
    }

    #[test]
    fn hybrid_scan_unprefixed_pattern() {
        let patterns = vec![r"\d{5}".to_string()];
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("zip code 12345 here");
        assert_eq!(count, 1);
    }

    #[test]
    fn hybrid_scan_many_patterns() {
        let patterns: Vec<String> = (0..100).map(|i| format!(r"sk-pattern-{i}-[a-z]+")).collect();
        let engine = HybridEngine::new(&patterns).unwrap();
        let (_, count) = engine.scan("no match payload here");
        assert_eq!(count, 0);
    }
}
