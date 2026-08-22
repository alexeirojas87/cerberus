use std::time::Duration;

use regex::RegexSet;

/// Engine A: uses `regex::RegexSet` for multi-pattern matching in a single pass.
pub(crate) struct RegexEngine {
    set: RegexSet,
}

impl RegexEngine {
    /// Compile patterns into a `RegexSet`.
    ///
    /// # Errors
    /// Returns an error if any pattern is invalid regex.
    pub(crate) fn new(patterns: &[String]) -> Result<Self, String> {
        let set = RegexSet::new(patterns.iter().map(String::as_str))
            .map_err(|e| format!("RegexSet compilation failed: {e}"))?;
        Ok(Self { set })
    }

    /// Scan `payload` and return (elapsed, number of matches).
    pub(crate) fn scan(&self, payload: &str) -> (Duration, usize) {
        let start = std::time::Instant::now();
        let matches = self.set.matches(payload).into_iter().count();
        (start.elapsed(), matches)
    }
}
