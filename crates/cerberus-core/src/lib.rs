#![doc = "Cerberus core detection engine."]

/// Returns the current engine version string.
#[must_use]
pub const fn engine_version() -> &'static str {
    "0.1.0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_version_returns_non_empty() {
        assert!(!engine_version().is_empty());
    }
}
