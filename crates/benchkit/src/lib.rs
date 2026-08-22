#![doc = "Shared benchmark utilities for Cerberus spike units."]

use std::time::{Duration, Instant};

/// Compute the p-th percentile from a sorted slice of durations.
///
/// Uses the nearest-rank method: the value at index `ceil(p/100 * n) - 1`.
/// Returns `None` if the input is empty.
///
/// # Panics
/// Panics if `p` is not in `(0.0, 100.0]`.
#[must_use]
pub fn percentile(data: &[Duration], p: f64) -> Option<Duration> {
    assert!((0.0..=100.0).contains(&p), "percentile must be in (0.0, 100.0]");

    let n = data.len();
    if n == 0 {
        return None;
    }

    let mut sorted = data.to_vec();
    sorted.sort();

    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);

    Some(sorted[idx])
}

/// Run a closure `n` times and return a vector of per-iteration durations.
pub fn time_n<F>(n: usize, mut f: F) -> Vec<Duration>
where
    F: FnMut(),
{
    let mut results = Vec::with_capacity(n);
    for _ in 0..n {
        let start = Instant::now();
        f();
        results.push(start.elapsed());
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_p50_of_single_element() {
        let data = vec![Duration::from_micros(42)];
        assert_eq!(percentile(&data, 50.0), Some(Duration::from_micros(42)));
    }

    #[test]
    fn percentile_p99_of_odd_count() {
        let data: Vec<Duration> = (1..=10).map(Duration::from_micros).collect();
        // 99th percentile of 10: rank = ceil(0.99 * 10) = ceil(9.9) = 10, idx = 9 => value 10
        assert_eq!(percentile(&data, 99.0), Some(Duration::from_micros(10)));
    }

    #[test]
    fn percentile_p50_of_even_count() {
        let data: Vec<Duration> = (1..=10).map(Duration::from_micros).collect();
        // rank = ceil(0.50 * 10) = ceil(5.0) = 5, idx = 4 => value 5
        assert_eq!(percentile(&data, 50.0), Some(Duration::from_micros(5)));
    }

    #[test]
    fn percentile_returns_none_for_empty() {
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn time_n_returns_correct_count() {
        let results = time_n(5, || {});
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn time_n_results_are_non_zero() {
        let results = time_n(3, || {
            // En release el busy-wait se optimiza; un sleep breve garantiza
            // una duración medible determinista.
            std::thread::sleep(std::time::Duration::from_micros(500));
        });
        for d in &results {
            assert!(*d > Duration::ZERO);
        }
    }
}
