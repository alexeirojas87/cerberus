use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use benchkit::percentile;
use reqwest::Client;
use serde::Serialize;
use tokio::net::TcpListener;

use crate::proxy::{serve_proxy, serve_upstream};

const WARMUP: usize = 20;
const FILLER: &str = "the quick brown fox jumps over the lazy dog ";
const PAYLOAD_SIZES_KB: &[usize] = &[1, 10, 50, 100];

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Percentiles {
    pub p50_ms: f64,
    pub p99_ms: f64,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct BenchResult {
    pub payload_kb: usize,
    pub iterations: usize,
    pub direct: Percentiles,
    pub proxy: Percentiles,
    pub overhead: Percentiles,
    pub overhead_percentile_p99_ms: f64,
}

#[must_use]
pub const fn payload_sizes_kb() -> &'static [usize] {
    PAYLOAD_SIZES_KB
}

#[must_use]
pub fn synthetic_payload(kb: usize) -> String {
    let target = kb * 1024;
    let mut body = String::with_capacity(target);
    while body.len() < target {
        body.push_str(FILLER);
    }
    body.truncate(target);
    body
}

#[must_use]
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[must_use]
fn stats(timings: &[Duration]) -> Percentiles {
    Percentiles {
        p50_ms: ms(percentile(timings, 50.0).unwrap_or_default()),
        p99_ms: ms(percentile(timings, 99.0).unwrap_or_default()),
    }
}

async fn round_trip(client: &Client, url: &str, payload: &str) -> Result<(), String> {
    let resp = client
        .post(url)
        .body(payload.to_string())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let _ = resp.bytes().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn measure_latencies(
    client: &Client,
    url: &str,
    payload: &str,
    iterations: usize,
) -> Result<Vec<Duration>, String> {
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        round_trip(client, url, payload).await?;
        timings.push(start.elapsed());
    }
    Ok(timings)
}

pub async fn run_bench(payload_kb: usize, iterations: usize) -> Result<BenchResult, String> {
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let upstream_addr = upstream_listener.local_addr().map_err(|e| e.to_string())?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|e| e.to_string())?;
    let proxy_addr = proxy_listener.local_addr().map_err(|e| e.to_string())?;

    let _upstream_handle = tokio::spawn(serve_upstream(upstream_listener));
    let _proxy_handle = tokio::spawn(serve_proxy(proxy_listener, upstream_addr));

    let client = Client::new();
    let payload = synthetic_payload(payload_kb);

    let direct_url = format!("http://{upstream_addr}/v1/chat/completions");
    let proxy_url = format!("http://{proxy_addr}/v1/chat/completions");

    for _ in 0..WARMUP {
        round_trip(&client, &direct_url, &payload).await?;
        round_trip(&client, &proxy_url, &payload).await?;
    }

    let direct = measure_latencies(&client, &direct_url, &payload, iterations).await?;
    let proxy = measure_latencies(&client, &proxy_url, &payload, iterations).await?;

    let d = stats(&direct);
    let p = stats(&proxy);
    let overhead = Percentiles {
        p50_ms: (p.p50_ms - d.p50_ms).max(0.0),
        p99_ms: (p.p99_ms - d.p99_ms).max(0.0),
    };

    Ok(BenchResult {
        payload_kb,
        iterations,
        direct: d,
        proxy: p,
        overhead: overhead.clone(),
        overhead_percentile_p99_ms: overhead.p99_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_payload_has_approximate_size() {
        let p = synthetic_payload(1);
        assert!(p.len() >= 1000);
        assert!(p.len() <= 1100);
    }

    #[test]
    fn stats_returns_reasonable_values() {
        let timings: Vec<Duration> = (1..=10).map(Duration::from_micros).collect();
        let s = stats(&timings);
        assert!(s.p50_ms > 0.0);
        assert!(s.p99_ms > 0.0);
        assert!(s.p99_ms >= s.p50_ms);
    }

    #[test]
    fn payload_sizes_returns_four() {
        assert_eq!(payload_sizes_kb().len(), 4);
    }
}
