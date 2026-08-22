#![allow(missing_docs)]

mod engine_hybrid;
mod engine_regex;
#[cfg(feature = "vectorscan")]
mod engine_vectorscan;

use std::time::Duration;

use benchkit::{percentile, time_n};
use spike_scan::patterns;
use spike_scan::payload;

use crate::engine_hybrid::HybridEngine;
use crate::engine_regex::RegexEngine;

enum ScanEngine {
    Regex(RegexEngine),
    Hybrid(HybridEngine),
}

impl ScanEngine {
    fn scan(&self, payload: &str) -> (Duration, usize) {
        match self {
            Self::Regex(e) => e.scan(payload),
            Self::Hybrid(e) => e.scan(payload),
        }
    }
}

enum EngineKind {
    Regex,
    Hybrid,
}

struct Args {
    patterns: usize,
    payload_size_kb: usize,
    iterations: usize,
    patterns_file: Option<String>,
    vectorscan: bool,
    engine: EngineKind,
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().collect();
    let mut args = Args {
        patterns: 300,
        payload_size_kb: 100,
        iterations: 1000,
        patterns_file: None,
        vectorscan: false,
        engine: EngineKind::Hybrid,
    };

    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--patterns" => {
                i += 1;
                args.patterns = raw[i].parse().unwrap_or(300);
            }
            "--payload-size" => {
                i += 1;
                args.payload_size_kb = raw[i].parse().unwrap_or(100);
            }
            "--iterations" => {
                i += 1;
                args.iterations = raw[i].parse().unwrap_or(1000);
            }
            "--patterns-file" => {
                i += 1;
                args.patterns_file = Some(raw[i].clone());
            }
            "--vectorscan" => {
                args.vectorscan = true;
            }
            "--engine" => {
                i += 1;
                args.engine = match raw[i].as_str() {
                    "regex" => EngineKind::Regex,
                    "hybrid" => EngineKind::Hybrid,
                    other => {
                        eprintln!("invalid engine '{other}' (expected 'regex' or 'hybrid')");
                        std::process::exit(1);
                    }
                };
            }
            _ => {}
        }
        i += 1;
    }
    args
}

fn build_engine(kind: &EngineKind, patterns: &[String]) -> ScanEngine {
    match kind {
        EngineKind::Regex => ScanEngine::Regex(RegexEngine::new(patterns).unwrap_or_else(|e| {
            eprintln!("RegexSet compilation error: {e}");
            std::process::exit(1);
        })),
        EngineKind::Hybrid => ScanEngine::Hybrid(HybridEngine::new(patterns).unwrap_or_else(|e| {
            eprintln!("Hybrid engine compilation error: {e}");
            std::process::exit(1);
        })),
    }
}

fn main() {
    let args = parse_args();

    let (patterns, examples) = if let Some(ref path) = args.patterns_file {
        let pats = patterns::load_from_file(path).unwrap_or_else(|e| {
            eprintln!("Error loading patterns: {e}");
            std::process::exit(1);
        });
        let exs: Vec<String> = (0..pats.len()).map(|_| String::new()).collect();
        (pats, exs)
    } else {
        patterns::generate(args.patterns)
    };

    let num_patterns = patterns.len();
    let payload = payload::generate(args.payload_size_kb, &examples);
    let payload_size_bytes = payload.len();

    let (compile_ms, bench_result) = {
        let compile_start = std::time::Instant::now();
        let engine = build_engine(&args.engine, &patterns);
        let compile_ms = compile_start.elapsed().as_secs_f64() * 1000.0;

        let timings = run_bench(args.iterations, &payload, |pl| engine.scan(pl));
        let (_, matches_found) = engine.scan(&payload);

        let result = BenchResult::from_timings(&timings, matches_found, payload_size_bytes);
        (compile_ms, result)
    };

    let vectorscan_result: Option<(f64, BenchResult)> = if args.vectorscan {
        #[cfg(feature = "vectorscan")]
        {
            let compile_start = std::time::Instant::now();
            match engine_vectorscan::VectorscanEngine::new(&patterns) {
                Ok(engine) => {
                    let compile_ms = compile_start.elapsed().as_secs_f64() * 1000.0;
                    let timings = run_bench(args.iterations, &payload, |pl| {
                        engine.scan(pl).unwrap_or((Duration::ZERO, 0))
                    });
                    let (_, matches_found) = engine.scan(&payload).unwrap_or((Duration::ZERO, 0));
                    Some((
                        compile_ms,
                        BenchResult::from_timings(&timings, matches_found, payload_size_bytes),
                    ))
                }
                Err(e) => {
                    eprintln!("Vectorscan engine error: {e}");
                    None
                }
            }
        }
        #[cfg(not(feature = "vectorscan"))]
        {
            let _ = &payload;
            eprintln!("Vectorscan feature not enabled. Compile with --features vectorscan.");
            None
        }
    } else {
        None
    };

    let engine_name = match args.engine {
        EngineKind::Regex => "regex",
        EngineKind::Hybrid => "hybrid",
    };

    let output = build_json_output(
        num_patterns,
        payload_size_bytes,
        args.iterations,
        engine_name,
        compile_ms,
        &bench_result,
        vectorscan_result.as_ref(),
    );

    println!("{output}");
}

fn run_bench<F>(iterations: usize, payload: &str, mut scan_fn: F) -> Vec<Duration>
where
    F: FnMut(&str) -> (Duration, usize),
{
    let _ = scan_fn(payload);
    time_n(iterations, || {
        let _ = scan_fn(payload);
    })
}

struct BenchResult {
    scan_p50_ms: f64,
    scan_p99_ms: f64,
    throughput_mbps: f64,
    matches_found: usize,
}

impl BenchResult {
    fn from_timings(timings: &[Duration], matches: usize, payload_bytes: usize) -> Self {
        let p50 = percentile(timings, 50.0).unwrap_or(Duration::ZERO);
        let p99 = percentile(timings, 99.0).unwrap_or(Duration::ZERO);

        let p50_ms = p50.as_secs_f64() * 1000.0;
        let p99_ms = p99.as_secs_f64() * 1000.0;

        let p50_secs = p50.as_secs_f64();
        let mbps = if p50_secs > 0.0 {
            (payload_bytes as f64 / 1_000_000.0) / p50_secs
        } else {
            0.0
        };

        Self {
            scan_p50_ms: p50_ms,
            scan_p99_ms: p99_ms,
            throughput_mbps: mbps,
            matches_found: matches,
        }
    }
}

fn build_json_output(
    patterns: usize,
    payload_size_bytes: usize,
    iterations: usize,
    engine_name: &str,
    compile_ms: f64,
    result: &BenchResult,
    vectorscan_result: Option<&(f64, BenchResult)>,
) -> String {
    let mut map = serde_json::Map::new();

    map.insert(
        "patterns".to_string(),
        serde_json::Value::Number(serde_json::Number::from(patterns)),
    );
    map.insert(
        "payload_size_kb".to_string(),
        serde_json::Value::Number(serde_json::Number::from(payload_size_bytes / 1024)),
    );
    map.insert(
        "iterations".to_string(),
        serde_json::Value::Number(serde_json::Number::from(iterations)),
    );
    map.insert("engine".to_string(), serde_json::Value::String(engine_name.to_string()));

    let engine_obj = result_to_json_value(compile_ms, result);
    map.insert(engine_name.to_string(), engine_obj);

    let vs_val = match vectorscan_result {
        Some((compile_ms, res)) => result_to_json_value(*compile_ms, res),
        None => serde_json::Value::Null,
    };
    map.insert("vectorscan".to_string(), vs_val);

    serde_json::to_string_pretty(&serde_json::Value::Object(map)).unwrap()
}

fn result_to_json_value(compile_ms: f64, res: &BenchResult) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("compile_ms".to_string(), round_val(compile_ms));
    obj.insert("scan_p50_ms".to_string(), round_val(res.scan_p50_ms));
    obj.insert("scan_p99_ms".to_string(), round_val(res.scan_p99_ms));
    obj.insert("throughput_mbps".to_string(), round_val(res.throughput_mbps));
    obj.insert(
        "matches_found".to_string(),
        serde_json::Value::Number(serde_json::Number::from(res.matches_found)),
    );
    serde_json::Value::Object(obj)
}

fn round_val(v: f64) -> serde_json::Value {
    let rounded = (v * 1000.0).round() / 1000.0;
    serde_json::Value::Number(serde_json::Number::from_f64(rounded).unwrap_or_else(|| serde_json::Number::from(0)))
}
