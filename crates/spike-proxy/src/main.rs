#![allow(missing_docs)]

use std::net::SocketAddr;
use std::process::ExitCode;

use spike_proxy::bench::{payload_sizes_kb, run_bench};
use spike_proxy::proxy::{spawn_proxy, spawn_upstream};

const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:8090";
const DEFAULT_UPSTREAM_ADDR: &str = "127.0.0.1:8091";
const DEFAULT_ITERATIONS: usize = 1000;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Proxy,
    Upstream,
    Bench,
}

struct Args {
    mode: Mode,
    listen: Option<SocketAddr>,
    upstream: Option<SocketAddr>,
    payload_kb: Option<usize>,
    iterations: usize,
}

fn parse_addr(s: &str) -> SocketAddr {
    s.parse().unwrap_or_else(|_| panic!("invalid address: {s}"))
}

fn parse_args() -> Args {
    let raw: Vec<String> = std::env::args().collect();
    let mut args = Args {
        mode: Mode::Proxy,
        listen: None,
        upstream: None,
        payload_kb: None,
        iterations: DEFAULT_ITERATIONS,
    };
    let mut i = 1;
    while i < raw.len() {
        match raw[i].as_str() {
            "--upstream" => args.mode = Mode::Upstream,
            "--bench" => args.mode = Mode::Bench,
            "--listen" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.listen = Some(parse_addr(v));
                }
            }
            "--upstream-addr" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.upstream = Some(parse_addr(v));
                }
            }
            "--payload-kb" => {
                i += 1;
                args.payload_kb = raw.get(i).and_then(|v| v.parse().ok());
            }
            "--iterations" => {
                i += 1;
                args.iterations = raw.get(i).and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_ITERATIONS);
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    args
}

fn print_help() {
    println!(
        "spike-proxy: reverse proxy latency spike\n\
         \n\
         Modes:\n\
         \x20 default            run reverse proxy (listen {DEFAULT_PROXY_ADDR}, forward to {DEFAULT_UPSTREAM_ADDR})\n\
         \x20 --upstream          run synthetic LLM upstream server (listen {DEFAULT_UPSTREAM_ADDR})\n\
         \x20 --bench             run overhead benchmark (p50/p99 of proxy vs direct)\n\
         \n\
         Flags:\n\
         \x20 --listen <ADDR>     listen address\n\
         \x20 --upstream-addr <ADDR>  upstream address for the proxy\n\
         \x20 --payload-kb <N>    bench: single payload size in KB (default: all of {:?})\n\
         \x20 --iterations <N>    bench: iterations per path (default {DEFAULT_ITERATIONS})",
        payload_sizes_kb()
    );
}

fn main() -> ExitCode {
    let args = parse_args();
    let code = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime")
        .block_on(run(args));
    ExitCode::from(code)
}

async fn run(args: Args) -> u8 {
    match args.mode {
        Mode::Upstream => run_upstream_mode(&args).await,
        Mode::Proxy => run_proxy_mode(&args).await,
        Mode::Bench => run_bench_mode(&args).await,
    }
}

async fn run_upstream_mode(args: &Args) -> u8 {
    let listen = args.listen.unwrap_or_else(|| parse_addr(DEFAULT_UPSTREAM_ADDR));
    match spawn_upstream(listen).await {
        Ok((addr, handle)) => {
            eprintln!("upstream listening on {addr}");
            let _ = handle.await;
            0
        }
        Err(e) => {
            eprintln!("upstream failed to start: {e}");
            1
        }
    }
}

async fn run_proxy_mode(args: &Args) -> u8 {
    let listen = args.listen.unwrap_or_else(|| parse_addr(DEFAULT_PROXY_ADDR));
    let upstream = args.upstream.unwrap_or_else(|| parse_addr(DEFAULT_UPSTREAM_ADDR));
    match spawn_proxy(listen, upstream).await {
        Ok((addr, handle)) => {
            eprintln!("proxy listening on {addr}, forwarding to {upstream}");
            let _ = handle.await;
            0
        }
        Err(e) => {
            eprintln!("proxy failed to start: {e}");
            1
        }
    }
}

async fn run_bench_mode(args: &Args) -> u8 {
    let iterations = args.iterations;
    let sizes: Vec<usize> = args
        .payload_kb
        .map_or_else(|| payload_sizes_kb().to_vec(), |kb| vec![kb]);
    let mut results = Vec::with_capacity(sizes.len());
    for kb in sizes {
        match run_bench(kb, iterations).await {
            Ok(res) => results.push(res),
            Err(e) => {
                eprintln!("bench failed at {kb} KB: {e}");
                return 1;
            }
        }
    }
    let json = if results.len() == 1 {
        serde_json::to_string_pretty(&results[0]).expect("serialize bench result")
    } else {
        serde_json::to_string_pretty(&results).expect("serialize bench results")
    };
    println!("{json}");
    0
}
