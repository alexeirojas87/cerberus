use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Headers that must not be forwarded verbatim between client and upstream.
const SKIP_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Spawn a synthetic LLM upstream server that echoes request metadata.
///
/// Returns the bound address (useful when `listen` uses port 0) and a handle
/// to the serving task.
pub async fn spawn_upstream(
    listen: SocketAddr,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen).await?;
    let actual = listener.local_addr()?;
    let handle = tokio::spawn(serve_upstream(listener));
    Ok((actual, handle))
}

/// Spawn a reverse proxy that forwards to `upstream`.
///
/// Returns the bound address (useful when `listen` uses port 0) and a handle
/// to the serving task.
pub async fn spawn_proxy(
    listen: SocketAddr,
    upstream: SocketAddr,
) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen).await?;
    let actual = listener.local_addr()?;
    let handle = tokio::spawn(serve_proxy(listener, upstream));
    Ok((actual, handle))
}

pub(crate) async fn serve_upstream(listener: TcpListener) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("upstream accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        tokio::spawn(async move {
            let service = service_fn(upstream_handler);
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("upstream connection error: {err}");
            }
        });
    }
}

pub(crate) async fn serve_proxy(listener: TcpListener, upstream: SocketAddr) {
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("proxy accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let client = client.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let client = client.clone();
                async move { proxy_handler(req, client, upstream).await }
            });
            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("proxy connection error: {err}");
            }
        });
    }
}

/// Synthetic LLM upstream: returns a small JSON acknowledging the request and
/// echoing method, path, body length and a test header so forwarding can be
/// verified end-to-end.
async fn upstream_handler(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    let body_len = body_bytes.len();
    let method = parts.method.to_string();
    let path = parts.uri.path().to_string();
    let test_header = parts
        .headers
        .get("x-test-header")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let payload = serde_json::json!({
        "ok": true,
        "method": method,
        "path": path,
        "body_len": body_len,
        "test_header": test_header,
    });
    let bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("x-upstream", "spike-upstream")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| e.to_string())
}

/// Reverse proxy handler: copies method, (non hop-by-hop) headers, path and
/// buffered body to the upstream and relays the upstream response back.
async fn proxy_handler(
    req: Request<Incoming>,
    client: Client<HttpConnector, Full<Bytes>>,
    upstream: SocketAddr,
) -> Result<Response<Full<Bytes>>, String> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();

    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".to_string(), ToString::to_string);
    let uri: Uri = format!("http://{upstream}{path_and_query}")
        .parse()
        .map_err(|e| format!("invalid upstream uri: {e}"))?;

    let mut builder = Request::builder().method(parts.method).uri(uri);
    for (name, value) in &parts.headers {
        if SKIP_HEADERS.contains(&name.as_str()) {
            continue;
        }
        builder = builder.header(name, value);
    }
    let up_req = builder.body(Full::new(body_bytes)).map_err(|e| e.to_string())?;

    let resp = client.request(up_req).await.map_err(|e| e.to_string())?;
    let (resp_parts, resp_body) = resp.into_parts();
    let resp_bytes = resp_body.collect().await.map_err(|e| e.to_string())?.to_bytes();

    let mut response = Response::new(Full::new(resp_bytes));
    *response.status_mut() = resp_parts.status;
    *response.headers_mut() = resp_parts.headers;
    Ok(response)
}
