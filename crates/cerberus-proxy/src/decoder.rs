//! Provider-agnostic body decoder (§4.2 of the build plan).
//!
//! Decodes the request body (JSON/text/multipart) and extracts all the
//! textual content for scanning. It is agnostic by construction: it works
//! with any LLM provider.
//!
//! Multipart (§4.2 MVP scope, R9-13): `multipart/form-data` bodies are
//! parsed with a bounded delimiter scanner; the payload of every **textual**
//! part is extracted for scanning (the same content the JSON path scans),
//! while **binary** parts (`application/octet-stream`, `image/*`, `audio/*`,
//! `video/*`, …) are NOT scanned and stay byte-exact end to end. The raw
//! body is never re-parsed downstream: the redaction path consumes the
//! [`TextRegion`] offsets recorded here (single parse per request).
//!
//! FIX attempt 2 (review 9 P1-1): the regions cover ALL the scannable text,
//! not just part payloads — the preamble, the epilogue and every part's
//! header block are recorded as text regions too (the old lossy path scanned
//! them; dropping them was a silent under-scan). Binary part PAYLOADS stay
//! byte-exact and unscanned; every skipped payload is counted in
//! [`DecodedBody::binary_parts_skipped`] so the under-scan is visible in the
//! audit trail (review 9 P2-1), never silent.

use bytes::Bytes;

/// Maximum accepted `boundary=` parameter length (bounded parsing, R9-13).
/// RFC 2046 caps boundaries at 70 chars; 256 gives generous real-world
/// tolerance while keeping a crafted header from driving unbounded work.
const MAX_BOUNDARY_LEN: usize = 256;

/// Maximum number of parts parsed from one multipart body. Beyond this the
/// body falls back to whole-text scanning (over-scan, never under-scan) so
/// adversarial part-count bombs cannot drive unbounded work. (Each part
/// contributes at most two scanned regions — headers + payload — so the
/// region count stays bounded at ~2× this.)
const MAX_MULTIPART_REGIONS: usize = 4096;

/// Result of decoding a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBody {
    /// All the textual content extracted for scanning.
    pub text: String,
    /// Detected content type.
    pub content_type: ContentType,
    /// The parsed JSON tree when `content_type` is [`ContentType::Json`]
    /// (fix F2.1 / review 9 R9-1: parse the body ONCE per request in the
    /// pipeline — the redaction path reuses this value instead of parsing
    /// the same bytes a second time). `None` for plain-text bodies.
    pub parsed: Option<serde_json::Value>,
    /// Textual regions of a `multipart/form-data` body (R9-13): byte
    /// offsets into the RAW body of every scanned region — text-part
    /// payloads PLUS part-header blocks, the preamble and the epilogue
    /// (fix P1-1) — recorded at decode time so the redaction path never
    /// re-parses the multipart structure. `None` for non-multipart bodies.
    pub multipart: Option<Vec<TextRegion>>,
    /// How many binary-claimed part PAYLOADS were skipped (not scanned) in
    /// the structured parse (fix P2-1): the byte-exact-preservation trade-off
    /// must be VISIBLE — the pipeline turns a non-zero count into an audit
    /// flag, so an under-scanned request is never silent. `0` for
    /// non-multipart bodies and for the whole-text fallback (which scans
    /// everything).
    pub binary_parts_skipped: usize,
}

/// What one recorded [`TextRegion`] carries (fix P1-1). The scan and the
/// redaction treat every region identically; the kind exists so tests and
/// audits can assert WHERE the text came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Bytes before the first boundary delimiter (excluding the line break
    /// that belongs to the delimiter line).
    Preamble,
    /// One part's header block, between the delimiter line and the blank
    /// line (the separator itself stays out so redaction cannot eat it).
    PartHeaders,
    /// One textual part's payload.
    Payload,
    /// Bytes after the closing `--` delimiter line.
    Epilogue,
}

/// Byte offsets (into the raw body) of one scanned multipart region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextRegion {
    /// Offset of the first payload byte.
    pub start: usize,
    /// Offset one past the last payload byte.
    pub end: usize,
    /// What this region carries.
    pub kind: RegionKind,
}

/// Body content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// JSON body (most common in LLM APIs).
    Json,
    /// Plain text.
    Text,
    /// `multipart/form-data` (§4.2 MVP: textual parts are scanned, binary
    /// parts are preserved byte-exact).
    Multipart,
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => f.write_str("json"),
            Self::Text => f.write_str("text"),
            Self::Multipart => f.write_str("multipart"),
        }
    }
}

/// Decode a body into a `DecodedBody`.
///
/// Strategy (§4.2):
/// 1. If it is JSON, serialize the whole JSON to a string (this extracts all
///    the text fields, regardless of the provider's schema).
/// 2. If the content type declares `multipart/form-data` with a usable
///    `boundary`, parse the parts and scan every textual part payload.
/// 3. If it is not JSON (or the multipart structure is unusable), treat it
///    as plain text — the safe over-scan fallback.
/// 4. The extracted text is passed to the detection engine.
#[must_use]
pub fn decode(body: &Bytes, content_type_hint: Option<&str>) -> DecodedBody {
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) {
        let text = json_to_string(&json);
        return DecodedBody {
            text,
            content_type: ContentType::Json,
            parsed: Some(json),
            multipart: None,
            binary_parts_skipped: 0,
        };
    }

    if let Some(hint) = content_type_hint {
        if let Some(boundary) = multipart_boundary(hint) {
            if let Some((regions, binary_skipped)) = parse_multipart(body, &boundary) {
                // Informational view of everything the structured parse
                // scans, joined with a separator. NOTE: the pipeline scans
                // each region IN ISOLATION (never across this join) so the
                // decision view and the redaction view are the same model —
                // a pattern spanning two regions is visible to neither (fix
                // F-1/F-2: one authoritative scan model for both).
                let mut text = String::new();
                for region in &regions {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&String::from_utf8_lossy(&body[region.start..region.end]));
                }
                return DecodedBody {
                    text,
                    content_type: ContentType::Multipart,
                    parsed: None,
                    multipart: Some(regions),
                    binary_parts_skipped: binary_skipped,
                };
            }
        }
    }

    let text = String::from_utf8_lossy(body).to_string();
    DecodedBody {
        text,
        content_type: ContentType::Text,
        parsed: None,
        multipart: None,
        binary_parts_skipped: 0,
    }
}

/// Recursively extract all the text from a JSON Value.
fn json_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => {
            let mut parts: Vec<String> = arr.iter().map(json_to_string).collect();
            parts.retain(|p| !p.is_empty());
            parts.join(" ")
        }
        serde_json::Value::Object(obj) => {
            let mut parts: Vec<String> = obj.values().map(json_to_string).collect();
            parts.retain(|p| !p.is_empty());
            parts.join(" ")
        }
        _ => String::new(),
    }
}

// ── Multipart/form-data (§4.2 MVP, R9-13) ──

/// Extract the `boundary` parameter from a `Content-Type` hint.
///
/// Returns `None` when the hint does not declare `multipart/` or carries no
/// usable boundary (missing, empty or over [`MAX_BOUNDARY_LEN`] — bounded
/// parsing). Quoted boundaries (RFC 2045 `quoted-string`) are unwrapped.
#[must_use]
fn multipart_boundary(content_type_hint: &str) -> Option<String> {
    let lower = content_type_hint.to_ascii_lowercase();
    // `to_ascii_lowercase` preserves byte length, so `pos` indexes the
    // original string too.
    if !lower.contains("multipart/") {
        return None;
    }
    let pos = lower.find("boundary=")?;
    let raw = content_type_hint[pos + "boundary=".len()..].trim_start();
    let value = if let Some(rest) = raw.strip_prefix('"') {
        // Quoted form: everything up to the closing quote (may contain ';').
        let end = rest.find('"')?;
        &rest[..end]
    } else {
        raw.split(';').next().unwrap_or("").trim_end()
    };
    if value.is_empty() || value.len() > MAX_BOUNDARY_LEN {
        return None;
    }
    Some(value.to_string())
}

/// Is a part with this `Content-Type` textual (scanned) for MVP purposes?
///
/// A part WITHOUT a `Content-Type` header defaults to `text/plain`
/// (RFC 7578 §4.4). Scanned: `text/*` plus the known textual `application`
/// types LLM traffic actually carries. Everything else is treated as binary:
/// not scanned, preserved byte-exact (§4.2 / F3.1 mandate exact preservation
/// of binaries, so unknown non-text types fail toward preservation, and the
/// trade-off is documented in the evidence pack).
fn part_is_textual(content_type: Option<&[u8]>) -> bool {
    let Some(raw) = content_type else {
        return true; // no Content-Type → RFC 7578 default text/plain
    };
    let value = String::from_utf8_lossy(raw);
    let base = value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if base.is_empty() {
        return true; // empty header value → default text/plain
    }
    base.starts_with("text/")
        || matches!(
            base.as_str(),
            "application/json"
                | "application/xml"
                | "application/x-www-form-urlencoded"
                | "application/javascript"
                | "application/yaml"
                | "application/x-yaml"
        )
}

/// Parse a `multipart/form-data` body and return the byte ranges of every
/// scanned TEXT region — textual part payloads, PLUS every part's header
/// block, the preamble and the epilogue (fix P1-1: the old lossy path
/// scanned all of that text; dropping it was a silent under-scan) — together
/// with the count of binary-claimed part payloads that were skipped (fix
/// P2-1: the skip must be visible, never silent).
///
/// Bounded by construction: one linear pass over the body (the delimiter
/// search is a first-byte probe, never `windows()`), at most
/// [`MAX_MULTIPART_REGIONS`] parts; beyond that it returns `None` so the
/// caller falls back to whole-text scanning. Robustness (F3.1 adversarial
/// cases): a delimiter only counts at the start of the body or after a line
/// break (`\r\n` or `\n`) AND its suffix must end a delimiter line (fix F1:
/// CRLF/LF, transport padding, or the closing `--`; a junk suffix is payload
/// text — the token stays in the part and the body continues to be scanned);
/// transport padding is tolerated; a truncated body
/// (no closing delimiter) yields the parts found so far with the last
/// payload running to EOF; a body with no delimiter at all returns `None`
/// (whole-text fallback). Never panics.
///
/// Regions are returned in ascending offset order and never overlap, so the
/// redaction path can splice them in reverse safely. The line break that
/// belongs to a delimiter line is kept OUT of the neighbouring regions, so a
/// redaction splice can never swallow a delimiter's line break.
///
/// `Some((vec![], n))` means the structure parsed but the body carries only
/// binary part payloads: no payload text was scanned (the part header
/// blocks, preamble and epilogue still are) and the binaries stay byte-exact.
#[must_use]
fn parse_multipart(body: &[u8], boundary: &str) -> Option<(Vec<TextRegion>, usize)> {
    let delim = format!("--{boundary}");
    let delim = delim.as_bytes();

    // Opening delimiter: at body start or at the start of a line.
    let first = find_delimiter(body, delim, 0)?;
    let mut cursor = first + delim.len();
    let mut regions: Vec<TextRegion> = Vec::new();
    let mut binary_skipped = 0usize;
    let mut parts_seen = 0usize;

    // Preamble (fix P1-1): everything before the first delimiter, minus the
    // line break that belongs to the delimiter line (a redaction splice must
    // not swallow it — the upstream parser needs the delimiter at line
    // start).
    if first > 0 {
        let end = strip_preceding_line_break(body, first);
        if end > 0 {
            regions.push(TextRegion {
                start: 0,
                end,
                kind: RegionKind::Preamble,
            });
        }
    }

    loop {
        // After the delimiter: optional transport padding, then either the
        // closing `--`, a line break (part follows), or EOF.
        let after_pad = skip_transport_padding(body, cursor);
        if body[after_pad.min(body.len())..].starts_with(b"--") {
            // Closing delimiter (fix P1-1): the epilogue after the `--` (and
            // its terminating line break, which belongs to the delimiter
            // line per RFC 2046) is scanned as text. Nothing structural
            // follows it, so a splice there cannot corrupt the MIME
            // structure.
            let after_close = skip_line_break(body, (after_pad.min(body.len()) + 2).min(body.len()));
            if after_close < body.len() {
                regions.push(TextRegion {
                    start: after_close,
                    end: body.len(),
                    kind: RegionKind::Epilogue,
                });
            }
            break;
        }
        let part_start = skip_line_break(body, after_pad);

        // Find the delimiter closing this part.
        let next = find_delimiter(body, delim, part_start);
        // Truncated body: the last payload runs to EOF and there is no
        // closing delimiter.
        let (payload_end, next_cursor) = next.map_or(
            // The payload ends before the line break that precedes the
            // delimiter.
            (body.len(), body.len()),
            |pos| (strip_preceding_line_break(body, pos), pos + delim.len()),
        );

        parts_seen += 1;
        if parts_seen > MAX_MULTIPART_REGIONS {
            // Part-count bomb: abandon the structured parse; the caller
            // falls back to whole-text scanning (over-scan).
            return None;
        }

        // Split the part into headers and payload at the first blank line.
        let (headers, payload) = split_part_headers(body, part_start, payload_end);
        // Part headers are text (fix P1-1): a secret in `Content-Disposition`
        // or a custom header must be detected (and redacted in place), not
        // forwarded raw. Recorded for EVERY part — a binary part's headers
        // are still text.
        if let Some(header_bytes) = headers {
            let header_start = part_start;
            let header_end = part_start + header_bytes.len();
            if header_end > header_start {
                regions.push(TextRegion {
                    start: header_start,
                    end: header_end,
                    kind: RegionKind::PartHeaders,
                });
            }
        }
        if payload.end > payload.start {
            if part_is_textual(part_content_type(headers)) {
                regions.push(TextRegion {
                    start: payload.start,
                    end: payload.end,
                    kind: RegionKind::Payload,
                });
            } else {
                // Binary part payload: preserved byte-exact, NOT scanned
                // (§4.2 trade-off) — but the skip is COUNTED so the pipeline
                // can surface it (fix P2-1, never silent under-scan).
                binary_skipped += 1;
            }
        }

        if next.is_none() || next_cursor >= body.len() {
            break;
        }
        cursor = next_cursor;
    }

    if parts_seen == 0 {
        // No part at all: a structural surprise — fall back to whole-text
        // scanning so the body never silently escapes the scan.
        return None;
    }
    Some((regions, binary_skipped))
}

/// Position of the next delimiter occurrence at/after `from` that starts the
/// body or a line (`\r\n` or `\n` before it) AND carries a legal suffix (fix
/// F1: the bytes after the token must end a delimiter line — CRLF/LF,
/// transport padding, or the closing `--`; anything else is payload text).
/// Linear scan with a first-byte probe (bounded, no `windows()` quadratic
/// blow-up on adversarial bodies). An invalid-suffix token is skipped and the
/// scan continues (`i += 1`): the token stays inside the current part's
/// payload, which continues to be scanned.
fn find_delimiter(body: &[u8], delim: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + delim.len() <= body.len() {
        if body[i] == delim[0] && body[i..i + delim.len()] == *delim {
            // Delimiter validity: start of body or preceded by a line break,
            // plus the F1 suffix validation.
            if (i == 0 || body[i - 1] == b'\n') && delimiter_suffix_is_valid(body, i + delim.len()) {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// F1 suffix validation (design verdict table, RFC 2046 §6.4): is the text
/// right after a `--boundary` token a legal ending for a delimiter line?
///
/// | suffix                            | verdict |
/// |-----------------------------------|---------|
/// | CRLF / LF                         | VALID open (LF: documented leniency beyond strict RFC 2046) |
/// | LWSP* then CRLF / LF              | VALID open + transport padding |
/// | `--` then LWSP* then CRLF/LF/EOF  | VALID close |
/// | `--` then EOF                     | VALID close (documented leniency) |
/// | LWSP* then EOF (open)             | INVALID → whole-text over-scan fallback (fail-safe, never under-scan) |
/// | any other byte                    | INVALID → payload text, keep scanning |
fn delimiter_suffix_is_valid(body: &[u8], p: usize) -> bool {
    if p >= body.len() {
        // Open delimiter at EOF (no `--`, no line break): not a delimiter
        // line. The whole-text fallback over-scans, so nothing escapes.
        return false;
    }
    if body[p] == b'-' && p + 1 < body.len() && body[p + 1] == b'-' {
        // Close delimiter: `--` then LWSP* then CRLF/LF/EOF.
        let after = skip_transport_padding(body, p + 2);
        return after >= body.len() || body[after] == b'\r' || body[after] == b'\n';
    }
    // Open delimiter: LWSP* then CRLF or LF.
    let after = skip_transport_padding(body, p);
    if after >= body.len() {
        // LWSP* then EOF on an open delimiter → invalid (over-scan fallback).
        return false;
    }
    if body[after] == b'\n' {
        return true;
    }
    body[after] == b'\r' && after + 1 < body.len() && body[after + 1] == b'\n'
}

/// Skip RFC 2046 transport padding (SP / HTAB) after a delimiter.
const fn skip_transport_padding(body: &[u8], mut i: usize) -> usize {
    while i < body.len() && (body[i] == b' ' || body[i] == b'\t') {
        i += 1;
    }
    i
}

/// Skip one line break after a delimiter, returning the part start.
const fn skip_line_break(body: &[u8], i: usize) -> usize {
    if i < body.len() && body[i] == b'\r' && i + 1 < body.len() && body[i + 1] == b'\n' {
        return i + 2;
    }
    if i < body.len() && body[i] == b'\n' {
        return i + 1;
    }
    i
}

/// Length in bytes of the line break that ends at `end` (the delimiter is at
/// `end`): `\r\n` = 2, `\n` = 1, none = 0.
const fn strip_preceding_line_break(body: &[u8], end: usize) -> usize {
    if end >= 2 && body[end - 2] == b'\r' && body[end - 1] == b'\n' {
        return end - 2;
    }
    if end >= 1 && body[end - 1] == b'\n' {
        return end - 1;
    }
    end
}

/// Split one part into `(headers, payload_range)` at the first blank line
/// (`\r\n\r\n` canonical, bare `\n\n` tolerated). A part without a blank
/// line is treated as header-less: the whole region is the payload
/// (tolerant over-scan; the RFC-mandated headers are simply absent).
fn split_part_headers(body: &[u8], part_start: usize, part_end: usize) -> (Option<&[u8]>, std::ops::Range<usize>) {
    let region = &body[part_start..part_end];
    // Earliest of the canonical and the tolerated separators.
    let crlf = find_subslice(region, b"\r\n\r\n");
    let lf = find_subslice(region, b"\n\n");
    let sep = match (crlf, lf) {
        (Some(c), Some(l)) => Some(if c <= l { (c, 4) } else { (l, 2) }),
        (Some(c), None) => Some((c, 4)),
        (None, Some(l)) => Some((l, 2)),
        (None, None) => None,
    };
    match sep {
        Some((pos, sep_len)) => (
            Some(&region[..pos]),
            std::ops::Range {
                start: part_start + pos + sep_len,
                end: part_end,
            },
        ),
        None => (
            None,
            std::ops::Range {
                start: part_start,
                end: part_end,
            },
        ),
    }
}

/// First position of `needle` in `haystack` (linear, first-byte probe).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if haystack[i] == needle[0] && &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Extract the value of the `Content-Type` header from one part's header
/// block (case-insensitive name match; value runs to the end of the line).
fn part_content_type(headers: Option<&[u8]>) -> Option<&[u8]> {
    const CT_PREFIX: &[u8] = b"content-type:";
    let headers = headers?;
    let mut start = 0;
    while start < headers.len() {
        let line_end = headers[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(headers.len(), |p| start + p);
        let mut end = line_end;
        if end > start && headers[end - 1] == b'\r' {
            end -= 1;
        }
        let line = &headers[start..end];
        if line.len() > CT_PREFIX.len() && line[..CT_PREFIX.len()].eq_ignore_ascii_case(CT_PREFIX) {
            let mut v = CT_PREFIX.len();
            if line[v] == b' ' {
                v += 1;
            }
            if v >= line.len() {
                return None; // empty header value → RFC 7578 default
            }
            return Some(&headers[start + v..end]);
        }
        start = line_end + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_json_object() {
        let body = Bytes::from(r#"{"prompt":"my api key is sk-abc123","user":"alice"}"#);
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Json);
        assert!(decoded.text.contains("sk-abc123"));
        assert!(decoded.text.contains("alice"));
    }

    #[test]
    fn decode_json_array() {
        let body = Bytes::from(r#"[{"role":"user","content":"hello"},{"role":"assistant","content":"hi"}]"#);
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Json);
        assert!(decoded.text.contains("hello"));
        assert!(decoded.text.contains("hi"));
    }

    #[test]
    fn decode_json_nested() {
        let body = Bytes::from(r#"{"messages":[{"role":"user","content":"my token is sk-secret"}]}"#);
        let decoded = decode(&body, None);
        assert!(decoded.text.contains("sk-secret"));
    }

    #[test]
    fn decode_plain_text() {
        let body = Bytes::from("this is plain text with a secret api_key=abc123");
        let decoded = decode(&body, None);
        assert_eq!(decoded.content_type, ContentType::Text);
        assert!(decoded.text.contains("api_key=abc123"));
    }

    #[test]
    fn decode_empty_body() {
        let body = Bytes::from("");
        let decoded = decode(&body, None);
        assert!(decoded.text.is_empty());
    }

    #[test]
    fn decode_json_ignores_numbers_and_bools() {
        let body = Bytes::from(r#"{"count":42,"active":true,"name":"secret"}"#);
        let decoded = decode(&body, None);
        assert!(!decoded.text.contains("42"));
        assert!(!decoded.text.contains("true"));
        assert!(decoded.text.contains("secret"));
    }

    #[test]
    fn decode_invalid_utf8_fallback() {
        let body = Bytes::copy_from_slice(&[0xff, 0xfe, 0x00]);
        let decoded = decode(&body, None);
        assert!(!decoded.text.is_empty());
    }

    #[test]
    fn content_type_display() {
        assert_eq!(ContentType::Json.to_string(), "json");
        assert_eq!(ContentType::Text.to_string(), "text");
        assert_eq!(ContentType::Multipart.to_string(), "multipart");
    }

    // ── R9-13: multipart/form-data (§4.2 MVP) ──

    const B: &str = "testboundary123";

    /// Build a canonical multipart body from `(headers, payload)` parts.
    fn mp(parts: &[(&str, &[u8])]) -> Bytes {
        let mut body = Vec::new();
        for (headers, payload) in parts {
            body.extend_from_slice(format!("--{B}\r\n").as_bytes());
            body.extend_from_slice(headers.as_bytes());
            body.extend_from_slice(b"\r\n\r\n");
            body.extend_from_slice(payload);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{B}--\r\n").as_bytes());
        Bytes::from(body)
    }

    fn decode_mp(body: &Bytes) -> DecodedBody {
        decode(body, Some(&format!("multipart/form-data; boundary={B}")))
    }

    fn region_text(body: &[u8], regions: &[TextRegion]) -> Vec<String> {
        regions
            .iter()
            .map(|r| String::from_utf8_lossy(&body[r.start..r.end]).into_owned())
            .collect()
    }

    #[test]
    fn multipart_multiple_text_parts_extracted() {
        let body = mp(&[
            ("Content-Disposition: form-data; name=\"model\"", b"gpt-4o"),
            (
                "Content-Disposition: form-data; name=\"prompt\"\r\nContent-Type: text/plain",
                b"my token is sk-secret123",
            ),
        ]);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        assert!(decoded.parsed.is_none());
        assert!(decoded.text.contains("gpt-4o"));
        assert!(decoded.text.contains("sk-secret123"));
        let regions = decoded.multipart.as_ref().expect("regions");
        // Two payload regions + two part-header regions (fix P1-1).
        assert_eq!(regions.len(), 4);
        let payloads: Vec<TextRegion> = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Payload)
            .cloned()
            .collect();
        assert_eq!(payloads.len(), 2);
        let texts = region_text(&body, &payloads);
        assert_eq!(texts[0], "gpt-4o");
        assert_eq!(texts[1], "my token is sk-secret123");
    }

    #[test]
    fn multipart_binary_part_payload_not_scanned_but_headers_are() {
        let binary: Vec<u8> = (0u8..=255).cycle().take(300).collect();
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\n");
        body.extend_from_slice(b"Content-Type: audio/wav\r\n\r\n");
        let binary_start = body.len();
        body.extend_from_slice(&binary);
        let binary_end = body.len();
        body.extend_from_slice(format!("\r\n--{B}--\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        // The binary PAYLOAD is not a region; its HEADER BLOCK is (fix P1-1:
        // a secret in a part header is text regardless of the part type).
        let regions = decoded.multipart.as_ref().expect("regions recorded");
        assert_eq!(regions.len(), 1, "only the header block is a region");
        assert_eq!(regions[0].kind, RegionKind::PartHeaders);
        assert!(decoded.text.contains("filename=\"audio.wav\""));
        assert_eq!(decoded.binary_parts_skipped, 1, "the skipped payload must be counted");
        // The binary payload is exactly where the decoder says it is not:
        // it is simply untouched — verify its bytes are still in the body.
        assert_eq!(&body[binary_start..binary_end], &binary[..]);
    }

    #[test]
    fn multipart_part_without_content_type_defaults_text() {
        // RFC 7578 §4.4: a part without Content-Type defaults to text/plain.
        let body = mp(&[("Content-Disposition: form-data; name=\"note\"", b"api_key=abc123def")]);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 2, "part headers + payload");
        assert!(decoded.text.contains("api_key=abc123def"));
    }

    #[test]
    fn multipart_application_json_part_is_textual() {
        let body = mp(&[
            (
                "Content-Type: application/json",
                br#"{"q":"secret-value-xyz"}"#.as_slice(),
            ),
            ("Content-Type: application/octet-stream", [0u8, 1, 2, 3].as_slice()),
        ]);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 3, "json headers + json payload + binary headers");
        assert_eq!(decoded.binary_parts_skipped, 1, "octet-stream payload skipped");
        assert!(decoded.text.contains("secret-value-xyz"));
        assert!(!decoded.text.contains('\0'), "binary bytes must not be scanned");
    }

    #[test]
    fn multipart_octet_stream_and_image_are_binary() {
        let body = mp(&[
            ("Content-Type: application/octet-stream", [9u8; 16].as_slice()),
            ("Content-Type: image/png", [8u8; 16].as_slice()),
            ("Content-Type: charset-bogus/whatever", [7u8; 16].as_slice()),
        ]);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 3, "the three part header blocks are scanned");
        assert!(regions.iter().all(|r| r.kind == RegionKind::PartHeaders));
        assert_eq!(decoded.binary_parts_skipped, 3);
    }

    #[test]
    fn multipart_content_type_is_case_insensitive_with_params() {
        let body = mp(&[("content-type: TEXT/PLAIN; charset=utf-8", b"hello secret world")]);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 2);
        let payload = regions.iter().find(|r| r.kind == RegionKind::Payload).expect("payload");
        assert_eq!(
            region_text(&body, std::slice::from_ref(payload))[0],
            "hello secret world"
        );
    }

    #[test]
    fn multipart_quoted_boundary_parses() {
        let body = mp(&[("Content-Type: text/plain", b"quoted boundary works")]);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary=\"{B}\"")));
        assert_eq!(decoded.content_type, ContentType::Multipart);
        assert!(decoded.text.contains("quoted boundary works"));
    }

    #[test]
    fn multipart_boundary_with_special_characters() {
        // Regex-special characters are irrelevant: matching is byte search.
        let boundary = "----abc123::++??**";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\nsecret-in-part\r\n");
        body.extend_from_slice(format!("--{boundary}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary=\"{boundary}\"")));
        assert_eq!(decoded.content_type, ContentType::Multipart);
        assert!(decoded.text.contains("secret-in-part"));
    }

    #[test]
    fn multipart_boundary_too_long_falls_back_to_text() {
        // Bounded parsing: a boundary over MAX_BOUNDARY_LEN is refused.
        let long = format!("b{}", "x".repeat(600));
        let body = mp(&[("Content-Type: text/plain", b"payload")]);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={long}")));
        assert_eq!(
            decoded.content_type,
            ContentType::Text,
            "over-long boundary → text fallback"
        );
    }

    #[test]
    fn multipart_missing_boundary_falls_back_to_text() {
        let body = mp(&[("Content-Type: text/plain", b"payload")]);
        let decoded = decode(&body, Some("multipart/form-data"));
        assert_eq!(decoded.content_type, ContentType::Text);
    }

    #[test]
    fn multipart_body_without_any_delimiter_falls_back_to_text() {
        // A multipart hint over a body that is not multipart at all.
        let body = Bytes::from("this is not multipart content at all");
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={B}")));
        assert_eq!(decoded.content_type, ContentType::Text);
        assert!(decoded.text.contains("not multipart"));
    }

    #[test]
    fn multipart_truncated_body_still_scans_last_payload() {
        // No closing delimiter: the last payload runs to EOF and is scanned.
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\nfirst part ok\r\n");
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\nsecond part TRUNCATED-SECRET-x9");
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 4, "two header blocks + two payloads");
        let payloads: Vec<TextRegion> = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Payload)
            .cloned()
            .collect();
        let texts = region_text(&body, &payloads);
        assert_eq!(texts[1], "second part TRUNCATED-SECRET-x9");
        assert!(decoded.text.contains("TRUNCATED-SECRET-x9"));
    }

    #[test]
    fn multipart_preamble_epilogue_and_headers_are_scanned_regions() {
        // FIX P1-1 (attempt 2): the preamble, the epilogue and part headers
        // are scanned text regions — a secret in any of them is DETECTED
        // (the old lossy path scanned all of this text; dropping it was a
        // silent under-scan).
        let mut body = Vec::new();
        body.extend_from_slice(b"preamble with SECRET-IN-PREAMBLE-12345678\r\n");
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\nX-Note: SECRET-IN-HEADER-123456\r\n\r\n");
        body.extend_from_slice(b"real payload here\r\n");
        body.extend_from_slice(format!("--{B}--\r\n").as_bytes());
        body.extend_from_slice(b"epilogue with SECRET-IN-EPILOGUE-123456\r\n");
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        let regions = decoded.multipart.expect("regions");
        let kinds: Vec<RegionKind> = regions.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&RegionKind::Preamble), "kinds: {kinds:?}");
        assert!(kinds.contains(&RegionKind::PartHeaders));
        assert!(kinds.contains(&RegionKind::Payload));
        assert!(kinds.contains(&RegionKind::Epilogue), "kinds: {kinds:?}");
        assert!(decoded.text.contains("SECRET-IN-PREAMBLE-12345678"));
        assert!(decoded.text.contains("SECRET-IN-HEADER-123456"));
        assert!(decoded.text.contains("SECRET-IN-EPILOGUE-123456"));
        assert!(decoded.text.contains("real payload here"));
        // Structural bytes stay out of the regions: the delimiter lines and
        // the blank separator line are never part of a scanned region.
        assert!(!decoded.text.contains(&format!("--{B}")));
        let header = regions
            .iter()
            .find(|r| r.kind == RegionKind::PartHeaders)
            .expect("header");
        let header_text = region_text(&body, std::slice::from_ref(header))[0].clone();
        assert!(
            !header_text.contains("\r\n\r\n"),
            "blank line stays out: {header_text:?}"
        );
    }

    #[test]
    fn multipart_preamble_region_never_swallows_the_delimiter_line_break() {
        // The line break that belongs to the first delimiter line must stay
        // out of the preamble region so a redaction splice there cannot
        // de-line-start the delimiter.
        let mut body = Vec::new();
        body.extend_from_slice(b"preamble text");
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\npayload\r\n");
        body.extend_from_slice(format!("--{B}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        let pre = regions
            .iter()
            .find(|r| r.kind == RegionKind::Preamble)
            .expect("preamble");
        assert_eq!(region_text(&body, std::slice::from_ref(pre))[0], "preamble text");
        // And the body still re-parses: the payload region is intact.
        let payload = regions.iter().find(|r| r.kind == RegionKind::Payload).expect("payload");
        assert_eq!(region_text(&body, std::slice::from_ref(payload))[0], "payload");
    }

    #[test]
    fn multipart_mid_line_delimiter_lookalike_is_not_a_boundary() {
        // The delimiter only counts at line start: a lookalike INSIDE a
        // payload line must not split the part.
        let payload = format!("look: --{B} not a boundary");
        let body = mp(&[("Content-Type: text/plain", payload.as_bytes())]);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        let payloads: Vec<TextRegion> = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Payload)
            .cloned()
            .collect();
        assert_eq!(payloads.len(), 1, "one part, not split mid-line");
        assert_eq!(region_text(&body, &payloads)[0], payload);
    }

    #[test]
    fn multipart_lf_only_line_endings_tolerated() {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\n\nlf-only payload\n");
        body.extend_from_slice(format!("--{B}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        assert!(decoded.text.contains("lf-only payload"));
    }

    #[test]
    fn multipart_transport_padding_tolerated() {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}   \r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\npadded delimiter payload\r\n");
        body.extend_from_slice(format!("--{B}--  \r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        assert!(decoded.text.contains("padded delimiter payload"));
    }

    #[test]
    fn multipart_many_parts_all_scanned() {
        let mut body = Vec::new();
        for i in 0..300 {
            body.extend_from_slice(format!("--{B}\r\nContent-Type: text/plain\r\n\r\npart-{i}-payload\r\n").as_bytes());
        }
        body.extend_from_slice(format!("--{B}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 600, "300 headers + 300 payloads");
        assert!(decoded.text.contains("part-299-payload"));
    }

    #[test]
    fn multipart_part_count_bomb_falls_back_to_text_over_scan() {
        // More parts than MAX_MULTIPART_REGIONS → the structured parse is
        // abandoned for the over-scan text fallback (bounded work).
        let boundary = "bomb";
        let mut body = Vec::new();
        for _ in 0..5000 {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Type: text/plain\r\n\r\nx\r\n").as_bytes());
        }
        body.extend_from_slice(format!("--{boundary}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some("multipart/form-data; boundary=bomb"));
        assert_eq!(decoded.content_type, ContentType::Text, "part bomb → text over-scan");
        assert!(decoded.text.contains('x'));
    }

    #[test]
    fn multipart_empty_payload_parts_skipped() {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n\r\n"); // empty payload
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\nnonempty\r\n");
        body.extend_from_slice(format!("--{B}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        let regions = decoded.multipart.expect("regions");
        let payloads: Vec<TextRegion> = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Payload)
            .cloned()
            .collect();
        assert_eq!(payloads.len(), 1, "empty payloads are skipped");
        assert_eq!(region_text(&body, &payloads)[0], "nonempty");
    }

    #[test]
    fn multipart_nested_mime_part_treated_by_its_declared_type() {
        // A part whose payload is itself a MIME structure: at MVP it is
        // handled by its DECLARED type only — no recursive parse.
        let nested = "--inner\r\nContent-Type: text/plain\r\n\r\ninner secret\r\n--inner--";
        let body = mp(&[("Content-Type: multipart/mixed", nested.as_bytes())]);
        let decoded = decode_mp(&body);
        // multipart/mixed is not in the textual list → binary → the PAYLOAD
        // is preserved, not scanned (no recursive MIME walking at MVP). The
        // part's header block still is (fix P1-1) and the skip is counted.
        let regions = decoded.multipart.expect("regions");
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].kind, RegionKind::PartHeaders);
        assert!(decoded.text.is_empty() || !decoded.text.contains("inner secret"));
        assert_eq!(decoded.binary_parts_skipped, 1);
    }

    #[test]
    fn multipart_never_panics_on_adversarial_bodies() {
        // Malformed corpus: nothing here may panic; everything must produce
        // a usable DecodedBody (Multipart or Text fallback).
        let bodies: Vec<Vec<u8>> = vec![
            vec![],
            b"--".to_vec(),
            b"----".to_vec(),
            format!("--{B}").into_bytes(),
            format!("--{B}\r\n").into_bytes(),
            format!("--{B}--").into_bytes(),
            format!("--{B}\r\n\r\n").into_bytes(),
            format!("--{B}\r\nContent-Type: \r\n\r\nempty ctype\r\n--{B}--").into_bytes(),
            format!("--{B}\r\nno blank line no headers\r\n--{B}--").into_bytes(),
            format!("--{B}\r\rContent-Type: text/plain\r\rpayload\r\r--{B}--").into_bytes(),
            format!("--{B}\n\r\n--{B}--").into_bytes(),
            format!("--{B}\r\nContent-Type: text/plain\r\n\r\npayload with no closing").into_bytes(),
        ];
        for body in bodies {
            let bytes = Bytes::from(body);
            let decoded = decode(&bytes, Some(&format!("multipart/form-data; boundary={B}")));
            // Either outcome is acceptable; the invariants are: never panic,
            // regions within bounds, and the text is consistent.
            if let Some(regions) = &decoded.multipart {
                for r in regions {
                    assert!(r.start <= r.end);
                    assert!(r.end <= bytes.len());
                }
            }
        }
    }

    #[test]
    fn multipart_secret_at_part_boundaries_is_scanned() {
        // Payload immediately after the delimiter line and ending exactly at
        // the closing delimiter (no trailing blank), including a secret that
        // "crosses" what would be stream chunks in a real request — the body
        // is buffered before decoding, so the whole secret is in one buffer.
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        body.extend_from_slice(b"BEGIN-");
        body.extend_from_slice(b"CHUNK-");
        body.extend_from_slice(b"CROSSING-SECRET-");
        body.extend_from_slice(b"VALUE-42");
        body.extend_from_slice(format!("\r\n--{B}--").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert!(decoded.text.contains("CHUNK-CROSSING-SECRET-VALUE-42"));
    }

    // ── F1 (r9-remediation): delimiter suffix validation ──

    #[test]
    fn f1_delimiter_suffix_matrix() {
        // Table-driven per the design verdict table (RFC 2046 §6.4): the
        // bytes right after a `--boundary` token decide whether the token is
        // a delimiter line. A junk suffix is payload text: the token must
        // NOT match and the scan must continue to the next legal token.
        let delim = format!("--{B}");
        let delim = delim.as_bytes();
        // Offset of the LATER legal token in the junk-suffix cases: the scan
        // skips the invalid token and keeps going (never abandons the body).
        let next = |junk_line: &str| junk_line.len();
        let open = format!("--{B}");
        let cases: Vec<(&str, String, Option<usize>)> = vec![
            // VALID open: CRLF.
            ("F1-valid: CRLF open", format!("{open}\r\nX"), Some(0)),
            // VALID open + transport padding (LWSP* then CRLF / LF).
            (
                "F1-legit: LWSP-tolerant open (CRLF)",
                format!("{open} \t \r\nX"),
                Some(0),
            ),
            ("F1-legit: LWSP-tolerant open (LF)", format!("{open}\t\nX"), Some(0)),
            // VALID close: `--` then CRLF / LWSP* then CRLF / EOF variants.
            ("F1-valid: CRLF close", format!("{open}--\r\nX"), Some(0)),
            ("F1-legit: LWSP-tolerant close", format!("{open}--  \t\r\n"), Some(0)),
            (
                // Close delimiter whose line break is missing because the
                // body ends there: kept for LF-era senders.
                "F1-valid: EOF-after-close (documented leniency beyond strict RFC 2046)",
                format!("{open}--"),
                Some(0),
            ),
            ("F1-valid: close + LWSP + EOF", format!("{open}--  "), Some(0)),
            (
                // Bare LF instead of CRLF after an open delimiter: kept so
                // LF-only bodies still parse (pre-existing leniency).
                "F1-valid: LF open (documented leniency beyond strict RFC 2046)",
                format!("{open}\nX"),
                Some(0),
            ),
            // INVALID suffixes: NOT delimiters; the scan continues (i += 1)
            // and finds the next legal token.
            (
                "F1-defect-pin: junk suffix",
                format!("{open}junk\r\n{open}\r\nX"),
                Some(next(&format!("{open}junk\r\n"))),
            ),
            (
                "F1-defect-pin: close-junk `--B--junk`",
                format!("{open}--junk\r\n{open}\r\nX"),
                Some(next(&format!("{open}--junk\r\n"))),
            ),
            (
                "F1-defect-pin: LWSP then junk",
                format!("{open} x\r\n{open}\r\n"),
                Some(next(&format!("{open} x\r\n"))),
            ),
            (
                "F1-defect-pin: single dash then CRLF",
                format!("{open}-\r\n{open}\r\n"),
                Some(next(&format!("{open}-\r\n"))),
            ),
            // INVALID, fail-safe direction: an OPEN delimiter with no line
            // break (LWSP* then EOF, or bare EOF) must not match — the
            // whole-text over-scan fallback takes over (never under-scan).
            ("F1-fail-safe: LWSP then EOF (open)", format!("{open}   "), None),
            ("F1-fail-safe: bare EOF after open", open, None),
        ];
        for (label, body, expected) in cases {
            let body = body.into_bytes();
            assert_eq!(find_delimiter(&body, delim, 0), expected, "{label}: body {body:?}");
        }
    }

    #[test]
    fn f1_junk_close_boundary_stays_in_payload_no_epilogue_misread() {
        // F1-defect-pin (parse level): a line-start `--B--junk` token is NOT
        // a delimiter. It stays inside the part payload and the body after
        // it continues to be scanned as payload — the close branch must not
        // misread it (no premature end, no bogus epilogue region).
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{B}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\n");
        body.extend_from_slice(b"before junk\r\n");
        body.extend_from_slice(format!("--{B}--junk\r\n").as_bytes());
        body.extend_from_slice(b"secret after junk\r\n");
        body.extend_from_slice(format!("--{B}--\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode_mp(&body);
        assert_eq!(decoded.content_type, ContentType::Multipart);
        let regions = decoded.multipart.expect("regions");
        let kinds: Vec<RegionKind> = regions.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            vec![RegionKind::PartHeaders, RegionKind::Payload],
            "junk close must not end the part structure (no epilogue): {kinds:?}"
        );
        let payload = regions.iter().find(|r| r.kind == RegionKind::Payload).expect("payload");
        let text = region_text(&body, std::slice::from_ref(payload))[0].clone();
        assert!(
            text.contains(&format!("--{B}--junk")),
            "junk token stays in the payload: {text:?}"
        );
        assert!(
            text.contains("secret after junk"),
            "body after the junk token is still scanned payload: {text:?}"
        );
    }
}
