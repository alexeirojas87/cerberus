//! JSON-preserving redaction (F2 fix, review P0-2).
//!
//! The old path concatenated every string value of the body, redacted that
//! concatenation, and forwarded plain text — corrupting JSON. This module
//! walks the parsed `serde_json::Value` tree and redacts **only** matching
//! string leaves, re-serializing the original structure afterwards.
//!
//! Non-JSON bodies fall back to whole-text redaction.

use bytes::Bytes;
use cerberus_engine::constraints::ContextAnalyzer;
use cerberus_engine::engine::{CompiledEngine, Finding, ScanOutput};
use cerberus_engine::redact::{apply_redaction, RedactOptions};
use cerberus_engine::vault::{apply_redaction_reversible, Vault};

use crate::decoder::{ContentType, DecodedBody, TextRegion};

/// Redact the body preserving structure.
///
/// Returns the transformed bytes. For JSON bodies the structure is preserved
/// (only matching string leaves are replaced); for `multipart/form-data`
/// bodies (R9-13) only the recorded TEXT regions are redacted and
/// everything else — boundaries and binary part payloads — is preserved
/// byte-exact; for text bodies the whole text is redacted in place using the
/// already-produced findings.
///
/// `vault` is the **request-scoped** reversible vault (F2.2/R9-8): `Some` →
/// spans are replaced by `[VAULT:<random>]` tokens and the originals are
/// stored zeroized for the response un-redaction; `None` (the default) →
/// standard irreversible `[REDACTED:flag]` tokens.
///
/// This is the 6-argument convenience form: on a multipart body it performs
/// its own authoritative region scan (identical algorithm to the pipeline's,
/// minus the allowlist — it can only over-redact, never under-redact). The
/// PIPELINE must call [`redact_body_with_scan`] and pass the ONE
/// scan pass the decision was made from, so the decision and the redaction
/// can never disagree (fix F-1/P1-3, attempt 2).
///
/// # Errors
///
/// Returns an error if the redaction itself fails internally (fail-policy
/// decides at the caller: Open → forward original, Closed → reject).
pub fn redact_body(
    engine: &CompiledEngine,
    body: &Bytes,
    decoded: &DecodedBody,
    opts: &RedactOptions,
    findings: &[Finding],
    vault: Option<&Vault>,
) -> Result<Vec<u8>, String> {
    redact_body_with_scan(engine, body, decoded, opts, findings, vault, AuthoredScan::None)
}

/// Pipeline entry: redact the body using the AUTHORITATIVE multipart scan
/// (fix F-1/P1-3, attempt 2).
///
/// `multipart_scan` is the single per-region scan
/// pass the pipeline's decision (block/redact/criticality) was made from;
/// the redaction consumes the very same findings, so there is no surface
/// where a region re-scan can fire a rule the decision never saw — or vice
/// versa. `None` (or a scan built from different regions) falls back to the
/// identical local self-scan of [`redact_body`].
///
/// # Errors
///
/// Returns an error if the redaction itself fails internally (fail-policy
/// decides at the caller: Open → forward original, Closed → reject).
/// The ONE authoritative scan pass the pipeline's decision was made from,
/// threaded into the redaction so the two can never disagree (fix F-1/P1-3
/// attempt 2 for multipart; fix R9-21/F9.A for JSON). A body has exactly one
/// content type, so the pass is one variant or none.
#[derive(Debug, Clone, Copy)]
pub enum AuthoredScan<'a> {
    /// The per-region multipart scan.
    Multipart(&'a MultipartScan),
    /// The per-leaf JSON scan.
    Json(&'a JsonScan),
    /// No authored scan (compat fallback: the redaction self-scans,
    /// identical to the pre-R9-21 behavior).
    None,
}

/// Pipeline entry: redact the body using the ONE authoritative scan pass
/// the pipeline's decision was made from (multipart per-region or JSON
/// per-leaf — see [`AuthoredScan`]).
///
/// # Errors
///
/// Returns an error if the redaction itself fails internally (fail-policy
/// decides at the caller: Open → forward original, Closed → reject).
pub fn redact_body_with_scan(
    engine: &CompiledEngine,
    body: &Bytes,
    decoded: &DecodedBody,
    opts: &RedactOptions,
    findings: &[Finding],
    vault: Option<&Vault>,
    scan: AuthoredScan<'_>,
) -> Result<Vec<u8>, String> {
    let (multipart_scan, json_scan) = match scan {
        AuthoredScan::Multipart(s) => (Some(s), None),
        AuthoredScan::Json(s) => (None, Some(s)),
        AuthoredScan::None => (None, None),
    };
    // JSON path first; if the body is not valid JSON it falls back to the text fallback.
    if decoded.content_type == ContentType::Json {
        if let Some(redacted) =
            redact_json_with_scan(engine, body, decoded.parsed.as_ref(), opts, vault, json_scan, findings)?
        {
            return Ok(redacted);
        }
    }
    // Multipart path (R9-13): the decoder recorded the scanned TEXT regions
    // of the raw body — redact in place, no multipart re-parse.
    if decoded.content_type == ContentType::Multipart {
        if let Some(regions) = &decoded.multipart {
            return redact_multipart(engine, body, regions, multipart_scan, opts, vault);
        }
        // A hand-built `DecodedBody` without regions falls through to the
        // text fallback (whole-text redaction of the decoded text).
    }
    fallback_text(decoded, findings, opts, vault)
}

/// The ONE authoritative per-region scan of a multipart body (fix F-1/P1-3,
/// attempt 2).
///
/// Every recorded text region (payloads, part headers, preamble, epilogue)
/// is scanned IN ISOLATION with [`CompiledEngine::scan_with_context_analyzer`]
/// against ONE [`ContextAnalyzer`] built over the full lossy body — the same
/// context machinery as the JSON leaf path, so a keyword anywhere in the
/// body (another part's payload, a part header, the preamble) validates a
/// match. The union of the region findings is the pipeline's decision view;
/// the per-region findings are what the redaction splices. Both come from
/// THIS pass, so they can never disagree.
///
/// The consistent scan model (fix F-2, attempt 2): regions are the scan
/// unit. A pattern that spans two regions (e.g. a multiline rule whose match
/// bridges two parts) is visible to NEITHER the decision nor the redaction —
/// there is no joined-text view for the pipeline to disagree with. The
/// allowlist is applied per region on the region-relative raw value (the
/// operator allowlist is authoritative end to end: an allowlisted value is
/// not flagged and not redacted).
#[derive(Debug, Clone)]
pub struct MultipartScan {
    /// Regions in decode (ascending offset) order — the same vector as
    /// `DecodedBody.multipart`.
    pub regions: Vec<TextRegion>,
    /// Post-allowlist findings per region, in the same order as `regions`;
    /// offsets are relative to each region's lossy text.
    pub findings: Vec<Vec<Finding>>,
}

/// Build the authoritative multipart scan for one request.
///
/// `allowlist` is the operator allowlist as HMAC FINGERPRINTS (R9-7/F6.3):
/// a region-relative raw value is allowlisted when the fingerprint of its
/// trimmed text is in the set — the same semantics as the pipeline's
/// [`crate::proxy`] allowlist filter. `key` is the installation audit-hash
/// key (`None` = unkeyed test context: nothing is allowlisted, fail-closed).
#[must_use]
pub fn scan_multipart_regions(
    engine: &CompiledEngine,
    body: &Bytes,
    regions: &[TextRegion],
    allowlist: &[String],
    key: Option<&[u8]>,
) -> MultipartScan {
    // ONE analyzer over the full lossy body: the shared keyword context for
    // every region (keyword_anywhere semantics, cached per keyword set —
    // identical to the JSON leaf path).
    let body_text = String::from_utf8_lossy(body).into_owned();
    let analyzer = ContextAnalyzer::new(&body_text);
    let fingerprints: std::collections::HashSet<&str> = allowlist.iter().map(String::as_str).collect();
    let mut per_region: Vec<Vec<Finding>> = Vec::with_capacity(regions.len());
    // Dedup key includes the region index: offsets are region-relative, so
    // identical (flag, start, end) in two regions are two real matches.
    let mut seen: std::collections::HashSet<(String, usize, usize, usize)> = std::collections::HashSet::new();
    for (index, region) in regions.iter().enumerate() {
        let slice = String::from_utf8_lossy(&body[region.start..region.end]).into_owned();
        let found = engine.scan_with_context_analyzer(&slice, &analyzer);
        let mut kept = Vec::new();
        for f in found.findings {
            // Allowlist on the region-relative raw value (same trim
            // semantics as the pipeline's text-path filter; R9-7: the
            // comparison is fingerprint-vs-fingerprint).
            let allowlisted = f
                .end
                .le(&slice.len())
                .then(|| slice.get(f.start..f.end).map(str::trim))
                .flatten()
                .is_some_and(|raw| {
                    key.is_some_and(|k| fingerprints.contains(crate::allowlist::fingerprint(k, raw).as_str()))
                });
            if !allowlisted && seen.insert((f.flag.clone(), index, f.start, f.end)) {
                kept.push(f);
            }
        }
        per_region.push(kept);
    }
    MultipartScan {
        regions: regions.to_vec(),
        findings: per_region,
    }
}

/// The union of all region findings as the pipeline decision view.
#[must_use]
pub fn multipart_scan_output(scan: &MultipartScan) -> ScanOutput {
    let mut findings: Vec<Finding> = Vec::new();
    // F7 fix: the dedup key includes the REGION INDEX (mirroring the
    // authoritative scan at :176-178) — offsets are region-relative, so
    // identical (flag, start, end) in two regions are two real matches.
    // Within one region the dedup still holds (no double-counting).
    let mut seen: std::collections::HashSet<(String, usize, usize, usize)> = std::collections::HashSet::new();
    for (index, region) in scan.findings.iter().enumerate() {
        for f in region {
            if seen.insert((f.flag.clone(), index, f.start, f.end)) {
                findings.push(f.clone());
            }
        }
    }
    let action_overall = findings
        .iter()
        .map(|f| f.action)
        .max()
        .unwrap_or(cerberus_engine::rule::Action::Allow);
    ScanOutput {
        findings,
        action_overall,
    }
}

/// The ONE authoritative per-leaf scan of a JSON body (fix R9-21, F9.A).
///
/// Mirrors [`scan_multipart_regions`] for the JSON path: every string leaf is
/// scanned IN ISOLATION with [`CompiledEngine::scan_with_context_analyzer`]
/// against ONE [`ContextAnalyzer`] built over the full lossy body, and the
/// allowlist is applied per leaf on the leaf-relative raw value. The union of
/// the leaf findings feeds the pipeline's decision view; the per-leaf
/// findings are what the redaction splices. Both come from THIS pass, so
/// they can never disagree (the same one-scan-pass model F3.1/F3.2
/// established for multipart).
///
/// Plan reading (§4.2, documented decision): detection covers "all textual
/// content" — key names INCLUDED via the pipeline's flat-text scan; the
/// leaf scans add context-validated matches on the values. Redaction splices
/// only leaf substrings (in-place, structure-preserving); a decision finding
/// that no leaf can carry (e.g. a multiline match spanning two leaves) cannot
/// be redacted in place without corrupting the schema, so the redaction
/// fails closed instead of silently forwarding it.
#[derive(Debug, Clone)]
pub struct JsonScan {
    /// Post-allowlist findings per string leaf, in document walk order —
    /// the same order the splice phase walks the tree. Offsets are
    /// relative to each leaf's text.
    pub findings: Vec<Vec<Finding>>,
}

/// Build the authoritative JSON leaf scan for one request.
///
/// `allowlist` is the operator allowlist as HMAC FINGERPRINTS (R9-7/F6.3);
/// `key` is the installation audit-hash key (`None` = unkeyed test context:
/// nothing is allowlisted, fail-closed).
#[must_use]
pub fn scan_json_leaves(
    engine: &CompiledEngine,
    body: &Bytes,
    parsed: &serde_json::Value,
    allowlist: &[String],
    key: Option<&[u8]>,
) -> JsonScan {
    let body_text = String::from_utf8_lossy(body).into_owned();
    let analyzer = ContextAnalyzer::new(&body_text);
    let fingerprints: std::collections::HashSet<&str> = allowlist.iter().map(String::as_str).collect();
    let mut texts: Vec<String> = Vec::new();
    collect_string_leaves(parsed, &mut texts);
    let mut per_leaf: Vec<Vec<Finding>> = Vec::with_capacity(texts.len());
    // Dedup key includes the leaf index: offsets are leaf-relative, so
    // identical (flag, start, end) in two leaves are two real matches.
    let mut seen: std::collections::HashSet<(String, usize, usize, usize)> = std::collections::HashSet::new();
    for (index, leaf) in texts.iter().enumerate() {
        let found = engine.scan_with_context_analyzer(leaf, &analyzer);
        let mut kept = Vec::new();
        for f in found.findings {
            let allowlisted = f
                .end
                .le(&leaf.len())
                .then(|| leaf.get(f.start..f.end).map(str::trim))
                .flatten()
                .is_some_and(|raw| {
                    key.is_some_and(|k| fingerprints.contains(crate::allowlist::fingerprint(k, raw).as_str()))
                });
            if !allowlisted && seen.insert((f.flag.clone(), index, f.start, f.end)) {
                kept.push(f);
            }
        }
        per_leaf.push(kept);
    }
    JsonScan { findings: per_leaf }
}

/// Collect every string leaf's text in document walk order (the same order
/// both the scan and the splice phase use).
fn collect_string_leaves(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_string_leaves(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                collect_string_leaves(v, out);
            }
        }
        _ => {}
    }
}

/// The decision view for a JSON body: the flat-text scan (all textual
/// content, §4.2 — key names included) UNION the authoritative leaf scan.
///
/// Leaf-only findings are appended deduped by `(flag, hashed_value)`; their
/// spans are leaf-relative (documented artifact: flag/category/severity/
/// action/hash are exact, only the span is not body-relative). The overall
/// action is the precedence max across the union.
#[must_use]
pub fn json_decision_output(flat: ScanOutput, scan: &JsonScan) -> ScanOutput {
    let mut findings = flat.findings;
    let covered: std::collections::HashSet<(String, String)> = findings
        .iter()
        .map(|f| (f.flag.clone(), f.hashed_value.clone()))
        .collect();
    for leaf in &scan.findings {
        for f in leaf {
            if !covered.contains(&(f.flag.clone(), f.hashed_value.clone())) {
                findings.push(f.clone());
            }
        }
    }
    let action_overall = findings
        .iter()
        .map(|f| f.action)
        .max()
        .unwrap_or(cerberus_engine::rule::Action::Allow);
    ScanOutput {
        findings,
        action_overall,
    }
}

/// Redact the scanned TEXT regions of a `multipart/form-data` body (R9-13).
///
/// Each region is redacted with the findings of the AUTHORITATIVE scan pass
/// (`scan` — the SAME pass the pipeline decision was made from; fix F-1/P1-3,
/// attempt 2). When no authoritative scan is supplied (direct callers,
/// tests), an identical local self-scan is performed: same regions, same
/// analyzer model, empty allowlist — it can only over-redact, never
/// under-redact. Regions are spliced in REVERSE order so earlier offsets
/// stay valid. Boundaries and binary part payloads are never touched — they
/// are preserved byte-exact.
fn redact_multipart(
    engine: &CompiledEngine,
    body: &Bytes,
    regions: &[crate::decoder::TextRegion],
    scan: Option<&MultipartScan>,
    opts: &RedactOptions,
    vault: Option<&Vault>,
) -> Result<Vec<u8>, String> {
    // The per-region findings: the caller-supplied authoritative pass when it
    // covers exactly these regions, otherwise the identical local self-scan.
    let authoritative = scan.is_some_and(|s| s.findings.len() == regions.len());
    let owned;
    let per_region: &[Vec<Finding>] = if authoritative {
        scan.map(|s| &s.findings[..]).expect("checked above")
    } else {
        owned = scan_multipart_regions(engine, body, regions, &[], None).findings;
        &owned
    };
    let mut out = body.to_vec();
    for (index, region) in regions.iter().enumerate().rev() {
        let slice = String::from_utf8_lossy(&body[region.start..region.end]).into_owned();
        let findings = &per_region[index];
        if findings.is_empty() {
            continue;
        }
        let redacted = match vault {
            // Reversible (opt-in): unique vault token per span, the original
            // value goes into the request-scoped vault.
            Some(vault) => apply_redaction_reversible(&slice, findings, vault)
                .map(String::into_bytes)
                .map_err(|e| format!("multipart part redaction failed: {e}"))?,
            // Irreversible (default, closed decision §9 #4).
            None => apply_redaction(&slice, findings, opts)
                .map(String::into_bytes)
                .map_err(|e| format!("multipart part redaction failed: {e}"))?,
        };
        out.splice(region.start..region.end, redacted);
    }
    Ok(out)
}

/// Fallback: plain-text redaction of the decoded text.
fn fallback_text(
    decoded: &DecodedBody,
    findings: &[Finding],
    opts: &RedactOptions,
    vault: Option<&Vault>,
) -> Result<Vec<u8>, String> {
    if let Some(vault) = vault {
        return apply_redaction_reversible(&decoded.text, findings, vault)
            .map(String::into_bytes)
            .map_err(|e| format!("redaction failed: {e}"));
    }
    apply_redaction(&decoded.text, findings, opts)
        .map(String::into_bytes)
        .map_err(|e| format!("redaction failed: {e}"))
}

/// Redact every string leaf of a JSON body that triggers a finding.
/// Returns `Ok(None)` if the body isn't valid JSON (caller falls back to
/// whole-text redaction). Propagates redaction errors (review v4 #5): before
/// it swallowed the `apply_redaction` error and forwarded the raw secret.
///
/// Fix F2.1 (review 9 R9-1): `parsed` carries the `serde_json::Value` already
/// decoded by [`crate::decoder::decode`] on the scan path, so the body is
/// parsed exactly once per request. `None` (hand-built `DecodedBody`) falls
/// back to parsing here — same parser, same bytes, identical output.
fn redact_json_with_scan(
    engine: &CompiledEngine,
    body: &Bytes,
    parsed: Option<&serde_json::Value>,
    opts: &RedactOptions,
    vault: Option<&Vault>,
    json_scan: Option<&JsonScan>,
    decision_findings: &[Finding],
) -> Result<Option<Vec<u8>>, String> {
    let mut value: serde_json::Value = match parsed {
        // The decoded tree is borrowed by the caller; clone is an exact copy
        // (no re-parse, no re-validation) and is O(body) once per request.
        Some(v) => v.clone(),
        None => match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        },
    };
    // The full body as context for keyword constraints.
    let body_text = String::from_utf8_lossy(body).to_string();
    let analyzer = ContextAnalyzer::new(&body_text);
    // Fix R9-21 (fail-closed under-redaction): a decision finding with a
    // Redact action that NO leaf scan produced (e.g. a multiline match
    // spanning two leaves) cannot be redacted in place without corrupting
    // the schema. The redaction must fail (the fail-policy decides at the
    // caller) instead of silently forwarding it. Coverage is matched by
    // (flag, hashed_value): the same pattern matching the same substring in
    // a leaf and in the flat text share both.
    if let Some(scan) = json_scan {
        let covered: std::collections::HashSet<(&str, &str)> = scan
            .findings
            .iter()
            .flatten()
            .map(|f| (f.flag.as_str(), f.hashed_value.as_str()))
            .collect();
        let unspliceable = decision_findings
            .iter()
            .filter(|f| {
                f.action == cerberus_engine::rule::Action::Redact
                    && !covered.contains(&(f.flag.as_str(), f.hashed_value.as_str()))
            })
            .count();
        if unspliceable > 0 {
            return Err(format!(
                "json redaction cannot be applied in-place for {unspliceable} structural finding(s)                  (no leaf carries them); fail-closed"
            ));
        }
    }
    splice_json_value(engine, &mut value, opts, &analyzer, vault, json_scan, &mut 0)?;
    serde_json::to_vec(&value)
        .map(Some)
        .map_err(|e| format!("json reserialize failed: {e}"))
}

/// Splice phase: walk the tree in the SAME order `collect_string_leaves`
/// walked it, consuming the pre-collected per-leaf findings (no scan of our
/// own — fix R9-21: decision and redaction share ONE scan pass). With
/// `json_scan: None` (compat fallback) the leaf is scanned here, identical
/// to the pre-R9-21 behavior.
fn splice_json_value(
    engine: &CompiledEngine,
    value: &mut serde_json::Value,
    opts: &RedactOptions,
    analyzer: &ContextAnalyzer<'_>,
    vault: Option<&Vault>,
    scan: Option<&JsonScan>,
    leaf_index: &mut usize,
) -> Result<(), String> {
    match value {
        serde_json::Value::String(s) => {
            let leaf_findings = scan.map_or_else(
                // Compat path (hand-built DecodedBody / no scan passed):
                // scan here exactly like the pre-R9-21 redact_value did.
                || engine.scan_with_context_analyzer(s, analyzer).findings,
                |scan| {
                    let idx = *leaf_index;
                    *leaf_index += 1;
                    scan.findings.get(idx).cloned().unwrap_or_default()
                },
            );
            if !leaf_findings.is_empty() {
                let redacted = match vault {
                    // Reversible (opt-in): unique vault token per span, the
                    // original value goes into the request-scoped vault.
                    Some(vault) => apply_redaction_reversible(s, &leaf_findings, vault)
                        .map_err(|e| format!("leaf redaction failed: {e}"))?,
                    // Irreversible (default, closed decision §9 #4).
                    None => {
                        apply_redaction(s, &leaf_findings, opts).map_err(|e| format!("leaf redaction failed: {e}"))?
                    }
                };
                *s = redacted;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                splice_json_value(engine, item, opts, analyzer, vault, scan, leaf_index)?;
            }
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                splice_json_value(engine, v, opts, analyzer, vault, scan, leaf_index)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::decode;
    use cerberus_engine::engine::EngineBuilder;
    use cerberus_engine::loader::load_rules_from_str;
    use cerberus_engine::rule::Rule;

    const RULES: &str = r#"[
        {"flag":"secret.oauth_bearer","category":"secrets","severity":"high","action":"redact",
         "contextKeywords":[],"minLength":8,"maxLength":256,
         "patterns":["\\bBearer\\s+[A-Za-z0-9._~+/-]+=*\\b"]},
        {"flag":"secret.google_api_key","category":"secrets","severity":"high","action":"redact",
         "contextKeywords":["google","api_key"],"minLength":30,"maxLength":100,
         "patterns":["AIza[A-Za-z0-9_-]{35}"]}
    ]"#;

    fn engine() -> CompiledEngine {
        let rules: Vec<Rule> = load_rules_from_str(RULES).expect("rules");
        EngineBuilder::new(&rules).build().expect("engine")
    }

    #[test]
    fn json_structure_preserved_after_redaction() {
        let engine = engine();
        let raw = r#"{"messages":[{"role":"user","content":"Authorization: Bearer abcdefghijklmnopqrstuvwxyzA123456 fin"}],"model":"gpt-4","temperature":0.0,"n":1}"#;
        let body = Bytes::from(raw);
        let decoded = decode(&body, Some("application/json"));
        let findings: Vec<Finding> = Vec::new(); // unused in JSON path
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &findings, None).expect("redact");
        let text = String::from_utf8(out).expect("utf8");
        // JSON removed? it must still be valid JSON with the structure.
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON after redaction");
        assert_eq!(parsed["model"], "gpt-4");
        assert_eq!(parsed["temperature"], 0.0);
        assert_eq!(parsed["n"], 1);
        let content = parsed["messages"][0]["content"].as_str().unwrap();
        assert!(content.contains("[REDACTED"));
        assert!(!content.contains("Bearer abcdefghijklmnopqrstuvwxyzA123456"));
    }

    #[test]
    fn redaction_reaches_nested_string_leaves() {
        let engine = engine();
        let payload =
            r#"{"data":{"items":[{"tag":"secret","note":"auth: Bearer xyzwvutsrqponmlkjihgfedcbaA987654"}]}}"#;
        let body = Bytes::from(payload);
        let decoded = decode(&body, Some("application/json"));
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let parsed: serde_json::Value = serde_json::from_slice(&out[..]).expect("valid JSON");
        let inner = parsed["data"]["items"][0]["note"].as_str().unwrap();
        assert!(inner.contains("[REDACTED"));
        assert!(!inner.contains("xyzwvutsrqponmlkjihgfedcbaA987654"));
    }

    #[test]
    fn context_keyword_in_other_field_redacts() {
        // Review 2 regression (P0): the context keyword lives in ANOTHER field
        // of the JSON. A leaf scan without context would not see it, allowing
        // leaks; scan_with_context must redact it.
        let key = format!("AIza{}", "A".repeat(35));
        let payload = format!(r#"{{"context":"google api_key","secret":"{key}"}}"#);
        let body = Bytes::from(payload);
        let decoded = decode(&body, Some("application/json"));
        let out = redact_body(&engine(), &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let text = String::from_utf8(out).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let redacted = parsed["secret"].as_str().expect("secret field");
        assert!(
            !redacted.contains(key.as_str()),
            "secret must not reach upstream raw; got {redacted:?}"
        );
        assert!(redacted.contains("[REDACTED"), "got {redacted:?}");
        assert_eq!(parsed["context"], "google api_key");
    }

    #[test]
    fn redaction_failure_propagates_not_swallowed() {
        // Review v4 #5: a `block` rule on a leaf makes `apply_redaction`
        // return Err. Before it was swallowed (`if let Ok`) and the raw
        // secret was forwarded; now `redact_body` must propagate the error
        // so the fail_policy can decide (Closed → 502 / Open → forward
        // original).
        let rules: Vec<Rule> = load_rules_from_str(
            r#"[{"flag":"secret.block","category":"secrets","severity":"critical","action":"block",
                "contextKeywords":[],"minLength":8,"maxLength":256,
                "patterns":["\\bBlockMe[A-Za-z0-9]{20,}\\b"]}]"#,
        )
        .expect("rules");
        let engine = EngineBuilder::new(&rules).build().expect("engine");
        let raw = r#"{"prompt":"BlockMeSuperSecretDoNotLeak1234567890 fin"}"#;
        let body = Bytes::from(raw);
        let decoded = decode(&body, Some("application/json"));
        let err = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None)
            .expect_err("redaction must fail (block finding) and NOT return the raw JSON");
        assert!(
            err.contains("redaction") || err.contains("Blocked"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn text_fallback_propagates_invalid_span_error() {
        // Review v4 #5, invalid span (end > len): `apply_redaction` fails and
        // the error must reach the caller, not return the raw text.
        let engine = engine();
        let body = Bytes::from("hello");
        let decoded = decode(&body, Some("text/plain"));
        let bad_finding = Finding {
            flag: "broken.span".to_string(),
            category: cerberus_engine::rule::Category::Secrets,
            severity: cerberus_engine::rule::Severity::High,
            action: cerberus_engine::rule::Action::Redact,
            start: 0,
            end: 100,
            hashed_value: "unused".to_string(),
        };
        let err = redact_body(
            &engine,
            &body,
            &decoded,
            &RedactOptions::default(),
            &[bad_finding],
            None,
        )
        .err();
        assert!(err.is_some(), "invalid span must propagate as Err");
    }

    #[test]
    fn single_parse_reuse_and_fallback_outputs_are_byte_identical() {
        // F2.1 (R9-1): the pipeline parses the body once (decode stores the
        // parsed tree) and redact_json reuses it. The fallback path (a
        // hand-built DecodedBody carrying no parsed tree) must produce the
        // BYTE-IDENTICAL redaction output.
        let engine = engine();
        let key = format!("AIza{}", "B".repeat(35));
        let raw = format!(
            r#"{{"context":"google api_key here","secret":"{key}","note":"Bearer abcdefghijklmnopqrstuvwxyz012345"}}"#
        );
        let body = Bytes::from(raw);

        // Pipeline path: decode() parses once, redact reuses the tree.
        let decoded = decode(&body, Some("application/json"));
        assert!(decoded.parsed.is_some(), "JSON decode must retain the parsed tree");
        let reused = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("reuse path");

        // Fallback path: same body, no pre-parsed tree.
        let manual = crate::decoder::DecodedBody {
            text: decoded.text,
            content_type: crate::decoder::ContentType::Json,
            parsed: None,
            multipart: None,
            binary_parts_skipped: 0,
        };
        let fallback =
            redact_body(&engine, &body, &manual, &RedactOptions::default(), &[], None).expect("fallback path");

        assert_eq!(reused, fallback, "reuse and fallback redaction must be byte-identical");

        let parsed: serde_json::Value = serde_json::from_slice(&reused).expect("valid output JSON");
        assert!(parsed["secret"].as_str().unwrap().contains("[REDACTED"));
        assert!(!String::from_utf8_lossy(&reused).contains(key.as_str()));
    }

    #[test]
    fn text_body_decoded_without_parsed_tree_falls_back_to_text_redaction() {
        // The `parsed` field is None exactly when the body is not JSON; the
        // text fallback must keep working for such bodies (it redacts the
        // caller-provided findings, as the proxy pipeline supplies them).
        let engine = engine();
        let body = Bytes::from("plain note with Bearer abcdefghijklmnopqrstuvwxyz012345 inside");
        let decoded = decode(&body, Some("text/plain"));
        assert!(decoded.parsed.is_none());
        let scanned = engine.scan(&decoded.text);
        assert!(!scanned.findings.is_empty(), "bearer token must be found by the scan");
        let out = redact_body(
            &engine,
            &body,
            &decoded,
            &RedactOptions::default(),
            &scanned.findings,
            None,
        )
        .expect("text redaction");
        let text = String::from_utf8(out).expect("utf8");
        assert!(text.contains("[REDACTED"), "got {text:?}");
        assert!(!text.contains("abcdefghijklmnopqrstuvwxyz012345"));
    }

    // ── R9-13: multipart redaction (§4.2 MVP) ──

    const MP_BOUNDARY: &str = "XxCERBERUSTESTxX";

    fn mp_body(text_part: &str, binary_part: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"prompt\"\r\nContent-Type: text/plain\r\n\r\n");
        body.extend_from_slice(text_part.as_bytes());
        body.extend_from_slice(format!("\r\n--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"audio.wav\"\r\nContent-Type: audio/wav\r\n\r\n",
        );
        body.extend_from_slice(binary_part);
        body.extend_from_slice(format!("\r\n--{MP_BOUNDARY}--\r\n").as_bytes());
        body
    }

    #[test]
    fn multipart_text_part_redacted_binary_part_byte_exact() {
        // The secret in the TEXT part is redacted; the binary part, the
        // boundaries and every part header survive byte-exact (F3.1).
        let engine = engine();
        let secret = "Bearer abcdefghijklmnopqrstuvwxyzA123456";
        let binary: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let body = Bytes::from(mp_body(&format!("authorization: {secret}"), &binary));
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        assert_eq!(decoded.content_type, crate::decoder::ContentType::Multipart);
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("abcdefghijklmnopqrstuvwxyzA123456"),
            "secret must not reach upstream raw"
        );
        assert!(text.contains("[REDACTED"), "got {text:?}");
        // Structure preserved: boundary count and both part headers intact.
        assert_eq!(text.matches(&format!("--{MP_BOUNDARY}")).count(), 3);
        assert!(text.contains("name=\"prompt\""));
        assert!(text.contains("filename=\"audio.wav\""));
        // The binary payload is byte-exact.
        let bin_pos = out
            .windows(b"audio/wav".len())
            .position(|w| w == b"audio/wav")
            .expect("audio header present");
        let bin_start = bin_pos + b"audio/wav\r\n\r\n".len();
        assert_eq!(
            &out[bin_start..bin_start + 512],
            &binary[..],
            "binary part must be byte-exact"
        );
    }

    #[test]
    fn multipart_context_keyword_in_other_part_redacts() {
        // REDACTION-LAYER mechanics (attempt 2): the keyword lives in a
        // DIFFERENT part than the secret, and the secret is still redacted.
        // The ACCEPTANCE for cross-part context in the DECISION path is
        // `multipart_context_keyword_in_other_part_redacts_via_pipeline` in
        // tests/smoke_harness.rs (attempt-1 review P1-3: the old acceptance
        // test lived here, at the wrong layer).
        let engine = engine();
        let key = format!("AIza{}", "D".repeat(35));
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"context\"\r\n\r\ngoogle api_key here\r\n");
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"secret\"\r\n\r\n");
        body.extend_from_slice(key.as_bytes());
        body.extend_from_slice(format!("\r\n--{MP_BOUNDARY}--\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains(&key), "cross-part context must redact the secret");
        assert!(text.contains("google api_key here"), "the other part stays intact");
    }

    #[test]
    fn multipart_authoritative_scan_is_the_single_consistent_model() {
        // FIX F-1/P1-3 (attempt 2): `scan_multipart_regions` is the ONE pass
        // that feeds both the decision (multipart_scan_output) and the
        // redaction (redact_body_with_scan). The allowlist applied
        // in that pass is authoritative end to end: an allowlisted value is
        // neither flagged nor redacted; a non-allowlisted one is both.
        let engine = engine();
        let key = format!("AIza{}", "E".repeat(35));
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"context\"\r\n\r\ngoogle api_key here\r\n");
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"secret\"\r\n\r\n");
        body.extend_from_slice(key.as_bytes());
        body.extend_from_slice(format!("\r\n--{MP_BOUNDARY}--\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let regions = decoded.multipart.as_ref().expect("regions");

        // Without the allowlist: the decision view carries the finding and
        // the redaction redacts it.
        let scan = scan_multipart_regions(&engine, &body, regions, &[], None);
        let view = multipart_scan_output(&scan);
        assert_eq!(view.findings.len(), 1, "one cross-part-context finding");
        assert_eq!(view.action_overall, cerberus_engine::rule::Action::Redact);
        let out = redact_body_with_scan(
            &engine,
            &body,
            &decoded,
            &RedactOptions::default(),
            &[],
            None,
            AuthoredScan::Multipart(&scan),
        )
        .expect("redact");
        assert!(!String::from_utf8_lossy(&out).contains(&key));

        // With the value allowlisted: the SAME pass drops it from the
        // decision view and the redaction leaves it alone — no disagreement
        // between what the policy saw and what redaction did. (R9-7: the
        // allowlist carries the HMAC FINGERPRINT of the value, not the raw.)
        let fp_key = b"test-installation-key-0123456789ab";
        let fp = crate::allowlist::fingerprint(fp_key, &key);
        let scan_allow = scan_multipart_regions(&engine, &body, regions, std::slice::from_ref(&fp), Some(fp_key));
        let view_allow = multipart_scan_output(&scan_allow);
        assert!(view_allow.findings.is_empty(), "allowlisted value must not be flagged");
        let out_allow = redact_body_with_scan(
            &engine,
            &body,
            &decoded,
            &RedactOptions::default(),
            &[],
            None,
            AuthoredScan::Multipart(&scan_allow),
        )
        .expect("redact");
        assert!(
            String::from_utf8_lossy(&out_allow).contains(&key),
            "allowlisted value is forwarded (operator decision, visible in the audit flags)"
        );
    }

    #[test]
    fn multipart_part_header_secret_is_scanned_and_redacted_in_place() {
        // FIX P1-1 (attempt 2): a secret in a part HEADER is text — the
        // authoritative scan detects it and the redaction redacts it in
        // place without breaking the header line or the structure.
        let engine = engine();
        let key = format!("AIza{}", "F".repeat(35));
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"f\"\r\n");
        body.extend_from_slice(b"X-Note: google api_key\r\n");
        body.extend_from_slice(format!("X-Api-Key: {key}\r\n\r\n").as_bytes());
        body.extend_from_slice(b"clean payload\r\n");
        body.extend_from_slice(format!("--{MP_BOUNDARY}--\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains(&key), "header secret must not survive: {text}");
        assert!(
            text.contains("x-api-key: [REDACTED") || text.contains("X-Api-Key: [REDACTED"),
            "{text}"
        );
        assert!(text.contains("clean payload"), "payload untouched");
        assert_eq!(text.matches(&format!("--{MP_BOUNDARY}")).count(), 2, "structure intact");
        // The output still re-parses as multipart with the same region count.
        let re = decode(
            &Bytes::from(out),
            Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")),
        );
        assert_eq!(
            re.multipart.as_ref().map(Vec::len),
            decoded.multipart.as_ref().map(Vec::len)
        );
    }

    #[test]
    fn multipart_preamble_and_epilogue_secrets_are_redacted() {
        // FIX P1-1 (attempt 2): preamble/epilogue secrets are redacted in
        // place; boundaries stay intact and the body re-parses.
        let engine = engine();
        let key = format!("AIza{}", "G".repeat(35));
        let mut body = Vec::new();
        body.extend_from_slice(format!("preamble google api_key {key}\r\n").as_bytes());
        body.extend_from_slice(format!("--{MP_BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Type: text/plain\r\n\r\nclean\r\n");
        body.extend_from_slice(format!("--{MP_BOUNDARY}--\r\n").as_bytes());
        body.extend_from_slice(format!("epilogue google api_key {key}\r\n").as_bytes());
        let body = Bytes::from(body);
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let out = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None).expect("redact");
        let text = String::from_utf8_lossy(&out);
        assert_eq!(
            text.matches(&key).count(),
            0,
            "preamble+epilogue secrets redacted: {text}"
        );
        assert!(text.contains(&format!("--{MP_BOUNDARY}\r\n")));
        assert!(text.contains(&format!("--{MP_BOUNDARY}--")));
        assert!(text.contains("clean"));
        let re = decode(
            &Bytes::from(out),
            Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")),
        );
        assert_eq!(re.content_type, crate::decoder::ContentType::Multipart);
    }

    #[test]
    fn multipart_redaction_failure_propagates() {
        // A block-action finding inside a text part makes apply_redaction
        // fail; the error must reach the caller (fail-policy decides).
        let rules: Vec<Rule> = load_rules_from_str(
            r#"[{"flag":"secret.block","category":"secrets","severity":"critical","action":"block",
                "contextKeywords":[],"minLength":8,"maxLength":256,
                "patterns":["\\bBlockMe[A-Za-z0-9]{20,}\\b"]}]"#,
        )
        .expect("rules");
        let engine = EngineBuilder::new(&rules).build().expect("engine");
        let body = Bytes::from(mp_body("BlockMeSuperSecretDoNotLeak1234567890", &[0u8, 1, 2]));
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let err = redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], None)
            .expect_err("block finding in a text part must fail redaction");
        assert!(err.contains("multipart"), "unexpected error: {err}");
    }

    #[test]
    fn multipart_reversible_vault_round_trip() {
        // F2.2 interop: with the opt-in vault the text part carries vault
        // tokens that un-redact back to the originals; binaries stay exact.
        let engine = engine();
        let secret = "Bearer abcdefghijklmnopqrstuvwxyzA123456";
        let binary: Vec<u8> = vec![7u8; 64];
        let body = Bytes::from(mp_body(&format!("authorization: {secret}"), &binary));
        let decoded = decode(&body, Some(&format!("multipart/form-data; boundary={MP_BOUNDARY}")));
        let vault = cerberus_engine::vault::Vault::new();
        let out =
            redact_body(&engine, &body, &decoded, &RedactOptions::default(), &[], Some(&vault)).expect("vault redact");
        let text = String::from_utf8_lossy(&out);
        assert!(
            !text.contains("abcdefghijklmnopqrstuvwxyzA123456"),
            "raw secret must not be forwarded"
        );
        assert!(text.contains("[VAULT:"), "got {text:?}");
        let restored = vault.unredact(&out);
        let restored_text = String::from_utf8_lossy(&restored);
        assert!(
            restored_text.contains("abcdefghijklmnopqrstuvwxyzA123456"),
            "vault must restore the original"
        );
        // And the binary payload is byte-exact after the round trip.
        let bin_pos = restored
            .windows(b"audio/wav".len())
            .position(|w| w == b"audio/wav")
            .unwrap();
        let bin_start = bin_pos + b"audio/wav\r\n\r\n".len();
        assert_eq!(&restored[bin_start..bin_start + 64], &binary[..]);
    }

    // ── F7 (r9-remediation): the output-view dedup key carries the region ──

    fn f7_finding(flag: &str, start: usize, end: usize) -> Finding {
        Finding {
            flag: flag.to_string(),
            category: cerberus_engine::rule::Category::Secrets,
            severity: cerberus_engine::rule::Severity::High,
            action: cerberus_engine::rule::Action::Redact,
            start,
            end,
            hashed_value: "sha256:test".to_string(),
        }
    }

    fn f7_region(start: usize, end: usize) -> TextRegion {
        TextRegion {
            start,
            end,
            kind: crate::decoder::RegionKind::Payload,
        }
    }

    #[test]
    fn f7_output_view_keeps_identical_offsets_from_two_regions() {
        // F7-collision: offsets are REGION-RELATIVE, so identical
        // (flag, start, end) in two different regions are two real matches
        // and BOTH must appear in the audit/feedback view. The old 3-tuple
        // key silently dropped the second region's finding (audit gap).
        let scan = MultipartScan {
            regions: vec![f7_region(0, 10), f7_region(20, 30)],
            findings: vec![vec![f7_finding("f", 0, 5)], vec![f7_finding("f", 0, 5)]],
        };
        let out = multipart_scan_output(&scan);
        assert_eq!(
            out.findings.len(),
            2,
            "identical (flag,start,end) in two regions must BOTH be reported"
        );
    }

    #[test]
    fn f7_output_view_still_dedups_within_one_region() {
        // F7-no-doublecount: one region per key — a repeated identical
        // finding inside ONE region is still deduplicated (count unchanged),
        // while the same offsets in ANOTHER region are kept.
        let scan = MultipartScan {
            regions: vec![f7_region(0, 10), f7_region(20, 30)],
            findings: vec![
                vec![f7_finding("f", 0, 5), f7_finding("f", 0, 5)],
                vec![f7_finding("f", 0, 5)],
            ],
        };
        let out = multipart_scan_output(&scan);
        assert_eq!(out.findings.len(), 2, "1 from region 0 + 1 from region 1");
        assert_eq!(out.action_overall, cerberus_engine::rule::Action::Redact);
    }
}
