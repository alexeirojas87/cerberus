//! Control-plane Host/Origin allowlist — DNS-rebinding defense (R9-5 / F6.1).
//!
//! A malicious web page (DNS rebinding / CSRF against `http://127.0.0.1:8787`)
//! can drive the browser to the local control plane with a *rebound* Host
//! (`attacker.com` resolving to 127.0.0.1) or an *evil* Origin. The defense
//! (fix-plan F6.1) is an EXACT allowlist — no wildcards — enforced on every
//! `/api/*` request BEFORE authentication:
//!
//! - **Host** must be loopback-named when the proxy binds loopback, or the
//!   exact configured listen host; extra hostnames come from the config
//!   (`allowed_hosts`), never wildcards.
//! - **Origin** (browsers always send it on cross-origin requests) must be
//!   same-origin with an allowed Host or explicitly allowlisted; `Origin:
//!   null` (sandboxed iframe) is always rejected.
//! - **Browser mutations** (requests carrying an Origin) must not use the
//!   form-submittable "simple" content types (`text/plain`,
//!   `application/x-www-form-urlencoded`, `multipart/form-data`); the
//!   JSON-body routes additionally enforce JSON parsing, so the effective
//!   browser shape is `application/json`. `multipart/form-data` is rejected
//!   for control-plane mutations (the pack-install byte upload sends
//!   `application/octet-stream`-style types and remains usable).
//! - CLI/curl without Origin keep working with a valid token (the Origin
//!   and content-type gates only apply to browser-shaped requests).
//!
//! Default policy (A.1, config-driven `allowed_hosts`): loopback bind →
//! `localhost` / `127.0.0.1` / `[::1]` (with or without the real port);
//! non-loopback bind → **fail-closed**: only the exact configured entries
//! pass, so a public bind must name its hostnames explicitly.

use std::collections::HashSet;

use crate::config::ProxyConfig;

/// Form-submittable "simple" content types (what a cross-site `<form>` can
/// send without a CORS preflight). These are exactly the shapes a CSRF /
/// DNS-rebinding attack can produce from a web page, so a browser-shaped
/// mutation carrying one of them is rejected (403) before any handler runs.
const SIMPLE_FORM_CONTENT_TYPES: [&str; 3] = ["text/plain", "application/x-www-form-urlencoded", "multipart/form-data"];

/// The resolved Host/Origin policy for one boot.
///
/// Built once from the listen address + config (fail-closed defaults) and
/// held in [`cerberus_proxy::api::ApiContext`]; the API gate consults it for
/// every `/api/*` request. Product wiring (daemon → `spawn_proxy`) always
/// installs a policy; `None` in the context is only reachable from direct
/// handler tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostOriginPolicy {
    allowed_hosts: HashSet<String>,
    allowed_origins: HashSet<String>,
}

impl HostOriginPolicy {
    /// Build the policy for a boot (fix-plan F6.1: exact allowlist, no
    /// wildcards; loopback names + real port on a loopback bind in Mode B;
    /// explicitly configured hostnames on a public bind in Mode A).
    ///
    /// Wildcard (`*`) or whitespace entries in `allowed_hosts`/`allowed_origins`
    /// make the build FAIL — a silently-never-matching entry would be a
    /// fail-open config lie.
    ///
    /// # Errors
    ///
    /// Returns an error listing the rejected entries when the configuration
    /// contains wildcards or blank entries.
    pub fn build(listen: &std::net::SocketAddr, cfg: &ProxyConfig) -> Result<Self, String> {
        let mut allowed_hosts: HashSet<String> = HashSet::new();
        let mut allowed_origins: HashSet<String> = HashSet::new();

        let host = listen.ip();
        let port = listen.port();
        let loopback = host.is_loopback();

        // Wildcard check FIRST: fail-closed on wildcard/blank entries. Host
        // entries are bare hostnames (no scheme, no path); Origin entries
        // are full origins (`scheme://host[:port]`).
        for entry in &cfg.allowed_hosts {
            let e = entry.trim();
            if e.is_empty() || e.contains('*') || e.contains('/') || e.contains("://") {
                return Err(format!(
                    "invalid allowed_hosts entry {entry:?}: entries are exact hostnames — \
                     no wildcards, no paths, no scheme (fail-closed)"
                ));
            }
        }
        for entry in &cfg.allowed_origins {
            let e = entry.trim();
            if e.is_empty() || e.contains('*') {
                return Err(format!(
                    "invalid allowed_origins entry {entry:?}: entries are exact origins — \
                     no wildcards, no blanks (fail-closed)"
                ));
            }
        }

        if loopback {
            // Mode B default: loopback names, with and without the real port.
            // A port-0 (ephemeral) bind is covered by the port-stripped
            // fallback in `host_allowed` (bare name entries).
            for name in ["localhost", "127.0.0.1", "::1"] {
                allowed_hosts.insert(name.to_string());
                allowed_hosts.insert(format!("{name}:{port}"));
                allowed_origins.insert(format!("http://{name}:{port}"));
            }
            // Literal IPv6 Host form.
            allowed_hosts.insert(format!("[::1]:{port}"));
            allowed_origins.insert(format!("http://[::1]:{port}"));
        } else {
            // Mode A / public bind: FAIL-CLOSED — nothing is trusted by
            // default, not even the literal listen host ("hostnames públicos
            // configurados explícitamente"): the operator names the hostnames
            // the control plane may be reached as, via `allowed_hosts`.
        }

        for h in &cfg.allowed_hosts {
            let e = h.trim().to_ascii_lowercase();
            allowed_hosts.insert(e.clone());
            allowed_origins.insert(format!("http://{e}"));
            allowed_origins.insert(format!("https://{e}"));
        }
        for o in &cfg.allowed_origins {
            allowed_origins.insert(o.trim().to_ascii_lowercase());
        }

        Ok(Self {
            allowed_hosts,
            allowed_origins,
        })
    }

    /// Is the `Host` header authority allowed? Normalizes case, strips
    /// brackets and port; the comparison is hostname-exact (no wildcard).
    #[must_use]
    pub fn host_allowed(&self, host_header: &str) -> bool {
        let authority = normalize_authority(host_header);
        if authority.is_empty() {
            return false;
        }
        if self.allowed_hosts.contains(&authority) {
            return true;
        }
        // Port-stripped form (an entry without a port accepts any port on
        // that hostname — the hostname IS the allowlist unit; "loopback +
        // puerto real" defaults already carry both shapes).
        let bare = authority.rsplit_once(':').map_or(authority.as_str(), |(h, _)| {
            if h.ends_with(']') || !h.contains(':') {
                h
            } else {
                authority.as_str()
            }
        });
        self.allowed_hosts.contains(bare)
    }

    /// Is the `Origin` header allowed? Empty means "no Origin" (CLI/curl) →
    /// allowed (the token gate still applies). `null` origin (sandboxed
    /// iframe, file://) → rejected. Everything else must match the
    /// same-origin authority or the explicit allowlist.
    #[must_use]
    pub fn origin_allowed(&self, origin_header: &str, host_header: &str) -> bool {
        let origin = origin_header.trim();
        if origin.is_empty() {
            return true; // non-browser client (curl/CLI); token still required
        }
        if origin.eq_ignore_ascii_case("null") {
            return false; // sandboxed iframe / opaque origin — never trusted
        }
        // Same-origin: the origin's authority equals the request Host.
        let origin_authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
        let origin_norm = normalize_authority(origin_authority);
        let host_norm = normalize_authority(host_header);
        if !origin_norm.is_empty() && origin_norm == host_norm {
            return true;
        }
        self.allowed_origins.contains(&origin.to_ascii_lowercase())
    }

    /// Browser-shaped mutations must not use form-submittable content types.
    /// Called only when an Origin header is present (browser context).
    #[must_use]
    pub fn mutation_content_type_allowed(content_type: Option<&str>) -> bool {
        content_type.is_none_or(|ct| {
            let ct_lower = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            !SIMPLE_FORM_CONTENT_TYPES.contains(&ct_lower.as_str())
        })
    }
}

/// Normalize a Host/authority value: lowercase, strip IPv6 brackets and the
/// port suffix. Returns the bare hostname.
fn normalize_authority(authority: &str) -> String {
    let a = authority.trim();
    if a.is_empty() {
        return String::new();
    }
    let bare = a.strip_prefix('[').map_or_else(
        || {
            // A port suffix only exists when there is EXACTLY one colon
            // (`host:port`); an unbracketed bare IPv6 has several colons and
            // no port and must stay whole.
            if a.matches(':').count() == 1 {
                match a.rsplit_once(':') {
                    Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => h.to_string(),
                    _ => a.to_string(),
                }
            } else {
                a.to_string()
            }
        },
        // IPv6 literal: keep up to the closing bracket (drop :port).
        |rest| match rest.split_once(']') {
            Some((host, _)) => host.to_string(),
            None => rest.to_string(),
        },
    );
    bare.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn cfg(listen: &str, hosts: &[&str], origins: &[&str]) -> (SocketAddr, ProxyConfig) {
        let addr: SocketAddr = listen.to_string().parse().expect("listen");
        let c = ProxyConfig {
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            allowed_origins: origins.iter().map(ToString::to_string).collect(),
            ..ProxyConfig::default()
        };
        (addr, c)
    }

    #[test]
    fn loopback_default_allows_loopback_names_and_rejects_rebinding() {
        let addr: SocketAddr = SocketAddr::from((Ipv4Addr::LOCALHOST, 8787));
        let policy = HostOriginPolicy::build(&addr, &ProxyConfig::default()).expect("policy");

        assert!(policy.host_allowed("127.0.0.1:8787"));
        assert!(policy.host_allowed("localhost:8787"));
        assert!(policy.host_allowed("localhost"), "bare loopback name");
        assert!(policy.host_allowed("[::1]:8787"));
        assert!(policy.host_allowed("LOCALHOST:8787"), "case-insensitive");

        // The DNS-rebinding shapes (the R9-5 attack): attacker-controlled
        // Host names — rejected.
        assert!(!policy.host_allowed("attacker.com"));
        assert!(!policy.host_allowed("attacker.com:8787"));
        assert!(!policy.host_allowed("evil.rebindattacker.net:8787"));
        assert!(!policy.host_allowed(""));
    }

    #[test]
    fn non_loopback_bind_defaults_fail_closed() {
        let addr: SocketAddr = SocketAddr::from(([192, 168, 1, 10], 8787));
        let policy = HostOriginPolicy::build(&addr, &ProxyConfig::default()).expect("policy");

        // Even the listen host itself is NOT trusted by default on a public
        // bind: the operator must name the hostnames explicitly (Mode A).
        assert!(!policy.host_allowed("192.168.1.10:8787"));
        assert!(!policy.host_allowed("localhost:8787"));
        assert!(!policy.host_allowed("127.0.0.1:8787"));
    }

    #[test]
    fn configured_hosts_open_the_public_bind_exactly() {
        let (addr, c) = cfg("0.0.0.0:8787", &["cerberus.corp.example"], &[]);
        let policy = HostOriginPolicy::build(&addr, &c).expect("policy");
        assert!(policy.host_allowed("cerberus.corp.example"));
        assert!(
            policy.host_allowed("CERBERUS.CORP.EXAMPLE:8787"),
            "hostname match, any port form"
        );
        assert!(!policy.host_allowed("attacker.com"));
        assert!(!policy.host_allowed("sub.corp.example"), "no wildcards, exact only");
        assert!(!policy.host_allowed("localhost:8787"));
    }

    #[test]
    fn wildcard_and_blank_entries_fail_the_build() {
        let (addr, c) = cfg("127.0.0.1:8787", &["*.corp.example"], &[]);
        assert!(
            HostOriginPolicy::build(&addr, &c).is_err(),
            "wildcards rejected (fail-closed)"
        );
        let (addr, c) = cfg("127.0.0.1:8787", &["  "], &[]);
        assert!(HostOriginPolicy::build(&addr, &c).is_err(), "blank entries rejected");
    }

    #[test]
    fn origin_gate_matrix() {
        let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 8787));
        let policy = HostOriginPolicy::build(&addr, &ProxyConfig::default()).expect("policy");

        // No Origin → CLI/curl → allowed (token still enforced by the auth gate).
        assert!(policy.origin_allowed("", "127.0.0.1:8787"));
        // Same-origin.
        assert!(policy.origin_allowed("http://127.0.0.1:8787", "127.0.0.1:8787"));
        assert!(policy.origin_allowed("http://localhost:8787", "localhost:8787"));
        // The evil shapes.
        assert!(!policy.origin_allowed("http://attacker.com", "127.0.0.1:8787"));
        assert!(!policy.origin_allowed("http://evil.example:8787", "127.0.0.1:8787"));
        assert!(
            !policy.origin_allowed("null", "127.0.0.1:8787"),
            "sandboxed iframe origin"
        );
        // Scheme mismatch on the same host is still the same authority —
        // the Origin header's host is what matters for rebinding; scheme is
        // preserved in the exact allowlist below.
        assert!(policy.origin_allowed("https://127.0.0.1:8787", "127.0.0.1:8787"));
    }

    #[test]
    fn configured_origins_are_exact() {
        let (addr, c) = cfg(
            "0.0.0.0:8787",
            &["cerberus.corp.example"],
            &["https://ops.corp.example"],
        );
        let policy = HostOriginPolicy::build(&addr, &c).expect("policy");
        assert!(policy.origin_allowed("https://ops.corp.example", "cerberus.corp.example"));
        assert!(policy.origin_allowed("http://cerberus.corp.example", "cerberus.corp.example"));
        assert!(!policy.origin_allowed("https://evil.corp.example", "cerberus.corp.example"));
    }

    #[test]
    fn simple_form_content_types_are_rejected_for_browser_mutations() {
        assert!(!HostOriginPolicy::mutation_content_type_allowed(Some("text/plain")));
        assert!(!HostOriginPolicy::mutation_content_type_allowed(Some(
            "application/x-www-form-urlencoded"
        )));
        assert!(!HostOriginPolicy::mutation_content_type_allowed(Some(
            "multipart/form-data"
        )));
        assert!(!HostOriginPolicy::mutation_content_type_allowed(Some(
            "text/plain; charset=utf-8"
        )));
        assert!(HostOriginPolicy::mutation_content_type_allowed(Some(
            "application/json"
        )));
        assert!(HostOriginPolicy::mutation_content_type_allowed(Some(
            "application/json; charset=utf-8"
        )));
        assert!(
            HostOriginPolicy::mutation_content_type_allowed(None),
            "no content-type → not form-shaped"
        );
        assert!(HostOriginPolicy::mutation_content_type_allowed(Some(
            "application/octet-stream"
        )));
    }

    #[test]
    fn normalize_authority_matrix() {
        assert_eq!(normalize_authority("127.0.0.1:8787"), "127.0.0.1");
        assert_eq!(normalize_authority("LOCALHOST"), "localhost");
        assert_eq!(normalize_authority("[::1]:8787"), "::1");
        assert_eq!(normalize_authority("::1"), "::1");
        assert_eq!(normalize_authority(""), "");
        assert_eq!(normalize_authority("attacker.com:80"), "attacker.com");
    }
}
