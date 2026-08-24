//! `compression` — ePHPm native **response-phase** middleware that compresses
//! a buffered response body with `Accept-Encoding` negotiation (brotli, then
//! gzip), sets `Content-Encoding` / `Vary`, and lets the host recompute
//! `Content-Length`.
//!
//! Analogous to nginx `gzip`/`ngx_brotli`, Caddy's `encode`, or Traefik's
//! `compress` middleware.
//!
//! # ⚠ Overlaps ePHPm's built-in compression — read before mounting
//!
//! **ePHPm already compresses buffered responses by default.** The core server
//! runs brotli-then-gzip on buffered PHP and static responses whenever
//! `[server.response] compression` is on — and it *defaults to on*
//! (`compression = true`, `compression_min_size = 1024`) — negotiating
//! `Accept-Encoding`, setting `Content-Encoding` and `Vary`, and running
//! **before** the response phase. So on a stock server the response reaching
//! this module is *already* `Content-Encoding`-tagged.
//!
//! This module is therefore built to be **inert by default and never
//! double-encode**: it skips any response that already carries a
//! `Content-Encoding`. It only does real work when the operator has turned the
//! core compressor **off** (`[server.response] compression = false`) but still
//! wants compression on a specific mount — or on a build/config where core
//! compression is disabled. Mounting it does not conflict with core
//! compression; it simply stands down when the core already compressed.
//!
//! # Phase
//!
//! Response phase only. The request phase ([`Middleware::invoke`]) is a no-op
//! `CONTINUE`; all work happens in
//! [`ResponseMiddleware::invoke_response`]. Streamed responses never reach the
//! response phase (v1 is buffered-only), so a streamed/SSE body is untouched.
//!
//! # What it skips (besides an existing `Content-Encoding`)
//!
//! - a body smaller than `min_size`, or an empty body;
//! - a no-body / partial status (`204`, `304`, `1xx`, `206`);
//! - a `Content-Range` response (a range/partial transfer);
//! - `Cache-Control: no-transform` (RFC 9111 forbids transforming it);
//! - a `Content-Type` outside the compressible set;
//! - a request whose `Accept-Encoding` offers neither an enabled algorithm;
//! - a body that does not actually get smaller.
//!
//! Configuration (`[[middleware]] config = { ... }`), all optional:
//!
//! | key | default | meaning |
//! |-----|---------|---------|
//! | `brotli` (bool) | `true` | offer brotli (`Content-Encoding: br`), preferred when the client accepts it |
//! | `gzip` (bool) | `true` | offer gzip (`Content-Encoding: gzip`) |
//! | `level` (int 1–9) | `5` | effort: gzip level, and brotli quality (clamped to 0–11) |
//! | `min_size` (int) | `1024` | do not compress a body smaller than this many bytes |
//! | `types` (array of strings) | text/JSON/JS/XML/SVG | a `Content-Type` is compressible when it contains any of these substrings (case-insensitive) |

use std::io::Write;

use ephpm_middleware::{Middleware, Request, Response, ResponseMiddleware, ResponseView};
use flate2::Compression;
use flate2::write::GzEncoder;

/// Encoder scratch-buffer size, matching ePHPm's own buffered brotli path.
const BROTLI_BUF: usize = 4096;
/// Brotli window (log2): 4 MiB, matching ePHPm's buffered path.
const BROTLI_LGWIN: u32 = 22;

/// The default compressible `Content-Type` substrings — mirrors ePHPm's own
/// `is_compressible`.
const DEFAULT_TYPES: &[&str] = &["text/", "javascript", "json", "xml", "svg"];

/// The negotiated encoding to apply.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Brotli,
    Gzip,
}

impl Encoding {
    fn token(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Gzip => "gzip",
        }
    }
}

/// Compression policy, built once at `init`.
pub struct Compress {
    brotli: bool,
    gzip: bool,
    level: u32,
    min_size: usize,
    types: Vec<String>,
}

/// Read an optional boolean config key with a default.
fn opt_bool(config: &serde_json::Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(serde_json::Value::Bool(b)) => Ok(*b),
        Some(other) => Err(format!("`{key}` must be a boolean, got {other}")),
    }
}

/// Read an optional unsigned-integer config key with a default.
fn opt_u64(config: &serde_json::Value, key: &str, default: u64) -> Result<u64, String> {
    match config.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            v.as_u64().ok_or_else(|| format!("`{key}` must be a non-negative integer, got {v}"))
        }
    }
}

/// True when `content_type` matches any configured compressible substring.
fn is_compressible(content_type: &str, types: &[String]) -> bool {
    let ct = content_type.to_ascii_lowercase();
    types.iter().any(|t| ct.contains(t.as_str()))
}

/// True when the response status carries no body or a partial body and must not
/// be compressed.
fn status_forbids_compression(status: u16) -> bool {
    status < 200 || status == 204 || status == 304 || status == 206
}

/// Parse `Accept-Encoding` and return the q-weight the client assigned `token`
/// (or `*`), or `None` when the token is not acceptable (absent, or `q=0`).
fn accepts(accept_encoding: &str, token: &str) -> bool {
    let mut wildcard: Option<bool> = None;
    let mut explicit: Option<bool> = None;
    for part in accept_encoding.split(',') {
        let mut fields = part.split(';');
        let Some(name) = fields.next().map(str::trim) else { continue };
        // q defaults to 1.0 unless a `q=` parameter says otherwise.
        let mut acceptable = true;
        for param in fields {
            let param = param.trim();
            if let Some(q) = param.strip_prefix("q=") {
                acceptable = q.trim().parse::<f32>().is_ok_and(|v| v > 0.0);
            }
        }
        if name.eq_ignore_ascii_case(token) {
            explicit = Some(acceptable);
        } else if name == "*" {
            wildcard = Some(acceptable);
        }
    }
    explicit.or(wildcard).unwrap_or(false)
}

/// Gzip-compress `data` at `level` (1–9).
fn gzip(data: &[u8], level: u32) -> Option<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level.clamp(1, 9)));
    encoder.write_all(data).ok()?;
    encoder.finish().ok()
}

/// Brotli-compress `data` at quality derived from `level` (clamped to 0–11).
fn brotli(data: &[u8], level: u32) -> Option<Vec<u8>> {
    let quality = level.min(11);
    let mut out = Vec::new();
    {
        let mut encoder =
            brotli::CompressorWriter::new(&mut out, BROTLI_BUF, quality, BROTLI_LGWIN);
        encoder.write_all(data).ok()?;
        // CompressorWriter flushes the trailer on drop.
    }
    Some(out)
}

impl Compress {
    /// Choose the encoding to apply given the client's `Accept-Encoding`,
    /// honoring the brotli-preferred order.
    fn negotiate(&self, accept_encoding: &str) -> Option<Encoding> {
        if self.brotli && accepts(accept_encoding, "br") {
            return Some(Encoding::Brotli);
        }
        if self.gzip && accepts(accept_encoding, "gzip") {
            return Some(Encoding::Gzip);
        }
        None
    }

    /// Add `Accept-Encoding` to the response's `Vary`, preserving any existing
    /// tokens and avoiding a duplicate.
    fn apply_vary(resp: &mut ResponseView<'_>) {
        match resp.header("Vary") {
            Some(existing) => {
                let already =
                    existing.split(',').any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"));
                if already {
                    return;
                }
                if existing.trim().eq_ignore_ascii_case("*") {
                    return;
                }
                resp.set_header("Vary", format!("{}, Accept-Encoding", existing.trim()));
            }
            None => resp.set_header("Vary", "Accept-Encoding"),
        }
    }
}

impl Middleware for Compress {
    fn init(config: &serde_json::Value) -> Result<Self, String> {
        let level = opt_u64(config, "level", 5)?;
        if !(1..=9).contains(&level) {
            return Err(format!("`level` must be between 1 and 9, got {level}"));
        }
        let min_size = usize::try_from(opt_u64(config, "min_size", 1024)?)
            .map_err(|_| "`min_size` is too large".to_string())?;

        let types = match config.get("types") {
            None | Some(serde_json::Value::Null) => {
                DEFAULT_TYPES.iter().map(|s| (*s).to_owned()).collect()
            }
            Some(serde_json::Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    let s = item
                        .as_str()
                        .ok_or_else(|| format!("`types` entries must be strings, got {item}"))?;
                    if !s.is_empty() {
                        out.push(s.to_ascii_lowercase());
                    }
                }
                out
            }
            Some(other) => return Err(format!("`types` must be an array, got {other}")),
        };

        let brotli = opt_bool(config, "brotli", true)?;
        let gzip = opt_bool(config, "gzip", true)?;
        if !brotli && !gzip {
            return Err("at least one of `brotli` / `gzip` must be enabled".into());
        }

        Ok(Self { brotli, gzip, level: u32::try_from(level).unwrap_or(5), min_size, types })
    }

    fn invoke(&self, _req: &Request<'_>) -> Response {
        // All work happens in the response phase.
        Response::cont()
    }
}

impl ResponseMiddleware for Compress {
    fn invoke_response(&self, req: &Request<'_>, resp: &mut ResponseView<'_>) {
        // 1. Never double-encode: if the body already carries a
        //    Content-Encoding (e.g. ePHPm's core compressor already ran, or PHP
        //    encoded it), stand down.
        if resp.header("Content-Encoding").is_some_and(|v| !v.trim().is_empty()) {
            return;
        }
        // 2. No-body / partial statuses.
        if status_forbids_compression(resp.status()) {
            return;
        }
        // 3. Range/partial responses.
        if resp.header("Content-Range").is_some() {
            return;
        }
        // 4. Explicit no-transform.
        if resp
            .header("Cache-Control")
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-transform"))
        {
            return;
        }
        // 5. Content-Type gate.
        let content_type = resp.header("Content-Type").unwrap_or_default();
        if !is_compressible(&content_type, &self.types) {
            return;
        }
        // 6. Negotiate against Accept-Encoding.
        let accept = req.header("Accept-Encoding").unwrap_or("");
        let Some(encoding) = self.negotiate(accept) else {
            return;
        };
        // 7. Size floor.
        let body = resp.body();
        if body.len() < self.min_size {
            return;
        }

        let compressed = match encoding {
            Encoding::Brotli => brotli(body, self.level),
            Encoding::Gzip => gzip(body, self.level),
        };
        // 8. Only apply when it actually helped.
        let Some(compressed) = compressed.filter(|c| c.len() < body.len()) else {
            return;
        };

        resp.set_header("Content-Encoding", encoding.token());
        Self::apply_vary(resp);
        // The host recomputes Content-Length from the replacement body.
        resp.set_body(compressed);
    }
}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)] // tests build the FFI Request / Response views by hand.

    use std::io::Read;

    use ephpm_middleware::abi::ACTION_CONTINUE;
    use ephpm_middleware::host::{RequestCtx, ResponseCtx, host_table};

    use super::*;

    fn init(config: serde_json::Value) -> Compress {
        Compress::init(&config).expect("init")
    }

    fn hdr(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    /// Drive the response phase; return `(headers, body)` after applying edits.
    fn run(
        mw: &Compress,
        accept_encoding: &str,
        status: u16,
        resp_headers: Vec<(String, String)>,
        body: &[u8],
    ) -> (Vec<(String, String)>, Vec<u8>) {
        let req_headers: Vec<(String, String)> = if accept_encoding.is_empty() {
            vec![]
        } else {
            vec![hdr("Accept-Encoding", accept_encoding)]
        };
        let ctx = RequestCtx::new("GET", "/", "", "203.0.113.9", "example.test", &req_headers);
        // SAFETY: `ctx` outlives the view; host_table() is 'static.
        let req = unsafe { Request::from_raw(ctx.as_abi(), host_table()) };
        let mut rctx = ResponseCtx::new(status, resp_headers, body.to_vec());
        {
            // SAFETY: `rctx` outlives the view; host_table() is 'static.
            let mut view = unsafe { ResponseView::from_raw(rctx.as_ptr(), host_table()) };
            mw.invoke_response(&req, &mut view);
            let (st, b, set, remove) = view.__into_parts();
            for name in remove {
                rctx.remove_header(&name);
            }
            for (n, v) in set {
                rctx.set_header(&n, &v);
            }
            if let Some(s) = st {
                rctx.set_status(s);
            }
            if let Some(b) = b {
                rctx.replace_body(b);
            }
        }
        let (_status, headers, out_body) = rctx.into_parts();
        (headers, out_body)
    }

    fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn html_body() -> Vec<u8> {
        // Highly compressible, comfortably over the 1 KiB floor.
        "<html><body>".bytes().chain(std::iter::repeat_n(b'a', 4096)).collect()
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut d = flate2::read::GzDecoder::new(data);
        let mut out = Vec::new();
        d.read_to_end(&mut out).expect("gunzip");
        out
    }

    // ── request phase is a no-op ──────────────────────────────────────────

    #[test]
    fn request_phase_continues() {
        let mw = init(serde_json::Value::Null);
        let ctx = RequestCtx::new("GET", "/", "", "203.0.113.9", "example.test", &[]);
        // SAFETY: `ctx` outlives the view; host_table() is 'static.
        let req = unsafe { Request::from_raw(ctx.as_abi(), host_table()) };
        assert_eq!(mw.invoke(&req).__action(), ACTION_CONTINUE);
    }

    // ── happy paths ───────────────────────────────────────────────────────

    #[test]
    fn gzip_when_only_gzip_accepted() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, out) = run(&mw, "gzip", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), Some("gzip"));
        assert_eq!(get(&headers, "Vary"), Some("Accept-Encoding"));
        assert!(out.len() < body.len());
        assert_eq!(gunzip(&out), body, "gzip stream must round-trip");
    }

    #[test]
    fn brotli_preferred_over_gzip() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, out) =
            run(&mw, "gzip, br", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), Some("br"));
        assert!(out.len() < body.len());
    }

    #[test]
    fn gzip_used_when_brotli_disabled() {
        let mw = init(serde_json::json!({ "brotli": false }));
        let body = html_body();
        let (headers, _out) =
            run(&mw, "gzip, br", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), Some("gzip"));
    }

    // ── skip conditions ───────────────────────────────────────────────────

    #[test]
    fn skips_when_already_encoded() {
        // This is the core-compression-already-ran case: do NOT double-encode.
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, out) = run(
            &mw,
            "br",
            200,
            vec![hdr("Content-Type", "text/html"), hdr("Content-Encoding", "br")],
            &body,
        );
        assert_eq!(get(&headers, "Content-Encoding"), Some("br"));
        assert_eq!(out, body, "body must be left untouched");
    }

    #[test]
    fn skips_uncompressible_content_type() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, out) = run(&mw, "br", 200, vec![hdr("Content-Type", "image/png")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), None);
        assert_eq!(out, body);
    }

    #[test]
    fn skips_small_body() {
        let mw = init(serde_json::Value::Null);
        let body = b"<html>tiny</html>".to_vec();
        let (headers, out) = run(&mw, "br", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), None);
        assert_eq!(out, body);
    }

    #[test]
    fn skips_when_client_accepts_nothing() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, _out) =
            run(&mw, "identity", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), None);
    }

    #[test]
    fn skips_q0_encoding() {
        let mw = init(serde_json::json!({ "brotli": false }));
        let body = html_body();
        let (headers, _out) =
            run(&mw, "gzip;q=0", 200, vec![hdr("Content-Type", "text/html")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), None);
    }

    #[test]
    fn skips_no_transform() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, _out) = run(
            &mw,
            "br",
            200,
            vec![hdr("Content-Type", "text/html"), hdr("Cache-Control", "private, no-transform")],
            &body,
        );
        assert_eq!(get(&headers, "Content-Encoding"), None);
    }

    #[test]
    fn skips_304() {
        let mw = init(serde_json::Value::Null);
        let (headers, _out) =
            run(&mw, "br", 304, vec![hdr("Content-Type", "text/html")], &html_body());
        assert_eq!(get(&headers, "Content-Encoding"), None);
    }

    #[test]
    fn skips_content_range() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, _out) = run(
            &mw,
            "br",
            206,
            vec![hdr("Content-Type", "text/html"), hdr("Content-Range", "bytes 0-99/200")],
            &body,
        );
        assert_eq!(get(&headers, "Content-Encoding"), None);
    }

    // ── Vary preservation ─────────────────────────────────────────────────

    #[test]
    fn vary_is_appended_not_clobbered() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, _out) = run(
            &mw,
            "gzip",
            200,
            vec![hdr("Content-Type", "text/html"), hdr("Vary", "Cookie")],
            &body,
        );
        assert_eq!(get(&headers, "Vary"), Some("Cookie, Accept-Encoding"));
    }

    #[test]
    fn vary_not_duplicated() {
        let mw = init(serde_json::Value::Null);
        let body = html_body();
        let (headers, _out) = run(
            &mw,
            "gzip",
            200,
            vec![hdr("Content-Type", "text/html"), hdr("Vary", "Accept-Encoding")],
            &body,
        );
        assert_eq!(get(&headers, "Vary"), Some("Accept-Encoding"));
    }

    // ── config validation ─────────────────────────────────────────────────

    #[test]
    fn bad_config_fails_init() {
        assert!(Compress::init(&serde_json::json!({ "level": 0 })).is_err());
        assert!(Compress::init(&serde_json::json!({ "level": 10 })).is_err());
        assert!(Compress::init(&serde_json::json!({ "brotli": false, "gzip": false })).is_err());
        assert!(Compress::init(&serde_json::json!({ "types": "text/" })).is_err());
        assert!(Compress::init(&serde_json::json!({ "min_size": -1 })).is_err());
    }

    #[test]
    fn custom_types_are_honored() {
        let mw = init(serde_json::json!({ "types": ["application/octet-stream"] }));
        let body: Vec<u8> = std::iter::repeat_n(b'a', 4096).collect();
        let (headers, _out) =
            run(&mw, "gzip", 200, vec![hdr("Content-Type", "application/octet-stream")], &body);
        assert_eq!(get(&headers, "Content-Encoding"), Some("gzip"));
    }
}
