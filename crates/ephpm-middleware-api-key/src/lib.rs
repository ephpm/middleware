//! # Example: api-key (request-phase auth gate) middleware
//!
//! A self-contained, loadable ePHPm native-middleware module, kept as a
//! reference you can copy to write your own. The official build of this
//! module is compiled into ePHPm itself; nothing here needs to be fetched or
//! installed separately. See the repository README for the ABI, the
//! `declare!` macro, and the request- vs response-phase model.
//!

//! `api-key` — ePHPm native middleware validating an API key on the request
//! before PHP runs, then forwarding the resolved **consumer identity** to PHP.
//!
//! Analogous to Kong's `key-auth`, AWS API Gateway API keys / usage plans, and
//! Tyk: a request carrying a recognised key is admitted and tagged with the
//! consumer it belongs to; a request with a missing or unrecognised key is
//! short-circuited with `401` and PHP never runs.
//!
//! The key is read from a configurable request header (default `X-Api-Key`)
//! and, only when explicitly enabled, from a query parameter (default off —
//! see the security note). It is validated against either a static
//! `key → consumer-id` map baked into the config, a KV lookup (`kv_get_global`
//! on a `kv_key_template` like `apikey:<key>` whose value is the consumer id),
//! or both (the static map is consulted first). On success the module `REWRITE`s
//! the request, injecting the consumer id in a header (default
//! `X-Consumer-Id`) that PHP reads — the exact mechanism `jwt` uses to forward
//! claims. The injected header **overwrites** any same-named header the client
//! sent (the host's `override_header` replaces, not appends), so a client
//! cannot spoof its consumer identity.
//!
//! ## Security
//!
//! * **Constant-time comparison.** Static keys are compared with a
//!   constant-time equality check (`subtle::ConstantTimeEq`) so the match does
//!   not leak how many leading bytes were correct — closing the timing oracle
//!   that a naive `==` would open. All configured keys are compared on every
//!   request (no early return on the first match). Only the *lengths* of keys
//!   can differ in timing, which is not a practical attack surface. The KV
//!   path is an exact-key store lookup and does not compare secrets in Rust.
//! * **The key value is never logged.** This module emits no logs containing
//!   the presented key.
//! * **Query parameter is off by default.** Query strings routinely end up in
//!   access logs, proxy logs, browser history and `Referer` headers, so a key
//!   in the URL leaks far more readily than one in a header. Enable
//!   `query_param` only when a client genuinely cannot set a header.
//! * **Composes with `ratelimit`.** Point the `ratelimit` module's
//!   `key_headers` at the same header (e.g. `["X-Api-Key"]`) to get per-key
//!   rate limiting in front of, or alongside, this auth gate.
//!
//! ## The credential map lives in the PROCESS-GLOBAL store (ABI minor 3)
//!
//! Since ePHPm [#376](https://github.com/ephpm/ephpm/issues/376) the host
//! table's plain `kv_get` resolves **the serving vhost's** keyspace — the same
//! physically separate store that tenant's PHP writes through `ephpm_kv_set()`.
//! For a per-tenant counter that is exactly what you want. For a **credential
//! map it is a privilege escalation**: on a multi-tenant node any tenant's PHP
//! could write `apikey:<anything>` into its own store and mint itself a
//! consumer identity that this gate would then honour.
//!
//! So the lookup here uses [`Host::kv_get_global`], the process-wide store,
//! which no tenant's PHP can reach. That is also the pre-minor-3 behaviour, so
//! nothing changes for an existing deployment — it just stays correct once the
//! host starts scoping `kv_*` per vhost. Seed it out of band (the RESP listener
//! or a control-plane process), not from a tenant's application code.
//!
//! Mounted on a host older than ABI minor 3 the global slot does not exist, the
//! safe wrapper returns `None`, and the KV path therefore denies every request
//! (the static `keys` map still works). Failing closed is the right direction
//! for an auth gate, and the pinned `rev` in `Cargo.toml` makes it moot in
//! practice.
//!
//! ## Per-tenant key maps: `<site>` and failing closed
//!
//! One mount serves every vhost, so a multi-tenant deployment usually wants one
//! key map per tenant. Put the optional `<site>` placeholder in
//! `kv_key_template` (`apikey:<site>:<key>`) and it is substituted with the
//! request's **canonical site key** — [`Request::vhost_id`], the identity the
//! router resolved, never the `Host` header a client sent
//! ([#390](https://github.com/ephpm/ephpm/issues/390)).
//!
//! `vhost_id()` is `None` for a request that matched no virtual host, and this
//! module then **denies** rather than substituting anything: an auth gate that
//! guessed a site there would be keying policy on arbitrary client input. That
//! is the fail-closed half of the pattern — a rate limiter, which only has to
//! bucket, would instead use `ephpm_middleware::UNMATCHED_VHOST`.
//!
//! Configuration (`[[middleware]] config = { ... }`):
//!
//! | key | default | meaning |
//! |-----|---------|---------|
//! | `header` (string) | `"X-Api-Key"` | request header carrying the key |
//! | `query_param` (string) | unset (disabled) | also accept the key from this query parameter — see the security note |
//! | `keys` (object) | unset | static `key → consumer-id` map |
//! | `kv_key_template` (string) | unset | global-store lookup key with a required `<key>` placeholder and an optional `<site>` one, e.g. `apikey:<key>` or `apikey:<site>:<key>`; the value is the consumer id |
//! | `consumer_header` (string) | `"X-Consumer-Id"` | header injected for PHP with the resolved consumer id |
//!
//! At least one of `keys` / `kv_key_template` must be configured.
//!
//! [`Host::kv_get_global`]: ephpm_middleware::Host::kv_get_global

use ephpm_middleware::{Middleware, Request, Response};
use subtle::ConstantTimeEq;

/// The literal replaced with the presented key in `kv_key_template`.
const KEY_PLACEHOLDER: &str = "<key>";

/// The optional literal replaced with the request's canonical site key in
/// `kv_key_template`. Its presence is what makes a key map per-tenant — and
/// what makes a request with no tenant identity fail closed.
const SITE_PLACEHOLDER: &str = "<site>";

/// API-key validation policy, built once at `init`.
pub struct ApiKey {
    header: String,
    query_param: Option<String>,
    consumer_header: String,
    /// Static `key → consumer-id` entries. Keys are stored as bytes for the
    /// constant-time comparison.
    keys: Vec<(Vec<u8>, String)>,
    /// KV lookup template containing [`KEY_PLACEHOLDER`], e.g. `apikey:<key>`,
    /// and optionally [`SITE_PLACEHOLDER`], e.g. `apikey:<site>:<key>`.
    kv_key_template: Option<String>,
}

/// Outcome of the KV credential lookup.
///
/// The third variant exists so `invoke` can tell "this key is not in the store"
/// apart from "this request has no tenant, so a per-tenant key map cannot even
/// be addressed". Both deny — but only one of them is a statement about the
/// presented credential, and collapsing them would hide the fail-closed branch
/// this example exists to demonstrate.
enum KvLookup {
    /// The key resolved to this consumer id.
    Consumer(String),
    /// No KV template configured, or the key is absent from the store.
    Miss,
    /// The template is site-scoped (`<site>`) and [`Request::vhost_id`] is
    /// `None` — the request matched no virtual host, so there is no tenant
    /// whose key map could be consulted (ephpm#390).
    NoTenant,
}

/// Constant-time byte-slice equality. Wraps [`subtle::ConstantTimeEq`] so the
/// comparison does not short-circuit on the first differing byte (unequal
/// lengths still return `false` fast, leaking only length). This is the helper
/// the static-key match uses; it is unit-tested directly.
#[must_use]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// URL-decode a query-string component (`+` → space, `%XX` → byte). Invalid
/// escapes are passed through literally rather than failing the lookup.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Return the (decoded) value of query parameter `name` in `query`, if present.
fn query_value(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == name).then(|| percent_decode(v))
    })
}

impl ApiKey {
    /// Extract the presented key: the configured header first, then the query
    /// parameter when enabled. Empty values count as absent.
    fn extract_key(&self, req: &Request<'_>) -> Option<String> {
        if let Some(v) = req.header(&self.header) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_owned());
            }
        }
        if let Some(param) = &self.query_param
            && let Some(v) = query_value(req.query(), param)
            && !v.is_empty()
        {
            return Some(v);
        }
        None
    }

    /// Constant-time match of `presented` against the static key map. Every
    /// entry is compared (no early return) so the number of matching leading
    /// bytes is not observable via timing.
    fn match_static(&self, presented: &[u8]) -> Option<&str> {
        let mut matched: Option<&str> = None;
        for (key, consumer) in &self.keys {
            if ct_eq(presented, key) {
                matched = Some(consumer.as_str());
            }
        }
        matched
    }

    /// Look the presented key up in the KV store via `kv_key_template`. The
    /// stored value (UTF-8, non-empty) is the consumer id.
    ///
    /// Two deliberate choices, both explained at length in the module docs:
    ///
    /// * the lookup uses `kv_get_global`, so the credential map lives in the
    ///   process-wide store where no tenant's PHP can write it;
    /// * a `<site>`-scoped template resolves the site component from
    ///   `req.vhost_id()` — the canonical site key — and **fails closed** when
    ///   there is no tenant, instead of falling back to the `Host` header.
    fn match_kv(&self, req: &Request<'_>, presented: &str) -> KvLookup {
        let Some(template) = self.kv_key_template.as_ref() else {
            return KvLookup::Miss;
        };
        let lookup = if template.contains(SITE_PLACEHOLDER) {
            // Fail closed: no tenant identity, no per-tenant key map. Never
            // substitute `req.http_host()` here — that is client input, and
            // accepting it would let a caller pick which tenant's key map its
            // credential is checked against.
            let Some(site) = req.vhost_id() else {
                return KvLookup::NoTenant;
            };
            // Site first, key second, and the order is load-bearing: the
            // presented key is client input, so substituting it first would let
            // a caller inject a literal `<site>` that the next `replace` then
            // expanded. This way anything the client sends stays inert.
            template.replace(SITE_PLACEHOLDER, site).replace(KEY_PLACEHOLDER, presented)
        } else {
            template.replace(KEY_PLACEHOLDER, presented)
        };
        let Some(value) = req.host().kv_get_global(&lookup) else {
            return KvLookup::Miss;
        };
        match String::from_utf8(value) {
            Ok(consumer) if !consumer.is_empty() => KvLookup::Consumer(consumer),
            _ => KvLookup::Miss,
        }
    }

    /// Admit the request, injecting the consumer id for PHP (mirrors how `jwt`
    /// forwards its claims via a request header).
    fn grant(&self, consumer: &str) -> Response {
        Response::rewrite().header(self.consumer_header.as_str(), consumer)
    }

    /// `401` with a `WWW-Authenticate`-style hint naming the expected header.
    /// The key value is deliberately absent from the body.
    fn unauthorized(&self, body: &'static str) -> Response {
        Response::respond(401, body)
            .header("WWW-Authenticate", format!("ApiKey header=\"{}\"", self.header))
    }
}

impl Middleware for ApiKey {
    fn init(config: &serde_json::Value) -> Result<Self, String> {
        let opt_str = |key: &str| -> Result<Option<String>, String> {
            match config.get(key) {
                Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
                None | Some(serde_json::Value::Null | serde_json::Value::String(_)) => Ok(None),
                Some(other) => Err(format!("`{key}` must be a string, got {other}")),
            }
        };

        let header = opt_str("header")?.unwrap_or_else(|| "X-Api-Key".to_owned());
        let query_param = opt_str("query_param")?;
        let consumer_header =
            opt_str("consumer_header")?.unwrap_or_else(|| "X-Consumer-Id".to_owned());

        let keys = match config.get("keys") {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(v) => {
                let map = v.as_object().ok_or("`keys` must be an object of key -> consumer-id")?;
                map.iter()
                    .map(|(key, consumer)| {
                        if key.is_empty() {
                            return Err("`keys` entries must have a non-empty key".to_owned());
                        }
                        let consumer = consumer.as_str().ok_or_else(|| {
                            format!("`keys[\"{key}\"]` must be a string consumer-id")
                        })?;
                        Ok((key.as_bytes().to_vec(), consumer.to_owned()))
                    })
                    .collect::<Result<Vec<_>, String>>()?
            }
        };

        let kv_key_template = opt_str("kv_key_template")?;
        if let Some(template) = &kv_key_template
            && !template.contains(KEY_PLACEHOLDER)
        {
            return Err(format!(
                "`kv_key_template` must contain the `{KEY_PLACEHOLDER}` placeholder"
            ));
        }

        if keys.is_empty() && kv_key_template.is_none() {
            return Err("at least one of `keys` or `kv_key_template` must be configured".into());
        }

        Ok(Self { header, query_param, consumer_header, keys, kv_key_template })
    }

    fn invoke(&self, req: &Request<'_>) -> Response {
        let Some(key) = self.extract_key(req) else {
            return self.unauthorized("missing api key");
        };
        if let Some(consumer) = self.match_static(key.as_bytes()) {
            return self.grant(consumer);
        }
        match self.match_kv(req, &key) {
            KvLookup::Consumer(consumer) => self.grant(&consumer),
            KvLookup::NoTenant => self.unauthorized("unknown host"),
            KvLookup::Miss => self.unauthorized("invalid api key"),
        }
    }
}

// ── C ABI export ────────────────────────────────────────────────────────────
// `declare!` generates the `extern "C"` entry points ePHPm's module loader
// calls (init / invoke / free) and bakes in the ABI-major compatibility check,
// so a module built against the wrong host ABI refuses to load instead of
// corrupting memory. This is the ONLY line that turns the plain `Middleware`
// impl above into a loadable `.so`/`.dylib`/`.dll`.
ephpm_middleware::declare!(ApiKey);

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)] // tests build the FFI Request view by hand.

    use ephpm_middleware::abi::{ACTION_RESPOND, ACTION_REWRITE};
    use ephpm_middleware::host::{RequestCtx, host_table, set_kv_store};

    use super::*;

    fn api_key(config: serde_json::Value) -> ApiKey {
        ApiKey::init(&config).expect("init")
    }

    /// Invoke against a fresh ctx bound to `site` — the fifth `RequestCtx`
    /// argument is the request's **canonical site key** since ABI minor 3, and
    /// the empty string is how the host says "this request matched no virtual
    /// host" (the C accessor turns it into a NULL, so `vhost_id()` is `None`).
    fn invoke_on(mw: &ApiKey, site: &str, query: &str, headers: &[(String, String)]) -> Response {
        let ctx = RequestCtx::new("GET", "/api/x", query, "203.0.113.9", site, headers);
        // SAFETY: `ctx` outlives the view; host_table() is 'static.
        let req = unsafe { Request::from_raw(ctx.as_abi(), host_table()) };
        mw.invoke(&req)
    }

    /// Invoke with headers and an optional query string against a fresh ctx.
    fn invoke_q(mw: &ApiKey, query: &str, headers: &[(String, String)]) -> Response {
        invoke_on(mw, "example", query, headers)
    }

    fn invoke(mw: &ApiKey, headers: &[(String, String)]) -> Response {
        invoke_q(mw, "", headers)
    }

    fn hdr(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_owned(), value.to_owned())]
    }

    /// Wire a real in-memory Store into the host table (first call wins; all
    /// tests in this binary share it) and seed one `apikey:*` entry via the
    /// host's own `kv_set_global`.
    ///
    /// **Every test must seed key names no other test uses.** The store is
    /// process-wide and the tests run in parallel; `Store::set_local` removes
    /// the old entry before inserting the new one, so two tests writing the
    /// *same* key leave a window in which a third read sees a miss. Isolating
    /// the key names removes the interference rather than papering over it.
    fn setup_kv_with(entries: &[(&str, &str)]) {
        set_kv_store(&ephpm_kv::store::Store::new(ephpm_kv::store::StoreConfig::default()));
        let ctx = RequestCtx::new("GET", "/", "", "127.0.0.1", "seed", &[]);
        // SAFETY: `ctx` outlives the view; host_table() is 'static.
        let req = unsafe { Request::from_raw(ctx.as_abi(), host_table()) };
        for (k, v) in entries {
            // `kv_set_global` on purpose: this seeds the PROCESS-GLOBAL store,
            // which is the one `match_kv` reads. (In-process there is no site
            // scope active here either way, but naming the slot keeps the test
            // honest about which store the module depends on.)
            assert!(
                req.host().kv_set_global(k, v.as_bytes(), 0),
                "seed kv_set_global failed for {k}",
            );
        }
    }

    fn consumer_header(resp: &Response) -> Option<String> {
        resp.__headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("X-Consumer-Id"))
            .map(|(_, v)| v.clone())
    }

    fn assert_401(resp: &Response, body: &str) {
        assert_eq!(resp.__action(), ACTION_RESPOND);
        assert_eq!(resp.__status(), 401);
        assert_eq!(resp.__body(), body.as_bytes());
        // Never leak the key; always hint via WWW-Authenticate.
        assert!(
            resp.__headers().iter().any(|(n, _)| n.eq_ignore_ascii_case("WWW-Authenticate")),
            "401 must carry a WWW-Authenticate hint",
        );
    }

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"correct-key", b"correct-key"));
        assert!(!ct_eq(b"correct-key", b"correct-keZ"));
        assert!(!ct_eq(b"correct-key", b"correct-ke")); // length mismatch
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"a", b""));
    }

    #[test]
    fn init_requires_a_store() {
        // No keys and no KV template → misconfiguration.
        assert!(ApiKey::init(&serde_json::json!({})).is_err());
        assert!(ApiKey::init(&serde_json::json!({ "header": "X-Api-Key" })).is_err());
        // `keys` must be an object; entries must be string consumer-ids.
        assert!(ApiKey::init(&serde_json::json!({ "keys": "nope" })).is_err());
        assert!(ApiKey::init(&serde_json::json!({ "keys": { "k": 42 } })).is_err());
        // `kv_key_template` must contain the placeholder.
        assert!(ApiKey::init(&serde_json::json!({ "kv_key_template": "apikey:" })).is_err());
        // Valid minimal configs.
        assert!(ApiKey::init(&serde_json::json!({ "keys": { "k": "c" } })).is_ok());
        assert!(ApiKey::init(&serde_json::json!({ "kv_key_template": "apikey:<key>" })).is_ok());
    }

    #[test]
    fn valid_static_key_rewrites_with_consumer() {
        let mw = api_key(serde_json::json!({ "keys": { "secret-abc": "consumer-7" } }));
        let resp = invoke(&mw, &hdr("X-Api-Key", "secret-abc"));
        assert_eq!(resp.__action(), ACTION_REWRITE);
        assert_eq!(consumer_header(&resp).as_deref(), Some("consumer-7"));
    }

    #[test]
    fn invalid_static_key_is_401() {
        let mw = api_key(serde_json::json!({ "keys": { "secret-abc": "consumer-7" } }));
        assert_401(&invoke(&mw, &hdr("X-Api-Key", "wrong")), "invalid api key");
    }

    #[test]
    fn missing_key_is_401() {
        let mw = api_key(serde_json::json!({ "keys": { "secret-abc": "consumer-7" } }));
        assert_401(&invoke(&mw, &[]), "missing api key");
        // Present-but-empty header also counts as missing.
        assert_401(&invoke(&mw, &hdr("X-Api-Key", "   ")), "missing api key");
    }

    #[test]
    fn custom_header_and_consumer_header() {
        let mw = api_key(serde_json::json!({
            "header": "X-Key",
            "consumer_header": "X-Who",
            "keys": { "k1": "alice" },
        }));
        let resp = invoke(&mw, &hdr("X-Key", "k1"));
        assert_eq!(resp.__action(), ACTION_REWRITE);
        let who = resp
            .__headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("X-Who"))
            .map(|(_, v)| v.as_str());
        assert_eq!(who, Some("alice"));
    }

    #[test]
    fn query_param_disabled_by_default() {
        let mw = api_key(serde_json::json!({ "keys": { "qk": "qc" } }));
        // Key only in the query string, but query_param is off → 401 missing.
        assert_401(&invoke_q(&mw, "api_key=qk", &[]), "missing api key");
    }

    #[test]
    fn query_param_when_enabled() {
        let mw = api_key(serde_json::json!({
            "query_param": "api_key",
            "keys": { "qk": "qc" },
        }));
        let resp = invoke_q(&mw, "foo=1&api_key=qk&bar=2", &[]);
        assert_eq!(resp.__action(), ACTION_REWRITE);
        assert_eq!(consumer_header(&resp).as_deref(), Some("qc"));
        // Header still takes precedence over the query param.
        let resp = invoke_q(&mw, "api_key=wrong", &hdr("X-Api-Key", "qk"));
        assert_eq!(resp.__action(), ACTION_REWRITE);
        assert_eq!(consumer_header(&resp).as_deref(), Some("qc"));
        // URL-encoded value round-trips.
        let mw2 = api_key(serde_json::json!({
            "query_param": "api_key",
            "keys": { "a b": "spaced" },
        }));
        let resp = invoke_q(&mw2, "api_key=a%20b", &[]);
        assert_eq!(consumer_header(&resp).as_deref(), Some("spaced"));
    }

    #[test]
    fn kv_backed_valid_and_invalid() {
        setup_kv_with(&[("apikey:live-key", "kv-consumer-1")]);
        let mw = api_key(serde_json::json!({ "kv_key_template": "apikey:<key>" }));
        // Valid: value in the store is the consumer id.
        let resp = invoke(&mw, &hdr("X-Api-Key", "live-key"));
        assert_eq!(resp.__action(), ACTION_REWRITE);
        assert_eq!(consumer_header(&resp).as_deref(), Some("kv-consumer-1"));
        // Absent key → 401 invalid.
        assert_401(&invoke(&mw, &hdr("X-Api-Key", "no-such-key")), "invalid api key");
    }

    #[test]
    fn static_map_takes_precedence_then_kv() {
        setup_kv_with(&[("apikey:kv-only", "from-kv")]);
        let mw = api_key(serde_json::json!({
            "keys": { "static-only": "from-static" },
            "kv_key_template": "apikey:<key>",
        }));
        // Static hit.
        assert_eq!(
            consumer_header(&invoke(&mw, &hdr("X-Api-Key", "static-only"))).as_deref(),
            Some("from-static"),
        );
        // Falls through to KV.
        assert_eq!(
            consumer_header(&invoke(&mw, &hdr("X-Api-Key", "kv-only"))).as_deref(),
            Some("from-kv"),
        );
    }

    /// ePHPm #390 / #376. A `<site>`-scoped template gives each tenant its own
    /// key map, keyed by the CANONICAL site key — so the same presented key is
    /// a different credential on a different vhost, and neither tenant can
    /// spend the other's.
    #[test]
    fn a_site_scoped_template_keys_the_map_per_tenant() {
        setup_kv_with(&[
            ("apikey:blog:shared-secret", "blog-consumer"),
            ("apikey:shop:shared-secret", "shop-consumer"),
            ("apikey:blog:blog-only", "blog-consumer"),
        ]);
        let mw = api_key(serde_json::json!({ "kv_key_template": "apikey:<site>:<key>" }));

        let key = hdr("X-Api-Key", "shared-secret");
        assert_eq!(
            consumer_header(&invoke_on(&mw, "blog", "", &key)).as_deref(),
            Some("blog-consumer"),
        );
        assert_eq!(
            consumer_header(&invoke_on(&mw, "shop", "", &key)).as_deref(),
            Some("shop-consumer"),
        );

        // A key that only exists in `blog`'s map is not a credential on `shop`.
        let blog_only = hdr("X-Api-Key", "blog-only");
        assert_eq!(
            consumer_header(&invoke_on(&mw, "blog", "", &blog_only)).as_deref(),
            Some("blog-consumer"),
        );
        assert_401(&invoke_on(&mw, "shop", "", &blog_only), "invalid api key");
    }

    /// The fail-closed half of ePHPm #390: a request that matched no virtual
    /// host has no tenant identity (`vhost_id()` is `None`), and a site-scoped
    /// gate must deny rather than invent one from the `Host` header.
    #[test]
    fn a_site_scoped_template_fails_closed_on_an_unmatched_host() {
        setup_kv_with(&[
            ("apikey:blog:closed-secret", "blog-consumer"),
            ("apikey::closed-secret", "nope"),
        ]);
        let mw = api_key(serde_json::json!({ "kv_key_template": "apikey:<site>:<key>" }));

        // Sanity: the credential itself is good on the vhost that owns it.
        assert_eq!(
            consumer_header(&invoke_on(&mw, "blog", "", &hdr("X-Api-Key", "closed-secret")))
                .as_deref(),
            Some("blog-consumer"),
        );
        // Empty site key == no vhost matched == `vhost_id() == None`. Denied,
        // and denied as "unknown host" — the gate never reached the store.
        // Note `apikey::closed-secret` IS seeded: an empty site component is
        // not a bucket this can fall into, it is a refusal to look at all.
        assert_401(&invoke_on(&mw, "", "", &hdr("X-Api-Key", "closed-secret")), "unknown host");
    }

    /// A template with no `<site>` stays node-wide, and is unaffected by which
    /// vhost is serving — the pre-minor-3 shape, kept working.
    #[test]
    fn a_template_without_site_is_node_wide() {
        setup_kv_with(&[("apikey:node-wide-key", "node-wide-consumer")]);
        let mw = api_key(serde_json::json!({ "kv_key_template": "apikey:<key>" }));
        for site in ["blog", "shop", ""] {
            assert_eq!(
                consumer_header(&invoke_on(&mw, site, "", &hdr("X-Api-Key", "node-wide-key")))
                    .as_deref(),
                Some("node-wide-consumer"),
                "site {site:?} should reach the node-wide key map",
            );
        }
    }
}
