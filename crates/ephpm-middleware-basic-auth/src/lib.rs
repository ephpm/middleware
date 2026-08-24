//! # Example: basic-auth (the simplest whole-site auth gate) middleware
//!
//! A self-contained, loadable ePHPm native-middleware module, kept as a
//! reference you can copy to write your own. See the repository README for the
//! ABI, the `declare!` macro, and the request- vs response-phase model.
//!
//! `basic-auth` — ePHPm native middleware gating a whole site behind HTTP Basic
//! authentication ([RFC 7617](https://www.rfc-editor.org/rfc/rfc7617)) before
//! the request is served. It is the simplest possible auth gate: a request with
//! a recognised `Authorization: Basic` credential is admitted; anything else is
//! short-circuited with `401` and a `WWW-Authenticate` challenge, so the
//! browser shows its built-in login dialog and PHP never runs.
//!
//! The motivating deployment is per-PR preview hosting: a preview of a private
//! repo must not be publicly readable, and an unauthorised request must never
//! reach the interpreter. Because the whole site is gated (not one route), this
//! belongs in the middleware chain.
//!
//! ## It gates static assets too (ePHPm [#408](https://github.com/ephpm/ephpm/pull/408) / [#395](https://github.com/ephpm/ephpm/issues/395))
//!
//! The request phase runs on the **static-file path** as well as the PHP path,
//! and fails closed — the chain is evaluated *before* the file on disk is
//! opened. This module gates on the `Authorization` header alone and is blind
//! to whether the target would have been a PHP script or a static byte, so an
//! unauthenticated request for `/assets/app.js` (or any file under the document
//! root) gets the same `401` and **the bytes are never served**. That is the
//! whole point of #395: before #408 a gate protected only PHP-dispatched
//! requests and leaked static assets. `a_static_asset_is_challenged_before_it_is_read`
//! pins it.
//!
//! ## Security notes (read before copying)
//!
//! * **Constant-time comparison.** The presented `user:pass` credential is
//!   compared with a constant-time equality check ([`subtle::ConstantTimeEq`]),
//!   against **every** configured credential (no early return), so neither the
//!   match position nor *which usernames exist* leaks via timing. Only the
//!   *length* of a credential can differ in timing, which is not a practical
//!   attack surface.
//! * **Credentials are never logged.** This module emits no logs at all.
//! * **This example stores passwords in plaintext in the config** for clarity.
//!   A production gate should store a slow password hash (PBKDF2/bcrypt/argon2)
//!   and verify against it — the shape is identical, only the comparison in
//!   `authenticate` changes. Basic also sends base64 (not encryption), so serve
//!   it over HTTPS only.
//! * **Compose with `ratelimit`.** Mount the `ratelimit` module at a lower
//!   `order` so a brute-force client is turned away with `429` before it
//!   reaches this gate.
//!
//! Configuration (`[[middleware]] config = { ... }`):
//!
//! | key | default | meaning |
//! |-----|---------|---------|
//! | `users` (object) | **required** | `username -> password` table (at least one entry) |
//! | `realm` (string) | `"Restricted"` | the `WWW-Authenticate` realm shown in the browser dialog (no `"`, `\`, or control characters) |
//! | `forward_user_header` (string) | unset | on success, `REWRITE` the request with this header set to the authenticated username, for PHP to read (our SAPI does not populate `PHP_AUTH_USER`) |

use base64ct::{Base64, Encoding};
use ephpm_middleware::{Middleware, Request, Response};
use subtle::ConstantTimeEq;

/// One configured credential: the username (for forwarding) and the full
/// `username:password` byte string the presented credential is compared to.
struct Cred {
    username: String,
    /// `format!("{username}:{password}")` as bytes — exactly what a decoded
    /// `Authorization: Basic` credential contains.
    userpass: Vec<u8>,
}

/// HTTP Basic gate policy, built once at `init`.
pub struct BasicAuth {
    creds: Vec<Cred>,
    realm: String,
    forward_user_header: Option<String>,
}

/// Constant-time byte-slice equality. Wraps [`subtle::ConstantTimeEq`] so the
/// comparison does not short-circuit on the first differing byte (unequal
/// lengths still return `false` fast, leaking only length).
#[must_use]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

impl BasicAuth {
    /// The decoded `user:pass` credential from an `Authorization: Basic …`
    /// header, or `None` when the header is absent, not the Basic scheme, or
    /// not valid base64.
    fn presented(req: &Request<'_>) -> Option<Vec<u8>> {
        let value = req.header("Authorization")?;
        // RFC 7235: the scheme token is case-insensitive; exactly one space
        // separates it from the credentials.
        let rest = value.strip_prefix("Basic ").or_else(|| {
            let (scheme, rest) = value.split_once(' ')?;
            scheme.eq_ignore_ascii_case("basic").then_some(rest)
        })?;
        // Browsers send standard-alphabet, padded base64.
        Base64::decode_vec(rest.trim()).ok()
    }

    /// Constant-time match of the presented credential against every configured
    /// one (no early return). Returns the matched username, or `None`.
    fn authenticate(&self, presented: &[u8]) -> Option<&str> {
        let mut matched: Option<&str> = None;
        for cred in &self.creds {
            if ct_eq(presented, &cred.userpass) {
                matched = Some(cred.username.as_str());
            }
        }
        matched
    }

    /// The `401` challenge: what an unauthenticated request gets. The realm was
    /// validated at `init`, so it is safe to inline into the header value.
    fn challenge(&self) -> Response {
        Response::respond(401, "authentication required").header(
            "WWW-Authenticate",
            format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm),
        )
    }
}

impl Middleware for BasicAuth {
    fn init(config: &serde_json::Value) -> Result<Self, String> {
        let users = config
            .get("users")
            .and_then(serde_json::Value::as_object)
            .ok_or("`users` is required and must be an object of username -> password")?;
        if users.is_empty() {
            return Err("`users` must have at least one entry".into());
        }
        let creds = users
            .iter()
            .map(|(username, password)| {
                if username.is_empty() || username.contains(':') {
                    return Err(format!(
                        "username {username:?} is invalid (empty, or contains `:` — the \
                         Basic credential separator)"
                    ));
                }
                let password = password
                    .as_str()
                    .ok_or_else(|| format!("`users[{username:?}]` must be a string password"))?;
                Ok(Cred {
                    username: username.clone(),
                    userpass: format!("{username}:{password}").into_bytes(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let realm = match config.get("realm") {
            None | Some(serde_json::Value::Null) => "Restricted".to_owned(),
            Some(serde_json::Value::String(s)) if !s.is_empty() => {
                if s.contains(['"', '\\']) || s.chars().any(|c| c.is_ascii_control()) {
                    return Err("`realm` must not contain `\"`, `\\`, or control characters".into());
                }
                s.clone()
            }
            Some(other) => return Err(format!("`realm` must be a non-empty string, got {other}")),
        };

        let forward_user_header = match config.get("forward_user_header") {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(s)) if !s.is_empty() => Some(s.clone()),
            Some(other) => {
                return Err(format!(
                    "`forward_user_header` must be a non-empty string, got {other}"
                ));
            }
        };

        Ok(Self { creds, realm, forward_user_header })
    }

    fn invoke(&self, req: &Request<'_>) -> Response {
        let Some(presented) = Self::presented(req) else {
            return self.challenge();
        };
        let Some(username) = self.authenticate(&presented) else {
            return self.challenge();
        };
        // Authenticated. Forward the identity to PHP if asked (the host's
        // header override replaces, so a client cannot spoof it), else just
        // continue the chain.
        match &self.forward_user_header {
            Some(header) => Response::rewrite().header(header.as_str(), username),
            None => Response::cont(),
        }
    }

    fn describe() -> &'static str {
        "basic-auth (HTTP Basic whole-site gate)"
    }
}

// ── C ABI export ────────────────────────────────────────────────────────────
// `declare!` generates the `extern "C"` entry points ePHPm's module loader
// calls (init / invoke / free) and bakes in the ABI-major compatibility check,
// so a module built against the wrong host ABI refuses to load instead of
// corrupting memory. This is the ONLY line that turns the plain `Middleware`
// impl above into a loadable `.so`/`.dylib`/`.dll`.
ephpm_middleware::declare!(BasicAuth);

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)] // tests build the FFI Request view by hand.

    use base64ct::{Base64, Encoding};
    use ephpm_middleware::abi::{ACTION_CONTINUE, ACTION_RESPOND, ACTION_REWRITE};
    use ephpm_middleware::host::{RequestCtx, host_table};

    use super::*;

    fn basic_auth(config: serde_json::Value) -> BasicAuth {
        BasicAuth::init(&config).expect("init")
    }

    /// A ready-to-send `Authorization: Basic` header for `user:pass`.
    fn basic(user: &str, pass: &str) -> Vec<(String, String)> {
        let token = Base64::encode_string(format!("{user}:{pass}").as_bytes());
        vec![("Authorization".to_owned(), format!("Basic {token}"))]
    }

    fn invoke_path(mw: &BasicAuth, path: &str, headers: &[(String, String)]) -> Response {
        let ctx = RequestCtx::new("GET", path, "", "203.0.113.9", "preview.example", headers);
        // SAFETY: `ctx` outlives the view; host_table() is 'static.
        let req = unsafe { Request::from_raw(ctx.as_abi(), host_table()) };
        mw.invoke(&req)
    }

    fn invoke(mw: &BasicAuth, headers: &[(String, String)]) -> Response {
        invoke_path(mw, "/index.php", headers)
    }

    fn assert_challenge(resp: &Response) {
        assert_eq!(resp.__action(), ACTION_RESPOND, "unauthenticated must short-circuit");
        assert_eq!(resp.__status(), 401);
        let challenge = resp
            .__headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("WWW-Authenticate"))
            .map(|(_, v)| v.as_str());
        assert!(challenge.is_some_and(|c| c.starts_with("Basic realm=")), "401 must challenge");
    }

    fn forwarded_user(resp: &Response, header: &str) -> Option<String> {
        resp.__headers()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(header))
            .map(|(_, v)| v.clone())
    }

    // ── config ────────────────────────────────────────────────────────────

    #[test]
    fn init_requires_a_non_empty_users_table() {
        assert!(BasicAuth::init(&serde_json::json!({})).is_err());
        assert!(BasicAuth::init(&serde_json::json!({ "users": {} })).is_err());
        assert!(BasicAuth::init(&serde_json::json!({ "users": "nope" })).is_err());
        // A password must be a string; a username may not contain `:`.
        assert!(BasicAuth::init(&serde_json::json!({ "users": { "a": 1 } })).is_err());
        assert!(BasicAuth::init(&serde_json::json!({ "users": { "a:b": "x" } })).is_err());
        assert!(BasicAuth::init(&serde_json::json!({ "users": { "a": "secret" } })).is_ok());
    }

    #[test]
    fn init_rejects_a_dangerous_realm() {
        // A `"` or `\` would break out of the quoted WWW-Authenticate value.
        for bad in ["a\"b", "a\\b", "a\nb"] {
            let cfg = serde_json::json!({ "users": { "u": "p" }, "realm": bad });
            assert!(BasicAuth::init(&cfg).is_err(), "{bad:?} must be rejected");
        }
        let cfg = serde_json::json!({ "users": { "u": "p" }, "realm": "Preview PR-42" });
        assert_eq!(BasicAuth::init(&cfg).expect("init").realm, "Preview PR-42");
    }

    #[test]
    fn realm_defaults_and_appears_in_the_challenge() {
        let mw = basic_auth(serde_json::json!({ "users": { "u": "p" } }));
        assert_eq!(mw.realm, "Restricted");
        let challenge = mw
            .challenge()
            .__headers()
            .iter()
            .find(|(n, _)| n == "WWW-Authenticate")
            .map(|(_, v)| v.clone())
            .expect("challenge header");
        assert_eq!(challenge, "Basic realm=\"Restricted\", charset=\"UTF-8\"");
    }

    // ── the happy path ────────────────────────────────────────────────────

    #[test]
    fn valid_credentials_continue_to_php() {
        let mw = basic_auth(serde_json::json!({ "users": { "alice": "s3cret" } }));
        assert_eq!(invoke(&mw, &basic("alice", "s3cret")).__action(), ACTION_CONTINUE);
    }

    #[test]
    fn valid_credentials_forward_the_username_when_configured() {
        let mw = basic_auth(serde_json::json!({
            "users": { "alice": "s3cret" },
            "forward_user_header": "X-Auth-User",
        }));
        let resp = invoke(&mw, &basic("alice", "s3cret"));
        assert_eq!(resp.__action(), ACTION_REWRITE);
        assert_eq!(forwarded_user(&resp, "X-Auth-User").as_deref(), Some("alice"));
    }

    #[test]
    fn one_of_several_configured_users_authenticates() {
        let mw = basic_auth(serde_json::json!({
            "users": { "alice": "a-pass", "bob": "b-pass" },
        }));
        assert_eq!(invoke(&mw, &basic("bob", "b-pass")).__action(), ACTION_CONTINUE);
    }

    // ── the rejection paths ───────────────────────────────────────────────

    #[test]
    fn missing_authorization_is_challenged() {
        assert_challenge(&invoke(&basic_auth(serde_json::json!({ "users": { "u": "p" } })), &[]));
    }

    #[test]
    fn wrong_password_and_unknown_user_are_challenged() {
        let mw = basic_auth(serde_json::json!({ "users": { "alice": "s3cret" } }));
        assert_challenge(&invoke(&mw, &basic("alice", "wrong")));
        assert_challenge(&invoke(&mw, &basic("mallory", "s3cret")));
        // A right password under the wrong username must not authenticate.
        assert_challenge(&invoke(&mw, &basic("bob", "s3cret")));
    }

    #[test]
    fn a_non_basic_or_malformed_authorization_is_challenged() {
        let mw = basic_auth(serde_json::json!({ "users": { "u": "p" } }));
        for header in [
            ("Authorization", "Bearer sometoken"),    // wrong scheme
            ("Authorization", "Basic"),               // no credential
            ("Authorization", "Basic !!!not-base64"), // undecodable
            ("Authorization", ""),                    // empty
        ] {
            let h = vec![(header.0.to_owned(), header.1.to_owned())];
            assert_challenge(&invoke(&mw, &h));
        }
    }

    #[test]
    fn the_scheme_token_is_case_insensitive() {
        // RFC 7235: `basic`, `BASIC`, `Basic` are the same scheme.
        let mw = basic_auth(serde_json::json!({ "users": { "u": "p" } }));
        let token = Base64::encode_string(b"u:p");
        for scheme in ["basic", "BASIC", "BaSiC"] {
            let h = vec![("Authorization".to_owned(), format!("{scheme} {token}"))];
            assert_eq!(invoke(&mw, &h).__action(), ACTION_CONTINUE, "scheme {scheme}");
        }
    }

    // ── #408 / #395: the gate covers static assets, not only PHP ──────────

    #[test]
    fn a_static_asset_is_challenged_before_it_is_read() {
        // The request phase runs on the static-file path too, before the file
        // is opened. An unauthenticated request for a static asset must get the
        // 401 challenge — the module is blind to whether the target is a script
        // or a static byte, so the bytes on disk are never served.
        let mw = basic_auth(serde_json::json!({ "users": { "u": "p" } }));
        for asset in ["/assets/app.js", "/css/site.css", "/uploads/private.pdf", "/favicon.ico"] {
            assert_challenge(&invoke_path(&mw, asset, &[]));
            // ...and a valid credential lets the same asset through the gate.
            assert_eq!(
                invoke_path(&mw, asset, &basic("u", "p")).__action(),
                ACTION_CONTINUE,
                "{asset}: an authenticated request continues to the static file",
            );
        }
    }

    #[test]
    fn ct_eq_is_correct() {
        assert!(ct_eq(b"user:pass", b"user:pass"));
        assert!(!ct_eq(b"user:pass", b"user:pasZ"));
        assert!(!ct_eq(b"user:pass", b"user:pas")); // length mismatch
        assert!(ct_eq(b"", b""));
    }
}
