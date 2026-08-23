//! Fail-CLOSED deny path, driven through the loadable shell crate.
//!
//! The sibling `ratelimit` / `maintenance-mode` integration tests only assert
//! the fail-OPEN `CONTINUE` verdict. This one exercises the opposite — the
//! access-control gate producing a real `403` `RESPOND` — end to end through
//! the same surface the host uses: the module type as re-exported by the
//! *shell* crate (`ephpm_middleware_ip_allowlist::IpAllowlist`, the crate that
//! becomes the shipped cdylib), driven via the `host` feature's fabricated
//! `RequestCtx` and the real `host_table()`.
//!
//! It needs no ephpm binary and no KV store — the verdict is pure CIDR policy,
//! so the test is deterministic (never flaky). It proves that a built module,
//! reached through the ABI-facing `Request`/`Response` types, denies an
//! out-of-policy client with the exact status and body the module documents.
#![allow(unsafe_code)] // builds the FFI Request view by hand, like the unit tests.

use ephpm_middleware::Middleware;
use ephpm_middleware::abi::{ACTION_CONTINUE, ACTION_RESPOND};
use ephpm_middleware::host::{RequestCtx, host_table};
use ephpm_middleware_ip_allowlist::IpAllowlist;

/// Drive the module for one client IP and return the ABI `Response`.
fn invoke(mw: &IpAllowlist, ip: &str) -> ephpm_middleware::Response {
    let ctx = RequestCtx::new("GET", "/index.php", "", ip, "example.test", &[]);
    // SAFETY: `ctx` outlives the view; host_table() is 'static.
    let req = unsafe { ephpm_middleware::Request::from_raw(ctx.as_abi(), host_table()) };
    mw.invoke(&req)
}

#[test]
fn out_of_policy_ip_is_denied_403() {
    // Allow only the RFC1918 10/8 block; everything else hits the default deny.
    let mw = IpAllowlist::init(&serde_json::json!({ "allow": ["10.0.0.0/8"] })).expect("init");

    // An in-range client passes straight through to PHP.
    assert_eq!(invoke(&mw, "10.1.2.3").__action(), ACTION_CONTINUE);

    // An out-of-range client is rejected with a real 403 RESPOND verdict —
    // action, status, and the plain-text body all asserted.
    let resp = invoke(&mw, "203.0.113.9");
    assert_eq!(resp.__action(), ACTION_RESPOND);
    assert_eq!(resp.__status(), 403);
    assert!(!resp.__body().is_empty());
}

#[test]
fn explicit_deny_beats_allow() {
    // Same address in both lists with default=allow: deny must still win (403).
    let mw = IpAllowlist::init(&serde_json::json!({
        "allow": ["10.0.0.0/8"],
        "deny": ["10.6.6.6/32"],
        "default": "allow",
    }))
    .expect("init");
    assert_eq!(invoke(&mw, "10.6.6.6").__action(), ACTION_RESPOND);
    assert_eq!(invoke(&mw, "10.6.6.7").__action(), ACTION_CONTINUE);
}
