//! Fail-OPEN behaviour when the KV store is unavailable.
//!
//! This lives in its own integration-test binary (= its own process) because
//! the host KV store is process-global: once set it cannot be unset. Here
//! `set_kv_store` is never called, so every `kv_get` returns `None` — the
//! module must let the request through (fail-OPEN), never black-hole the
//! tenant. This is the deliberate opposite of an auth/allowlist gate, which
//! must fail closed. See the module docs for the rationale.
#![allow(unsafe_code)] // builds the FFI Request view by hand, like the unit tests.

use ephpm_middleware::Middleware;
use ephpm_middleware::abi::ACTION_CONTINUE;
use ephpm_middleware::host::{RequestCtx, host_table};
use ephpm_middleware_maintenance_mode::MaintenanceMode;

#[test]
fn kv_unavailable_fails_open() {
    // Even with an aggressive key template, no store means no flag can ever
    // read truthy — every request must continue.
    let mw = MaintenanceMode::init(&serde_json::json!({ "retry_after": 60 })).expect("init");
    let ctx = RequestCtx::new("GET", "/", "", "198.51.100.9", "vhost-open", &[]);
    // SAFETY: `ctx` outlives the view; host_table() is 'static.
    let req = unsafe { ephpm_middleware::Request::from_raw(ctx.as_abi(), host_table()) };
    for _ in 0..50 {
        assert_eq!(mw.invoke(&req).__action(), ACTION_CONTINUE);
    }
}
