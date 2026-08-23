//! `ratelimit` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::ratelimit`].
//!
//! The middleware itself (fixed-window per-client rate limiting over the
//! embedded KV store, docs and tests included) lives in
//! `ephpm-middleware-modules`. This crate only adds the C ABI exports
//! (`declare!`) so the module can be `dlopen`ed by dynamically linked ePHPm
//! builds.

pub use ephpm_middleware_modules::ratelimit::RateLimit;

ephpm_middleware::declare!(RateLimit);
