//! `api-key` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::api_key`].
//!
//! The middleware itself (API-key extraction, static/KV validation with a
//! constant-time key comparison, and consumer-id forwarding to PHP — docs and
//! tests included) lives in `ephpm-middleware-modules`. This crate only adds
//! the C ABI exports (`declare!`) so the module can be `dlopen`ed by
//! dynamically linked ePHPm builds.

pub use ephpm_middleware_modules::api_key::ApiKey;

ephpm_middleware::declare!(ApiKey);
