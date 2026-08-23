//! `cors` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::cors`].
//!
//! The middleware itself (CORS preflight handling and response headers, docs
//! and tests included) lives in `ephpm-middleware-modules`. This crate only
//! adds the C ABI exports (`declare!`) so the module can be `dlopen`ed by
//! dynamically linked ePHPm builds.

pub use ephpm_middleware_modules::cors::Cors;

ephpm_middleware::declare!(Cors);
