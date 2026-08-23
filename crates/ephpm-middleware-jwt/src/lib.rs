//! `jwt` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::jwt`].
//!
//! The middleware itself (HS256 bearer-token validation, docs and tests
//! included) lives in `ephpm-middleware-modules`. This crate only adds the C
//! ABI exports (`declare!`) so the module can be `dlopen`ed by dynamically
//! linked ePHPm builds. `describe()` reports this crate's name
//! (`ephpm-middleware-jwt`) in the host's startup log.

pub use ephpm_middleware_modules::jwt::Jwt;

ephpm_middleware::declare!(Jwt);
