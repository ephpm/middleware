//! `security-headers` — loadable cdylib shell around the shared
//! implementation in [`ephpm_middleware_modules::security_headers`].
//!
//! The middleware itself (standard security response headers, docs and tests
//! included) lives in `ephpm-middleware-modules`. This crate only adds the C
//! ABI exports (`declare!`) so the module can be `dlopen`ed by dynamically
//! linked ePHPm builds.

pub use ephpm_middleware_modules::security_headers::SecurityHeaders;

ephpm_middleware::declare!(SecurityHeaders);
