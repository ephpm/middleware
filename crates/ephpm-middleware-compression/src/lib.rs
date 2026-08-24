//! `compression` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::compression`].
//!
//! The middleware itself (response-phase gzip/brotli negotiation and the
//! anti-double-encode guards, docs and tests included) lives in
//! `ephpm-middleware-modules`. This crate only adds the C ABI exports
//! (`declare!(Compress, response)`) for the `dlopen` lane.
//!
//! Note: ePHPm's core already compresses buffered responses by default. This
//! module stands down when a `Content-Encoding` is already present — see the
//! implementation's module docs for when to actually mount it.

pub use ephpm_middleware_modules::compression::Compress;

ephpm_middleware::declare!(Compress, response);
