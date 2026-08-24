//! `header-transform` — loadable cdylib shell around the shared implementation
//! in [`ephpm_middleware_modules::header_transform`].
//!
//! The middleware itself (request/response header set + response header remove,
//! the request + response phase logic, docs and tests included) lives in
//! `ephpm-middleware-modules`. This crate only adds the C ABI exports
//! (`declare!(HeaderTransform, response)`) for the `dlopen` lane.

pub use ephpm_middleware_modules::header_transform::HeaderTransform;

ephpm_middleware::declare!(HeaderTransform, response);
