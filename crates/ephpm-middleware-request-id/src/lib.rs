//! `request-id` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::request_id`].
//!
//! The middleware itself (id generation/propagation, the request + response
//! phase logic, docs and tests included) lives in `ephpm-middleware-modules`.
//! This crate only adds the C ABI exports (`declare!(RequestId, response)`, so
//! both the request and response phase are exported) for the `dlopen` lane.

pub use ephpm_middleware_modules::request_id::RequestId;

ephpm_middleware::declare!(RequestId, response);
