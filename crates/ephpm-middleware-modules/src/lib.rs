//! The official ePHPm native middleware modules as plain Rust library code.
//!
//! Each module here is an ordinary [`ephpm_middleware::Middleware`]
//! implementation with **no C ABI exports**. That is what lets them all be
//! linked into one binary — either into the loadable cdylib shells one at a
//! time, or all together into an ePHPm built with the `vendor-middleware`
//! feature, which runs them in-process through the static builtin registry
//! (so `library = "jwt"` works even in a custom fully static build, where
//! `dlopen` does not exist).
//!
//! `ephpm-middleware-<name>` crates are thin cdylib shells: they re-export
//! these types and add the `declare!` C ABI glue, producing the loadable
//! `.so`/`.dylib`/`.dll` artifacts for the dynamic (dlopen) lane. The shells
//! cannot be merged into one binary — several copies of the same
//! `ephpm_middleware_*` export symbols collide at link time — which is exactly
//! why the implementations live here.

pub mod api_key;
pub mod compression;
pub mod cors;
pub mod header_transform;
pub mod ip_allowlist;
pub mod jwt;
pub mod maintenance_mode;
pub mod ratelimit;
pub mod redirect;
pub mod request_id;
pub mod security_headers;
