//! `maintenance-mode` — loadable cdylib shell around the shared
//! implementation in [`ephpm_middleware_modules::maintenance_mode`].
//!
//! The middleware itself (a per-site KV flag that short-circuits the request
//! with a 503 holding page, docs and tests included) lives in
//! `ephpm-middleware-modules`. This crate only adds the C ABI exports
//! (`declare!`) so the module can be `dlopen`ed by dynamically linked ePHPm
//! builds.

pub use ephpm_middleware_modules::maintenance_mode::MaintenanceMode;

ephpm_middleware::declare!(MaintenanceMode);
