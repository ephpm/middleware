//! `redirect` — loadable cdylib shell around the shared implementation in
//! [`ephpm_middleware_modules::redirect`].
//!
//! The middleware itself (canonical-host / scheme / trailing-slash redirect
//! logic, docs and tests included) lives in `ephpm-middleware-modules`. This
//! crate only adds the C ABI exports (`declare!`) so the module can be
//! `dlopen`ed by dynamically linked ePHPm builds.

pub use ephpm_middleware_modules::redirect::Redirect;

ephpm_middleware::declare!(Redirect);
