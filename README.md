# ePHPm middleware

Prebuilt, versioned **native middleware modules** for
[ePHPm](https://github.com/ephpm/ephpm) — the official modules, shipped as
loadable shared libraries (`.so` / `.dylib` / `.dll`) you fetch and mount,
rather than compile into the server.

> **This repo must be public to serve unauthenticated release downloads.** The
> `ephpm middleware` CLI downloads release assets over anonymous HTTPS; while
> the repo is private those downloads require a token. The owner flips it
> public when ready.

ePHPm runs middleware in two phases. The **request phase** runs **in front of
PHP, before PHP dispatch** — reject, rewrite, or annotate a request at native
speed, with direct access to the embedded (cluster-replicated) KV store; it
fails **closed**. The optional **response phase** runs **after** the response
is generated (PHP, static file, or error page), in reverse chain order, to
*transform* it — header injection, correlation ids; it fails
**safe** and is not a security gate. A module opts into the response phase with
`declare!(Type, response)`. See the
[Native Middleware guide](https://github.com/ephpm/ephpm/blob/main/site/content/guides/native-middleware.md)
for the operator view and chain semantics.

## The modules

| Module (short name) | Crate | What it does |
|---------------------|-------|--------------|
| `api-key` | `ephpm-middleware-api-key` | Validate an API key (header, optionally query param) against a static map or KV lookup; forward the resolved consumer id to PHP (constant-time compare; `401` otherwise). |
| `jwt` | `ephpm-middleware-jwt` | Validate HS256 bearer tokens before PHP runs (constant-time HMAC; `alg` pinned; `exp` required). |
| `cors` | `ephpm-middleware-cors` | Answer CORS preflights directly (`204`), append `Access-Control-*` to cross-origin responses. |
| `ratelimit` | `ephpm-middleware-ratelimit` | Fixed-window per-client rate limiting over the embedded KV store (`429` + `Retry-After`). |
| `redirect` | `ephpm-middleware-redirect` | Enforce canonical URLs with a single `301`/`308` — `http`→`https`, apex↔`www` (or an explicit host map), trailing-slash add/strip. |
| `security-headers` | `ephpm-middleware-security-headers` | Append standard security response headers (HSTS, CSP, `X-Frame-Options`, …). |
| `maintenance-mode` | `ephpm-middleware-maintenance-mode` | Flip a tenant into a `503` holding page via a per-site KV flag — no redeploy (`Retry-After`; IP/path bypass; fails **open**). |
| `ip-allowlist` | `ephpm-middleware-ip-allowlist` | Allow/deny requests by client IP against CIDR lists, fail-closed (`403`); deny beats allow. |
| `request-id` | `ephpm-middleware-request-id` | **Request + response phase.** Give every request a correlation id: generate or honor an inbound `X-Request-Id`, inject it for PHP, and echo it on the response. |
| `header-transform` | `ephpm-middleware-header-transform` | **Request + response phase.** Set request headers seen by PHP; set/remove response headers out. |

> **No `compression` module.** Response-body compression is deliberately *not*
> shipped as a middleware: ePHPm's core already compresses buffered responses
> by default (`[server.response] compression`, **on**, brotli-then-gzip),
> negotiating `Accept-Encoding` and running **before** the response phase — so
> a middleware compressor would be redundant and inert on a stock server. Use
> the built-in knob, not a module.

Per-module configuration keys are documented in each crate's module docs
(`crates/ephpm-middleware-<name>/src/lib.rs` re-exports the implementation from
`crates/ephpm-middleware-modules/src/<name>.rs`).

## ABI version

Every module is built against the ePHPm native-middleware **C ABI**, which is
versioned; the **major byte** gates compatibility. A module built against ABI
major *N* refuses to initialise in a host whose major is different — the check
is baked into the module by `ephpm_middleware::declare!`.

- **Current ABI major: `1`** (`ephpm_middleware::abi::ABI_V1 = 0x0100_0000`).
- The ABI/trait crate `ephpm-middleware` is **not** vendored here — it is the
  shared contract owned by the ePHPm host. This repo depends on it by git `rev`
  (see the root `Cargo.toml`), exactly the way ePHPm pins litewire, so every
  module is provably built against one specific host-ABI commit. Bumping the
  ABI means bumping that `rev` and cutting a new release.
- Each release records its ABI major in `manifest.json` (below), so the CLI can
  refuse an incompatible module **at download time**, before it is ever loaded.

## Releases: what the CLI consumes

Each release (tag `vX.Y.Z`) carries, per platform ePHPm ships:

| Asset name | Meaning |
|------------|---------|
| `<name>.<platform>.<ext>` | The module cdylib for that platform. `<platform>` is `<os>-<arch>` with `macos`→`darwin` — e.g. `jwt.linux-x86_64.so`, `cors.darwin-aarch64.dylib`, `jwt.windows-x86_64.dll`. This is **exactly** the file name the host loader looks for when a mount says `library = "<name>"`. |
| `<name>.linux-<arch>-musl.<ext>` | The musl build, for the rare fully-*dynamic* musl host. The loader has no libc distinction in its file names, so the CLI does **not** install this automatically — place it yourself with `ephpm middleware get <name> --dest <dir>` and mount it by explicit path. (A fully *static* musl binary cannot `dlopen` at all.) |
| `SHA256SUMS` | `sha256sum`-format digest of every asset. **The integrity floor** — the CLI verifies a downloaded module against this before writing it to disk, and fails closed on a mismatch or a missing `SHA256SUMS`. |
| `manifest.json` | `{ schema, abi_major, release, modules: [{ name, crate, describe, assets: [{ platform, libc, file, ext, sha256 }] }] }`. The CLI reads `abi_major` for the download-time compatibility gate and the module/asset list for `list` and platform→asset mapping. |

### Host loader search path (where the CLI drops files)

A bare `library = "<name>"` mount is resolved by the host, in each of the
current working directory, `$EPHPM_MIDDLEWARE_DIR` (when set), and
`/usr/local/lib/ephpm/middleware`, by trying:

1. `<name>.<platform>.<ext>`  ← the release asset name; the CLI writes here
2. `lib<name>.<ext>`
3. `<name>.<ext>`

So `ephpm middleware get jwt` writes `jwt.<platform>.<ext>` into a search
directory and `library = "jwt"` then resolves. Run `ephpm middleware
search-path` to print the exact directories.

## Building locally

```bash
# Fetch the ABI crate via the git CLI (handles host git rewrite rules).
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -p ephpm-middleware-jwt
# → target/release/libephpm_middleware_jwt.so  (lib<name>.dll on Windows)
```

`cargo test --workspace` runs the module unit tests plus the ratelimit
fail-open integration test (these pull the `host` feature of `ephpm-middleware`
and the embedded KV store as dev-dependencies; the shipped cdylibs need
neither).

## Layout

```
crates/
  ephpm-middleware-modules            rlib: the module impls as plain types, NO
                                      C ABI exports (so they can all be linked
                                      into one binary — the cdylib shells, or
                                      ePHPm's `vendor-middleware` feature)
  ephpm-middleware-api-key            cdylib shell: pub use + declare!(ApiKey)
  ephpm-middleware-jwt                cdylib shell: pub use + declare!(Jwt)
  ephpm-middleware-cors               cdylib shell
  ephpm-middleware-ratelimit          cdylib shell
  ephpm-middleware-redirect           cdylib shell
  ephpm-middleware-security-headers   cdylib shell
  ephpm-middleware-maintenance-mode   cdylib shell
  ephpm-middleware-ip-allowlist       cdylib shell
  ephpm-middleware-request-id         cdylib shell: declare!(RequestId, response)
  ephpm-middleware-header-transform   cdylib shell: declare!(HeaderTransform, response)
```

The last two opt into the **response phase** with `declare!(Type, response)` —
the host runs their `invoke_response` after the response is generated to
transform it, in addition to their request phase.

The impl/shell split is deliberate: multiple crates each exporting the same
`ephpm_middleware_*` symbols cannot be linked into one binary, so the
implementations live symbol-free in `ephpm-middleware-modules` and each cdylib
adds only the `declare!` exports. That same rlib is what ePHPm's off-by-default
`vendor-middleware` feature compiles in when someone needs middleware in a
fully-static (non-`dlopen`) build.

## Releasing

`.github/workflows/release.yml`:

- **push a `v*` tag** → builds all modules for the full platform matrix
  (linux x86_64/aarch64 × gnu+musl, macOS aarch64, windows x86_64) and
  publishes the assets + `SHA256SUMS` + `manifest.json`.
- **`workflow_dispatch`** → scriptable partial cut; `modules` and
  `only_host_platform` subset the work (used to validate the pipeline with a
  single module on one platform).

All runners are **GitHub-hosted** — these modules are pure Rust and must not
contend with ePHPm's self-hosted (ephemerd) fleet.

## License

MIT — see [LICENSE](LICENSE).
