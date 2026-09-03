# ePHPm middleware examples

Reference implementations of **native middleware** for
[ePHPm](https://github.com/ephpm/ephpm) — small, well-commented Rust modules
you can read, copy, and adapt to write your own.

> **The official modules are compiled into ePHPm itself.** `jwt`, `cors`,
> `ratelimit`, `security-headers`, `api-key`, `ip-allowlist`, `maintenance-mode`,
> `redirect`, `request-id`, and `header-transform` ship inside every ePHPm
> binary and are mounted by name (`library = "jwt"`) with nothing to download.
> This repo is **not** a distribution channel for them. It is teaching material:
> the four crates here are stand-alone templates that show the whole shape of a
> module — the ABI, the `declare!` macro, the request and response phases, and
> KV access — so you can build a *custom* one.

## What native middleware is

A native middleware module is a tiny shared library (`.so` / `.dylib` / `.dll`)
that ePHPm loads at startup and runs **in front of / around PHP**, at native
speed, with direct access to the embedded (cluster-replicated) KV store. It runs
in two phases:

- **Request phase** — runs **before** the request is served (on the PHP path and
  the static-file path), and can let the request `CONTINUE`, `REWRITE` it
  (inject/override request headers, rewrite the path), or `RESPOND` immediately
  (short-circuit with a status + body — an auth `401`, a redirect). It fails
  **closed**: a broken module aborts startup, and a panicking
  `invoke` returns `500` rather than letting the request through.
- **Response phase** — optional; runs **after** the response is generated
  (PHP, static file, or error page), in **reverse** chain order, to *transform*
  it: set/remove response headers, adjust status. It fails **safe** (a broken
  transform leaves the response unchanged) and is **not** a security gate. A
  module opts in with `declare!(Type, response)` (added to the ABI in ePHPm
  [#408](https://github.com/ephpm/ephpm/pull/408)); the response phase only runs
  on **buffered** bodies (streamed responses bypass it).

See the operator-facing
[Native Middleware guide](https://github.com/ephpm/ephpm/blob/main/site/content/guides/native-middleware.md)
for chain semantics, `match`/`order`, and mounting.

## The examples

Four modules, chosen to cover the range rather than every use case:

| Example | Crate | Teaches |
|---------|-------|---------|
| `basic-auth` | `ephpm-middleware-basic-auth` | The **simplest whole-site auth gate**: verify an `Authorization: Basic` credential (RFC 7617) with a constant-time compare, `401` + `WWW-Authenticate` otherwise. No KV. Gates static assets and PHP alike (ePHPm #408/#395). Start here. |
| `api-key` | `ephpm-middleware-api-key` | A **request-phase auth gate** that also **uses the KV store**: read a key from a header (or query param), validate it against a static map **or** a `kv_get_global` lookup with a constant-time compare, and forward the resolved consumer id to PHP — or short-circuit `401`. Also the **multi-tenancy** example: an optional `<site>` in the KV key template scopes the credential map per tenant, and fails closed when the request matched no vhost. |
| `redirect` | `ephpm-middleware-redirect` | The **simplest early-return**: compute a canonical URL (scheme / host / trailing slash) and emit a single `301`/`308`, or `CONTINUE`. No KV, no extra deps. |
| `header-transform` | `ephpm-middleware-header-transform` | The **response phase**: `declare!(Type, response)`, setting request headers PHP sees *and* setting/removing response headers on the way out. |

Each crate's `src/lib.rs` is self-contained — implementation, module docs, unit
tests, and the one `declare!` line that turns it into a loadable module — so you
can read one file end to end.

## Anatomy of a module

```rust
use ephpm_middleware::{Middleware, Request, Response};

pub struct MyGate { /* config parsed once at init */ }

impl Middleware for MyGate {
    // Parse `[[middleware]] config = { ... }` (as serde_json) once at startup.
    // Return Err(msg) to fail the mount fast.
    fn init(config: &serde_json::Value) -> Result<Self, String> { /* ... */ }

    // Run per request. Return one of the request-phase verdicts.
    fn invoke(&self, req: &Request<'_>) -> Response {
        if req.header("X-Token").is_none() {
            return Response::respond(401, "missing token"); // short-circuit
        }
        Response::cont()                                    // let it through
        // or Response::rewrite().header("X-Consumer", id)  // annotate for PHP
    }
}

// The ONE line that exports the C ABI entry points and bakes in the ABI-major
// compatibility check. Without it you have a plain Rust type, not a module.
ephpm_middleware::declare!(MyGate);
```

To also transform the response, implement `ResponseMiddleware` and opt in with
`declare!(MyGate, response)`:

```rust
use ephpm_middleware::{ResponseMiddleware, ResponseView};

impl ResponseMiddleware for MyGate {
    fn invoke_response(&self, _req: &Request<'_>, resp: &mut ResponseView<'_>) {
        resp.remove_header("X-Powered-By");
        resp.set_header("X-Served-By", "ephpm");
    }
}
```

**KV access.** The request carries a handle to ePHPm's embedded KV store —
`req.host().kv_get(key)`, `kv_set`, `kv_incr_ttl(key, by, ttl)` — the same
gossip-replicated store PHP uses. Since ABI minor 3 those resolve **the serving
vhost's** keyspace, and `kv_get_global` / `kv_set_global` / `kv_incr_ttl_global`
resolve the process-wide store; see [Tenancy](#tenancy-vhost_id-and-kv-scope)
below. `api-key` shows both.

### Tenancy: `vhost_id()` and KV scope

One mount serves every vhost, so a module on a multi-tenant node
(`[server] sites_dir`) has to decide *whose* request it is looking at. Two rules
carry all of it:

**1. `req.vhost_id()` is the tenant identity; the `Host` header is not.** It
returns `Option<&str>` — the **canonical site key** the router resolved, which
is the same identity that picks the request's per-site database, KV keyspace and
OPcache vhost. It is normalized by the router, so `Site.Example`,
`site.example:8080` and `site.example.` are one key, and a configured
`sites_domain_suffix` is already stripped.

`None` means the request matched **no** virtual host. That is a decision, not a
missing value: ePHPm serves unrecognised hosts from the default document root,
so `req.http_host()` there is arbitrary client input. Two correct ways to handle
it, and no third:

```rust
// Auth gate — fail closed. No tenant, no policy.
let Some(site) = req.vhost_id() else {
    return Response::respond(404, "unknown host");
};

// Rate limiter / counter — one deliberate bucket, never one per Host value.
let site = req.vhost_id().unwrap_or(ephpm_middleware::UNMATCHED_VHOST);
```

Substituting the header instead hands a caller a fresh keyspace — and a fresh
rate-limit budget — per `Host` they invent. That was ePHPm
[#390](https://github.com/ephpm/ephpm/issues/390). Use `req.http_host()` only
when you genuinely want the host as sent (a canonical-host redirect, a log
line); `redirect` is the example of that.

**2. `kv_*` is per-tenant, `kv_*_global` is node-wide.** Since ePHPm
[#376](https://github.com/ephpm/ephpm/issues/376) the plain `kv_*` callbacks
resolve the serving vhost's own store — the same one that tenant's PHP writes
through `ephpm_kv_set()`. A counter or flag is therefore per-tenant with no key
prefixing, and a module can share a key with the app it fronts. But **anything a
tenant must not be able to forge belongs in `kv_*_global`**: a credential map in
the per-site store is writable by that site's own PHP. `api-key` puts its map in
the global store for exactly that reason.

On a single-site node there is one store and the two are the same thing.

### The ABI is versioned

Every module is built against ePHPm's native-middleware **C ABI**, whose **major
byte** gates compatibility: `declare!` embeds the major, and a module built
against a different host major refuses to initialise rather than corrupt memory
at the FFI boundary (current major: `1`). The lower three bytes are an additive
**minor** level; these examples are built against **minor 3**
(`0x0100_0003`) — minor 1 added the response phase, minor 2 the
scheme/`is_secure`/normalized-host request accessors and a real request body,
and minor 3 the process-global KV slots plus the two redefinitions described
under [Tenancy](#tenancy-vhost_id-and-kv-scope).

The ABI/trait crate `ephpm-middleware` is **not** vendored here — it is the
shared contract owned by the ePHPm host, so these examples depend on it by git
`rev` (see the root `Cargo.toml`), pinned to one specific host commit exactly the
way ePHPm pins litewire. To build against a newer host, bump that `rev` and
`cargo update`.

## Building a module

```bash
# The ephpm-middleware ABI crate is a git dependency; fetch via the git CLI so
# host git rewrite rules apply.
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release -p ephpm-middleware-redirect
# → target/release/libephpm_middleware_redirect.so   (.dylib on macOS;
#   ephpm_middleware_redirect.dll — no `lib` prefix — on Windows)
```

`cargo test --workspace` runs every example's unit tests. The `host` feature of
`ephpm-middleware` and the embedded KV store are pulled in only as
**dev-dependencies** (to fabricate a request and a real KV store in tests); the
shipped cdylib needs neither.

## Mounting a custom module

Add a `[[middleware]]` block to your ePHPm config. `library` is resolved by
ePHPm's loader ([`resolve_library`](https://github.com/ephpm/ephpm/blob/main/crates/ephpm-server/src/middleware.rs))
against the **builtin registry first**, then the shared-library lane:

```toml
[[middleware]]
# A value with a path separator OR a file extension is used as an explicit
# path — the most predictable way to mount a module you just built:
library = "/usr/local/lib/ephpm/middleware/my-gate.so"
match   = "/api/*"     # optional glob; omit to run on every request
order   = 20           # required; lower runs first
config  = { header = "X-Token" }
```

Or drop the file into a search directory and mount it by **bare name**. A bare
name (no separator, no extension) is resolved through the middleware search path
— the current directory, `$EPHPM_MIDDLEWARE_DIR` (when set), and
`/usr/local/lib/ephpm/middleware` — trying, in order:

1. `<name>.<os>-<arch>.<ext>`  (e.g. `my-gate.linux-x86_64.so`)
2. `lib<name>.<ext>`
3. `<name>.<ext>`

```toml
[[middleware]]
library = "my-gate"    # resolves my-gate.linux-x86_64.so / libmy-gate.so / my-gate.so
order   = 20
```

> **Avoid the official names.** Because the builtin registry is consulted
> first, naming your module `jwt`, `redirect`, `ratelimit`, etc. mounts the
> **built-in** module, not yours. Give a custom module its own name (or mount it
> by explicit path).

The Linux release binaries are glibc-dynamic and can `dlopen` these modules;
a custom fully-static build cannot, and would need the module compiled in
instead.

## Layout

```
crates/
  ephpm-middleware-basic-auth         HTTP Basic whole-site gate    (declare!(BasicAuth))
  ephpm-middleware-api-key            request-phase auth gate + KV  (declare!(ApiKey))
  ephpm-middleware-redirect           canonical-URL redirect        (declare!(Redirect))
  ephpm-middleware-header-transform   response phase                (declare!(HeaderTransform, response))
```

## CI

`.github/workflows/ci.yml` runs fmt, clippy (pedantic, warnings-as-errors),
tests, and a release build on every PR and push to main — so the examples don't
rot. Runners are GitHub-hosted (pure Rust, no PHP SDK).

## License

MIT — see [LICENSE](LICENSE).
