# Architecture

## Overview
`rusty_tls` gives the rusty ecosystem one TLS client implementation and one
trust policy. It wraps rustls 0.23 (`ClientConnection`, already sans-IO)
behind a seam that hides every rustls type from callers: a consumer names
only `TlsStream`, `TrustPolicy`, and `Error`. Day one, the engine behind the
seam is rustls; the seam is what makes that replaceable later without
touching consumer code.

**Not goals (yet):** server-side TLS, an async adapter, ALPN/session
resumption/client-cert auth, revocation, or any hand-rolled cryptography —
see [Non-goals](#non-goals).

## Boundaries

| Port | Adapter(s) | Notes |
| ---- | ---------- | ----- |
| Trust decision (`TrustPolicy` → `rustls::ClientConfig`) | `trust::build_client_config` | The one place a `rustls::RootCertStore`/verifier gets constructed. `System` reads OS anchors via `rustls-native-certs`; `PinnedAnchors` takes caller-supplied DER; `DangerNoVerification` installs `danger::NoServerCertVerification`. |
| Sync transport (`TlsStream<S: Read + Write>`) | `client::TlsStream` (wraps `rustls::Stream` internally) | Never dials — accepts an already-connected `S`, so protocols that run a plaintext exchange before upgrading (RDP's X.224 negotiation) can hand over a used stream. |
| Async transport (planned) | *(not built)* | Will drive the same `rustls::ClientConnection` sans-IO surface (`wants_read`/`wants_write`/`read_tls`/`write_tls`/`process_new_packets`) over `rusty_tokio`'s reactor, behind a `rusty-tokio` feature. `rusty_tokio` stays TLS-free either way. |

## Structure
Single crate, modular by concern rather than a workspace — there is exactly
one artifact to ship and no team/language boundary to split across:

- `error` — the one `Error` type every fallible call returns.
- `trust` — `TrustPolicy` and the only function that turns a policy into a
  `rustls::ClientConfig`.
- `danger` — the `DangerNoVerification` verifier, isolated in its own module
  so it's never an accidental `use` away from the rest of the crate.
- `client` — `TlsStream`, the sync adapter.

There is currently no separate public sans-IO "core" type distinct from
`TlsStream` — `rustls::ClientConnection` already *is* the sans-IO engine,
and `trust::build_client_config` is the real shared logic (config
construction, independent of transport). `TlsStream` uses
`rustls::Stream` internally to drive it over a blocking `Read + Write`.
When the async adapter is built, the sans-IO drive loop
(`wants_read`/`read_tls`/`process_new_packets`/...) will be factored into
its own module shared by both adapters — deferred until there are actually
two consumers of it, per the "don't build for a consumer that doesn't
exist yet" rule this ecosystem applies elsewhere.

## Data flow
1. Caller connects `S` (e.g. `std::net::TcpStream`) and, for protocols that
   need it, runs any pre-TLS exchange on the raw socket.
2. `TlsStream::new(sock, server_name, policy)` builds a `ClientConfig` from
   `policy` and constructs a `rustls::ClientConnection` for `server_name`.
   No I/O happens yet.
3. The first `Read`/`Write` call drives the handshake (via
   `rustls::Stream::complete_prior_io`): plaintext in, TLS records out to
   `S`, and vice versa. Every subsequent call transparently encrypts/decrypts
   application data.
4. On a verification failure (wrong hostname, expired cert, chain that
   doesn't lead to a trusted anchor), the driving `Read`/`Write` call
   returns `Err` — there is no separate `handshake()` step to skip.

## Key decisions
See [docs/adr/](./docs/adr/) for the record of individual decisions and their tradeoffs.

## Non-goals
- **Server-side TLS.** A known future need (rusty_llama's optional server,
  rdp's server half) — left room for, not built.
- **An async adapter.** Planned (behind a `rusty-tokio` feature), not yet
  built; `rusty_request`'s `https://` support depends on it.
- **ALPN, session resumption, client certificates (mTLS), revocation,
  kTLS offload.** Out of scope for the MVP; add only if a named consumer
  needs one, the same consumer-gate discipline rustils applies to its own
  primitives.
- **Any hand-rolled cryptography, ever, as the default.** rustls stays the
  engine. If a future differential-testing experiment wants to explore an
  alternative backend behind the same seam, that happens explicitly,
  never silently promoted to default.
- **A public sans-IO `Connection` type, before the async adapter exists.**
  See [Structure](#structure) — avoided for now as a speculative surface
  with no second caller.
