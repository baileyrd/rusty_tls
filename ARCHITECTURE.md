# Architecture

## Overview
`rusty_tls` gives the rusty ecosystem one TLS implementation and one trust
policy, client and server. It wraps rustls 0.23 (`ClientConnection`/
`ServerConnection`, both already sans-IO) behind a seam that hides every
rustls type from callers: a consumer names only `TlsStream`/`TlsAcceptor`/
`TlsServerStream`, `TrustPolicy`, and `Error`. Day one, the engine behind
the seam is rustls; the seam is what makes that replaceable later without
touching consumer code.

**Not goals (yet):** an async server adapter, client-certificate
authentication (mTLS) on either side, ALPN/session resumption, revocation,
or any hand-rolled cryptography — see [Non-goals](#non-goals).

## Boundaries

| Port | Adapter(s) | Notes |
| ---- | ---------- | ----- |
| Trust decision (`TrustPolicy` → `rustls::ClientConfig`) | `trust::build_client_config` | The one place a `rustls::RootCertStore`/verifier gets constructed. `System` reads OS anchors via `rustls-native-certs`; `PinnedAnchors` takes caller-supplied DER; `DangerNoVerification` installs `danger::NoServerCertVerification`. Shared by both adapters below — this is the real reusable "core." |
| Sync transport (`TlsStream<S: Read + Write>`) | `client::TlsStream` (wraps `rustls::Stream` internally) | Never dials — accepts an already-connected `S`, so protocols that run a plaintext exchange before upgrading (RDP's X.224 negotiation) can hand over a used stream. `complete_handshake()`/`peer_certificate_der()` expose just enough handshake-derived state (raw DER, never a parsed rustls type) for a consumer like RDP's CredSSP exchange that needs the peer's certificate for its own channel binding. |
| Async transport (`AsyncTlsStream<S: AsyncRead + AsyncWrite>`, feature `rusty-tokio`) | `async_client::AsyncTlsStream` | Drives the same sans-IO `rustls::ClientConnection` (`wants_read`/`wants_write`/`read_tls`/`write_tls`/`process_new_packets`) over `rusty_tokio`'s poll-based `AsyncRead`/`AsyncWrite`, via a small internal `PollAdapter` that turns `Poll::Pending` into `io::ErrorKind::WouldBlock` for rustls' synchronous `read_tls`/`write_tls` to see. `rusty_tokio` itself stays TLS-free; the dependency is optional and off by default. |
| Server config (`TlsAcceptor`) | `server::TlsAcceptor` | The server-side mirror of the trust-decision row: builds a `rustls::ServerConfig` from a certificate chain + private key (DER, any of PKCS#8/PKCS#1/SEC1, auto-detected), no client-certificate authentication. Built once, cheap to reuse (`Arc`-backed) across every accepted connection. |
| Sync server transport (`TlsServerStream<S: Read + Write>`) | `server::TlsServerStream` (wraps `rustls::Stream` internally) | The server counterpart to `TlsStream` — built via `TlsAcceptor::accept`, same lazy-handshake/`complete_handshake()` shape. No async server adapter yet (see Non-goals). |

## Structure
Single crate, modular by concern rather than a workspace — there is exactly
one artifact to ship and no team/language boundary to split across:

- `error` — the one `Error` type every fallible call returns.
- `trust` — `TrustPolicy` and the only function that turns a policy into a
  `rustls::ClientConfig`.
- `danger` — the `DangerNoVerification` verifier, isolated in its own module
  so it's never an accidental `use` away from the rest of the crate.
- `client` — `TlsStream`, the sync client adapter.
- `async_client` (feature `rusty-tokio`) — `AsyncTlsStream`, the async
  client adapter.
- `server` — `TlsAcceptor` (config) and `TlsServerStream` (the sync server
  adapter it produces).

There is no separate public sans-IO "core" type distinct from the two
adapters — `rustls::ClientConnection` already *is* the sans-IO engine, and
`trust::build_client_config` is the real shared logic (config
construction, independent of transport). Each adapter drives the same
`ClientConnection` methods (`wants_read`/`wants_write`/`read_tls`/
`write_tls`/`process_new_packets`) itself: `client::TlsStream` via
`rustls::Stream` over a blocking `Read + Write`; `async_client::AsyncTlsStream`
via its own poll loop (`poll_complete_io`) over `rusty_tokio`'s
`AsyncRead + AsyncWrite`. The two loops are similar in shape but distinct
in kind (blocking vs. `Poll`/`Waker`-driven) — sharing config construction
was the real duplication to remove; sharing the drive loop itself would
have meant forcing one adapter's I/O model onto the other.
`server::TlsServerStream` is the same shape as `client::TlsStream` again,
over `rustls::ServerConnection` instead — enough structural overlap to
notice, not enough (different rustls connection type, no shared trait
worth introducing for two call sites) to be worth abstracting over.

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

Server side mirrors this: `TlsAcceptor::new(cert_chain_der, key_der)` builds
the `rustls::ServerConfig` once (step 2's counterpart, done up front instead
of per-connection); `TlsAcceptor::accept(sock)` constructs the
`ServerConnection` for one already-accepted socket (step 2 done per
connection); the first `Read`/`Write` on the resulting `TlsServerStream`
drives the handshake exactly as step 3 describes.

## Key decisions
See [docs/adr/](./docs/adr/) for the record of individual decisions and their tradeoffs.

## Non-goals
- **An async server adapter.** The sync `TlsServerStream` exists; nothing
  yet drives the same sans-IO `ServerConnection` over `rusty_tokio`. Add
  it if/when a named async server consumer shows up (rusty_llama's
  optional server is the one flagged in this project's design record, but
  its actual TLS shape hasn't been verified against source).
- **ALPN, session resumption, client certificates (mTLS), revocation,
  kTLS offload.** Out of scope for the MVP, client or server side; add
  only if a named consumer needs one, the same consumer-gate discipline
  rustils applies to its own primitives.
- **Any hand-rolled cryptography, ever, as the default.** rustls stays the
  engine. If a future differential-testing experiment wants to explore an
  alternative backend behind the same seam, that happens explicitly,
  never silently promoted to default.
