# Release Notes

<!--
Two variants, pick the one that fits this repo's actual unit of change:

1. No version tags yet (pre-1.0, nothing published) — track by PR instead, same way
   AISF does it: one entry per merged PR against main, reverse chronological, each
   linking to its PR and (where one exists) to the doc that covers the change in full
   detail. Use "## PR #N — <summary>" headers.

2. Actual version tags exist — use "## vX.Y.Z - YYYY-MM-DD" headers instead, each
   linking to the PRs it shipped and a compare link to the previous tag. Add an
   "### Upgrade notes" subsection under any entry with a breaking change.

Either way, keep the tone AISF's file uses: bolded category tags inline in the
bullet (**Added:** / **Changed:** / **Fixed:**), not separate subheaders per
category — and state known limitations or deliberate scope cuts plainly instead of
leaving them implied.
-->

Tracked by PR against main, reverse chronological, one entry per merged PR.

---

## Add `AsyncTlsServerStream`: async server-side TLS adapter (feature `rusty-tokio`)
**2026-07-23**

- **Added:** `AsyncTlsServerStream<S: AsyncRead + AsyncWrite>`, the async
  counterpart to `TlsServerStream` — produced by the new
  `TlsAcceptor::accept_async(io)`, driving the same sans-IO
  `rustls::ServerConnection` over `rusty_tokio`'s poll-based I/O the way
  `AsyncTlsStream` already does on the client side. Same lazy-handshake
  shape, plus an async `complete_handshake()`.
- **Context:** closes a gap tracked against `ARCHITECTURE.md`'s Non-goals
  list (parity-loop run). Built without a confirmed live consumer today —
  an explicit, requested exception to this project's usual consumer-gating
  discipline, same as the sync server adapter's own history.
- **Bug caught during implementation:** the first `complete_handshake`
  draft reused the client adapter's `poll_complete_io` loop directly, which
  exits only once `wants_read()` goes false — but that stays true
  indefinitely on an idle, already-established connection (a live
  connection always "wants" more incoming bytes). Awaited directly, that
  loop would block forever past the point the handshake actually finished.
  Fixed with a dedicated `poll_handshake` that checks `is_handshaking()`
  before every I/O round instead, the same condition
  `rustls::Connection::complete_io` uses internally for the sync adapters.
- **Tests:** 2 new hermetic tests, including a full async-client-against-
  async-server round trip. All 18 tests (7 sync client + 4 async client +
  4 sync server + 2 async server + 1 doctest) passing; `cargo clippy
  --all-targets --all-features -- -D warnings` and `cargo fmt --check`
  both clean.

## Add server-side TLS: `TlsAcceptor`/`TlsServerStream`
**2026-07-21**

- **Added:** `TlsAcceptor::new(cert_chain_der, private_key_der)` (builds
  the server config once — no client-certificate authentication, matching
  the client side's own MVP scope; the private key format is
  auto-detected among PKCS#8/PKCS#1/SEC1) and `TlsAcceptor::accept(sock)`,
  which produces a `TlsServerStream<S>` — the server counterpart to
  `TlsStream`, same lazy-handshake shape, same `complete_handshake()`.
  `Error::InvalidPrivateKey` covers the one new failure mode (key isn't
  valid DER in any recognized format).
- **Known limitation, stated plainly:** sync only — no async server
  adapter yet (nothing drives `ServerConnection` over `rusty_tokio`). No
  client-certificate authentication (mTLS) on either side. Built without a
  confirmed live consumer today (`rusty_rdp`'s existing server-side code
  works fine on raw `rustls` and wasn't required to migrate; `rusty_llama`'s
  server TLS shape, flagged in this project's design record, has never
  been verified against its actual source) — an explicit, requested
  exception to this project's usual consumer-gating discipline, not a
  quiet one.
- **Tests:** 4 new hermetic tests, including a full client↔server
  round trip using this crate's own `TlsStream` against its own
  `TlsAcceptor`/`TlsServerStream` — proving the two halves interoperate,
  not just that each compiles in isolation. All 16 tests (7 sync client +
  4 async client + 4 server + 1 doctest) passing; `cargo clippy
  --all-targets --all-features -- -D warnings` and `cargo fmt --check`
  both clean.

## Add `TlsStream::complete_handshake`/`peer_certificate_der`
**2026-07-21**

- **Added:** `TlsStream::complete_handshake()` (blocks until the
  handshake finishes, without requiring the caller to send/expect
  application data first) and `TlsStream::peer_certificate_der()` (the
  peer's end-entity certificate, as raw DER bytes — never a parsed
  rustls type, keeping the seam intact). Driven by a real, named
  consumer: `rusty_rdp`'s CredSSP exchange needs the server's public key
  for channel binding *before* the CredSSP bytes go over the wire, which
  the sync adapter had no way to give it without exposing rustls
  internals directly.
- Sync adapter only (`TlsStream`, not `AsyncTlsStream`) — no async
  consumer has needed this yet; add it there if and when one does,
  rather than speculatively now.
- **Tests:** 1 new hermetic test (handshake starts pending, completes on
  `complete_handshake()`, exposes the expected DER, and the connection
  remains fully usable for application data afterward). All 12 tests
  (7 sync + 4 async + 1 doctest) passing; `cargo clippy --all-targets
  --all-features -- -D warnings` and `cargo fmt --check` both clean.

## Add the async adapter (`AsyncTlsStream`, feature `rusty-tokio`)
**2026-07-21**

- **Added:** `AsyncTlsStream<S: AsyncRead + AsyncWrite>`, driving the same
  sans-IO `rustls::ClientConnection` the sync `TlsStream` uses, but over
  `rusty_tokio`'s poll-based `AsyncRead`/`AsyncWrite` and reactor instead
  of blocking I/O. Same `TrustPolicy`, same constructor shape, same "never
  dials" rule. Gated behind a new `rusty-tokio` feature (off by default) so
  a sync-only consumer never pulls in `rusty_tokio`.
- **Added:** a hermetic async handshake test suite mirroring the sync
  one — success + round-trip, `DangerNoVerification`, wrong-hostname
  rejection, untrusted-root rejection — run via `#[rusty_tokio::test]`
  against a plain sync rustls server on a background thread (only the
  client side is what this adapter is responsible for).
- **Implementation note:** rustls has no built-in poll-based adapter (it
  only ships the sans-IO connection plus the blocking `rustls::Stream`),
  so this crate's own `poll_complete_io` drive loop plus a small
  `PollAdapter` (translates `Poll::Pending` to `io::ErrorKind::WouldBlock`
  for rustls' synchronous `read_tls`/`write_tls` to see, the same
  translation tokio-rustls uses) had to be written — not reused from
  anywhere.
- **Tests:** 4 new tests, all passing; `cargo clippy --all-targets
  --all-features -- -D warnings` and `cargo fmt --check` both clean.
- This completes sequencing step 3 from the project handoff. Remaining:
  the `rusty_request` and `rusty_rdp` consumer PRs (steps 4–5), and the
  follow-up rows in step 6.

## Bootstrap the library: sync TLS client, TrustPolicy, hermetic tests
**2026-07-21**

- **Added:** the crate's first real code. `TlsStream<S: Read + Write>` (a
  sync TLS client adapter wrapping `rustls::Stream` internally) and
  `TrustPolicy` (`System` via `rustls-native-certs`, `PinnedAnchors` for
  hermetic tests/private CAs, `DangerNoVerification` for out-of-band-trust
  deployments like RDP) — the two pieces `rusty_rdp`'s eventual migration
  and `rusty_request`'s `https://` support both need. No rustls type is
  part of the public API.
- **Added:** a hermetic handshake test suite (no network, no real CA) —
  one success path plus four rejection tests (wrong hostname, expired
  cert, untrusted root, zero pinned anchors), deliberately outnumbering
  the happy path per the design record's point that TLS failures are
  silent by default.
- **Known limitation, stated plainly:** client-only — no server-side TLS,
  no async adapter yet (`rusty_tokio` integration is the next real
  consumer-forcing step), no ALPN/session resumption/client-cert auth.
  `Csprng` integration (mirroring `rusty_rdp`'s pattern) was considered and
  dropped: rustls brings its own RNG, and this crate has no real call site
  that needs one — see `ARCHITECTURE.md`'s Non-goals rather than carrying
  a speculative feature.
- **Tests:** 6 new tests (1 unit-style config-validation test + 5
  integration tests against a local rustls test server); all passing,
  0 ignored. `cargo clippy --all-targets --all-features -- -D warnings`
  and `cargo fmt --check` both clean.

## Add basic CI workflow
**2026-07-21**

- **Added:** `.github/workflows/ci.yml` running `cargo fmt --check`, `clippy
  -D warnings`, `build`, and `test` on push to `main` and on PRs.
- **Known limitation:** no `Cargo.toml`/source exists yet, so the Rust steps
  are gated behind a `Cargo.toml` existence check and no-op for now — they'll
  start running for real once source lands, with nothing further to wire up.

## Repo governance setup
**2026-07-21**

- **Added:** standard governance file set (PR/issue templates, CONTRIBUTING,
  CODE_OF_CONDUCT, SECURITY, CHANGELOG, RELEASE_NOTES, ARCHITECTURE, ADR seed)
  via repo-config, and filled in README with a real description and dev
  commands.
- **Known limitation:** repo has no Cargo.toml or source yet — README's
  "Getting started" and ARCHITECTURE's boundary table are placeholders until
  actual code lands. Security contact is a personal email, not a team alias.
