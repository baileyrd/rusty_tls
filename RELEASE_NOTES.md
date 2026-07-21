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
