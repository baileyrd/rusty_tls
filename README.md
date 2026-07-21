# rusty_tls

One TLS implementation, one trust policy, for the whole rusty ecosystem — so
no consumer (`rusty_request`, `rusty_rdp`, and eventually `rusty_tail`) ever
rolls its own TLS again. Wraps [rustls](https://docs.rs/rustls) behind a
seam: **consumers import `rusty_tls`, never `rustls`.** That seam is the
product — what sits behind it can be replaced piece by piece later without
any consumer changing a line. See `ARCHITECTURE.md` for the full design and
`docs/design-discussion-tls.md`'s upstream record (rustils#70) for why this
repo exists and what it deliberately leaves to rustils.

## Status
Early — client-only sync adapter (`TlsStream`) and `TrustPolicy` exist, with
a hermetic rejection-test suite. No async adapter, no server-side support,
and no consumer has been migrated onto it yet.

## Getting started
```bash
git clone https://github.com/baileyrd/rusty_tls
cd rusty_tls
cargo build
```

```rust
use std::net::TcpStream;
use std::io::Write;
use rusty_tls::{TlsStream, TrustPolicy};

let sock = TcpStream::connect("example.com:443")?;
let mut tls = TlsStream::new(sock, "example.com", &TrustPolicy::System)?;
tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
```

## Architecture
See [ARCHITECTURE.md](./ARCHITECTURE.md) for boundaries, key decisions, and data flow.

## Development
```bash
cargo build
cargo test
cargo fmt && cargo clippy --all-targets --all-features -- -D warnings
```

## Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Security
See [SECURITY.md](./SECURITY.md) to report a vulnerability.

## License
Internal — not for external distribution
