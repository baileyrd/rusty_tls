//! One TLS implementation, one trust policy, for the whole rusty ecosystem.
//!
//! `rusty_tls` wraps [rustls](https://docs.rs/rustls) behind a seam: callers
//! import this crate, never `rustls` directly. That's the whole point —
//! what sits behind the seam can change later (a different backend, native
//! OS verification on some platforms) without any consumer changing a line.
//!
//! # Scope
//!
//! Client side: [`TlsStream`], a sync adapter layered over any
//! `Read + Write` stream, plus [`TrustPolicy`], the one place trust
//! decisions are made. `new_with_client_identity` presents a client
//! certificate (mTLS) to a server that requests one; `new_with_alpn` offers
//! ALPN protocols (read back via `negotiated_alpn_protocol`). Behind the
//! `rusty-tokio` feature, [`AsyncTlsStream`] is the same thing over
//! `rusty_tokio`'s `AsyncRead + AsyncWrite`.
//!
//! Server side: [`TlsAcceptor`] (a certificate + private key, built once)
//! and [`TlsServerStream`], the sync per-connection wrapper it produces.
//! `new_with_client_auth` additionally requires and verifies a client
//! certificate against caller-supplied client-CA roots, pairing with the
//! client side's `new_with_client_identity` for full mTLS; `new_with_alpn`
//! mirrors the client side's ALPN support. Behind the `rusty-tokio`
//! feature, [`AsyncTlsServerStream`] is the async counterpart, produced by
//! [`TlsAcceptor::accept_async`] — see the crate's `ARCHITECTURE.md` for
//! the full roadmap and what's deliberately not built.
//!
//! # Example
//!
//! ```no_run
//! use std::net::TcpStream;
//! use std::io::Write;
//! use rusty_tls::{TlsStream, TrustPolicy};
//!
//! let sock = TcpStream::connect("example.com:443")?;
//! let mut tls = TlsStream::new(sock, "example.com", &TrustPolicy::System)?;
//! tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#[cfg(feature = "rusty-tokio")]
mod async_client;
#[cfg(feature = "rusty-tokio")]
mod async_server;
mod client;
mod danger;
mod error;
mod server;
mod trust;

#[cfg(feature = "rusty-tokio")]
pub use async_client::AsyncTlsStream;
#[cfg(feature = "rusty-tokio")]
pub use async_server::AsyncTlsServerStream;
pub use client::TlsStream;
pub use error::Error;
pub use server::{TlsAcceptor, TlsServerStream};
pub use trust::TrustPolicy;
