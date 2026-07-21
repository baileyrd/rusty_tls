//! One TLS implementation, one trust policy, for the whole rusty ecosystem.
//!
//! `rusty_tls` wraps [rustls](https://docs.rs/rustls) behind a seam: callers
//! import this crate, never `rustls` directly. That's the whole point —
//! what sits behind the seam can change later (a different backend, native
//! OS verification on some platforms) without any consumer changing a line.
//!
//! # Scope (client only, for now)
//!
//! This crate currently provides a **client-only** sync adapter,
//! [`TlsStream`], layered over any `Read + Write` stream, plus
//! [`TrustPolicy`], the one place trust decisions are made. An async
//! adapter (over `rusty_tokio`, behind a `rusty-tokio` feature) and
//! server-side support are known future work — see the crate's
//! `ARCHITECTURE.md` for the full roadmap and what's deliberately not built
//! yet.
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

mod client;
mod danger;
mod error;
mod trust;

pub use client::TlsStream;
pub use error::Error;
pub use trust::TrustPolicy;
