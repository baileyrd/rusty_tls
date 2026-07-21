use std::io::{self, Read, Write};

use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use crate::error::Error;
use crate::trust::{build_client_config, TrustPolicy};

/// A TLS client connection layered over any `Read + Write` stream.
///
/// Mirrors the shape of `rustls::StreamOwned<ClientConnection, S>` — the
/// pattern rusty_rdp's `tls.rs` already uses in production — but keeps
/// rustls types out of the public API. A caller of this crate only ever
/// names [`TlsStream`], [`TrustPolicy`](crate::TrustPolicy), and
/// [`Error`](crate::Error).
///
/// `S` must already be connected; this type never dials, and that's a hard
/// requirement rather than a convenience choice. Some protocols run a
/// plaintext exchange on the same socket *before* upgrading to TLS (e.g.
/// RDP's X.224 negotiation) — the stream handed to [`TlsStream::new`] may
/// already have been read from and written to, and this type must accept it
/// as-is.
pub struct TlsStream<S> {
    conn: ClientConnection,
    sock: S,
}

impl<S: Read + Write> TlsStream<S> {
    /// Wrap `sock` in a TLS client connection to `server_name`, trusted
    /// according to `policy`.
    ///
    /// Performs no I/O itself: the handshake runs lazily, driven by the
    /// first [`Read`]/[`Write`] call, exactly like [`rustls::StreamOwned`]
    /// (which this wraps internally).
    pub fn new(sock: S, server_name: &str, policy: &TrustPolicy) -> Result<Self, Error> {
        let config = build_client_config(policy)?;
        let name = ServerName::try_from(server_name.to_string())
            .map_err(|_| Error::InvalidServerName(server_name.to_string()))?;
        let conn = ClientConnection::new(config, name)?;
        Ok(Self { conn, sock })
    }

    /// Whether the TLS handshake has not yet completed.
    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// Borrow the underlying stream. Does not touch TLS state — mainly
    /// useful for inspecting the transport (e.g. peer address).
    pub fn get_ref(&self) -> &S {
        &self.sock
    }

    /// Mutably borrow the underlying stream.
    ///
    /// Reading from or writing to it directly bypasses TLS entirely and
    /// will corrupt the session — this exists for socket-option calls
    /// (e.g. `set_nodelay`), not I/O.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.sock
    }

    /// Consume `self`, returning the underlying stream. The TLS session is
    /// discarded; the stream is left wherever the last `Read`/`Write` call
    /// left it (mid-record if one was in-flight).
    pub fn into_inner(self) -> S {
        self.sock
    }
}

impl<S: Read + Write> Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).read(buf)
    }
}

impl<S: Read + Write> Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.conn, &mut self.sock).flush()
    }
}
