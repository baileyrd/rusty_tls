use std::sync::Arc;

use rustls::client::WantsClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ConfigBuilder, RootCertStore};

use crate::danger::NoServerCertVerification;
use crate::error::Error;

/// How a [`TlsStream`](crate::TlsStream) decides whether to trust the
/// server it connects to. Verify-by-default: [`TrustPolicy::System`] is the
/// only variant [`Default`] produces, and the unsafe variant is named so it
/// reads as dangerous at every call site.
///
/// `#[non_exhaustive]`: new variants get added as this crate grows (e.g.
/// revocation-checking support) without that being a breaking change for
/// callers every time — match with a wildcard arm (`_ => ...`) rather than
/// exhaustively.
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub enum TrustPolicy {
    /// Verify against the operating system's trust anchors, loaded via
    /// [`rustls-native-certs`](https://docs.rs/rustls-native-certs) (Windows'
    /// ROOT store, macOS's Security.framework/keychain, or Linux's
    /// distro-specific bundle file/directory, honoring `SSL_CERT_FILE` and
    /// `SSL_CERT_DIR` first if either is set).
    ///
    /// **This is a best-effort anchor set, on every platform.** Windows'
    /// ROOT store is lazily populated (enumeration can miss roots the chain
    /// engine would fetch on demand); macOS's anchor enumeration returns
    /// built-in roots but not full keychain trust-settings semantics; a flat
    /// DER list can never express a distrust record on any platform. This
    /// is the same honest contract `rustls-native-certs` itself carries —
    /// this crate does not paper over it.
    ///
    /// Individual anchors that fail to load or parse are skipped silently
    /// (matching real-world trust stores, which routinely contain a few);
    /// only a *total* loss of anchors — zero certificates usable — is a
    /// hard error ([`Error::NoTrustAnchors`]), so a connection never
    /// silently runs with a store that trusts nothing.
    #[default]
    System,
    /// Verify against exactly these caller-supplied root certificates
    /// (DER-encoded), ignoring the OS trust store entirely. For hermetic
    /// tests or a private CA.
    ///
    /// Unlike [`TrustPolicy::System`], a certificate here that fails to
    /// parse is a hard error — the caller named these roots deliberately,
    /// so a bad one is a caller bug worth surfacing, not routine noise to
    /// skip past.
    PinnedAnchors(Vec<CertificateDer<'static>>),
    /// Accept any server certificate, unconditionally. No chain building,
    /// no expiry check, no hostname match — **no protection against an
    /// active man-in-the-middle.**
    ///
    /// Exists for servers that present self-signed certificates and rely on
    /// out-of-band trust (e.g. RDP's typical deployment) — never as a
    /// default, and never silently: every call site naming this variant is
    /// declaring, in the type system, that it isn't verifying its peer.
    DangerNoVerification,
}

/// The part of building a `ClientConfig` that's identical whether the
/// caller ends up presenting a client certificate or not: deciding how to
/// verify the *server's* certificate, per `policy`. Shared by
/// [`build_client_config`] and [`build_client_config_with_identity`] so the
/// trust decision itself only lives in one place.
fn client_config_builder(
    policy: &TrustPolicy,
) -> Result<ConfigBuilder<ClientConfig, WantsClientCert>, Error> {
    Ok(match policy {
        TrustPolicy::System => {
            let loaded = rustls_native_certs::load_native_certs();
            let mut roots = RootCertStore::empty();
            for cert in loaded.certs {
                // Best-effort per the type's documentation: a handful of
                // unparseable anchors in an OS store is normal, not fatal.
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                return Err(Error::NoTrustAnchors);
            }
            ClientConfig::builder().with_root_certificates(roots)
        }
        TrustPolicy::PinnedAnchors(certs) => {
            let mut roots = RootCertStore::empty();
            for cert in certs {
                roots.add(cert.clone())?;
            }
            if roots.is_empty() {
                return Err(Error::NoTrustAnchors);
            }
            ClientConfig::builder().with_root_certificates(roots)
        }
        TrustPolicy::DangerNoVerification => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerCertVerification::new())),
    })
}

pub(crate) fn build_client_config(policy: &TrustPolicy) -> Result<Arc<ClientConfig>, Error> {
    let config = client_config_builder(policy)?.with_no_client_auth();
    Ok(Arc::new(config))
}

/// Like [`build_client_config`], but presents `cert_chain`/`key` to the
/// server as a client certificate (mTLS) — for a server that requests and
/// verifies one, rather than the plain `with_no_client_auth()` path.
pub(crate) fn build_client_config_with_identity(
    policy: &TrustPolicy,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ClientConfig>, Error> {
    let config = client_config_builder(policy)?.with_client_auth_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

/// Like [`build_client_config`], but offers `alpn_protocols` during the
/// handshake (`rustls::ClientConfig::alpn_protocols` is a plain field set
/// after building, not part of the typestate builder chain).
pub(crate) fn build_client_config_with_alpn(
    policy: &TrustPolicy,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>, Error> {
    let mut config = client_config_builder(policy)?.with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    Ok(Arc::new(config))
}
