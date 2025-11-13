use rustls::{ClientConfig, pki_types::ServerName};
use slinger::{CustomTlsConnector, CustomTlsStream, MaybeTlsStream, PeerCertificate, Result, Socket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream as RustlsStream;
use once_cell::sync::Lazy;

static CRYPTO_PROVIDER_INIT: Lazy<()> = Lazy::new(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
});

static SUPPORTED_VERIFY_SCHEMES: Lazy<Vec<rustls::SignatureScheme>> = Lazy::new(|| {
    vec![
        rustls::SignatureScheme::RSA_PKCS1_SHA256,
        rustls::SignatureScheme::RSA_PKCS1_SHA384,
        rustls::SignatureScheme::RSA_PKCS1_SHA512,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::RSA_PSS_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA512,
        rustls::SignatureScheme::ED25519,
    ]
});

#[derive(Debug)]
struct RustlsStreamWrapper {
    inner: RustlsStream<TcpStream>,
}

impl RustlsStreamWrapper {
    fn new(stream: RustlsStream<TcpStream>) -> Self {
        Self { inner: stream }
    }
}

impl CustomTlsStream for RustlsStreamWrapper {
    fn peer_certificate(&self) -> Option<PeerCertificate> {
        let (_, session) = self.inner.get_ref();
        session.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|cert| PeerCertificate {
                inner: cert.as_ref().to_vec()
            })
    }
}

impl AsyncRead for RustlsStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustlsStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        SUPPORTED_VERIFY_SCHEMES.clone()
    }
}

pub struct RustlsConnectorWrapper {
    connector: TlsConnector,
}

impl RustlsConnectorWrapper {
    pub fn with_dangerous_config() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Lazy::force(&CRYPTO_PROVIDER_INIT);

        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
            .with_no_client_auth();
        
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }
}

impl CustomTlsConnector for RustlsConnectorWrapper {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: Socket,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
        let connector = self.connector.clone();
        let domain_str = domain.to_string();

        Box::pin(async move {
            let tcp_stream = match stream.inner {
                MaybeTlsStream::Tcp(tcp) => tcp,
                _ => {
                    return Err(slinger::Error::Other(
                        "Expected plain TCP stream for TLS upgrade".to_string(),
                    ));
                }
            };

            let server_name = ServerName::try_from(domain_str.as_str())
                .map_err(|e| slinger::Error::Other(format!("Invalid server name: {}", e)))?
                .to_owned();

            let tls_stream = connector
                .connect(server_name, tcp_stream)
                .await
                .map_err(|e| slinger::Error::Other(e.to_string()))?;

            let custom_stream = RustlsStreamWrapper::new(tls_stream);

            Ok(Socket::new(
                MaybeTlsStream::Custom(Box::new(custom_stream)),
                stream.read_timeout,
                stream.write_timeout,
            ))
        })
    }
}
