use native_tls::{TlsConnector as NativeTlsConnector, Protocol};
use slinger::{CustomTlsConnector, CustomTlsStream, MaybeTlsStream, PeerCertificate, Result, Socket};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream as NativeTlsStream};

#[derive(Debug)]
struct NativeTlsStreamWrapper {
    inner: NativeTlsStream<TcpStream>,
}

impl NativeTlsStreamWrapper {
    fn new(stream: NativeTlsStream<TcpStream>) -> Self {
        Self { inner: stream }
    }
}

impl CustomTlsStream for NativeTlsStreamWrapper {
    fn peer_certificate(&self) -> Option<PeerCertificate> {
        self.inner
            .get_ref()
            .peer_certificate()
            .ok()
            .flatten()
            .and_then(|cert| cert.to_der().ok())
            .map(|der| PeerCertificate { inner: der })
    }
}

impl AsyncRead for NativeTlsStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NativeTlsStreamWrapper {
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

pub struct NativeTlsConnectorWrapper {
    connector: TokioTlsConnector,
}

impl NativeTlsConnectorWrapper {
    pub fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Self::with_legacy_support()
    }

    pub fn with_legacy_support() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let connector = NativeTlsConnector::builder()
            .min_protocol_version(Some(Protocol::Tlsv10))
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        
        Ok(Self {
            connector: TokioTlsConnector::from(connector),
        })
    }
}

impl CustomTlsConnector for NativeTlsConnectorWrapper {
    fn connect<'a>(
        &'a self,
        domain: &'a str,
        stream: Socket,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Socket>> + Send + 'a>> {
        let connector = self.connector.clone();
        let domain = domain.to_string();

        Box::pin(async move {
            let tcp_stream = match stream.inner {
                MaybeTlsStream::Tcp(tcp) => tcp,
                _ => {
                    return Err(slinger::Error::Other(
                        "Expected plain TCP stream for TLS upgrade".to_string(),
                    ));
                }
            };

            let tls_stream = connector
                .connect(&domain, tcp_stream)
                .await
                .map_err(|e| slinger::Error::Other(e.to_string()))?;

            let custom_stream = NativeTlsStreamWrapper::new(tls_stream);

            Ok(Socket::new(
                MaybeTlsStream::Custom(Box::new(custom_stream)),
                stream.read_timeout,
                stream.write_timeout,
            ))
        })
    }
}


