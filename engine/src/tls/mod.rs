pub mod native;
pub mod rustls_impl;

use slinger::{CustomTlsConnector, ConnectorBuilder, ClientBuilder};
use std::sync::Arc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

#[cfg_attr(feature = "mcp", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsBackend {
    #[serde(rename = "native")]
    Native,
    #[serde(rename = "rustls")]
    Rustls,
}

impl Default for TlsBackend {
    fn default() -> Self {
        TlsBackend::Native
    }
}

impl std::str::FromStr for TlsBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" | "native-tls" => Ok(TlsBackend::Native),
            "rustls" => Ok(TlsBackend::Rustls),
            _ => Err(format!("Unknown TLS backend: {}. Valid options are: native, rustls", s))
        }
    }
}

impl std::fmt::Display for TlsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsBackend::Native => write!(f, "native-tls"),
            TlsBackend::Rustls => write!(f, "rustls"),
        }
    }
}

static NATIVE_TLS_CONNECTOR: Lazy<Arc<native::NativeTlsConnectorWrapper>> = Lazy::new(|| {
    Arc::new(
        native::NativeTlsConnectorWrapper::with_legacy_support()
            .unwrap_or_else(|err| {
                log::warn!("Failed to create TLS connector with legacy support: {}", err);
                log::info!("Falling back to standard TLS connector");
                native::NativeTlsConnectorWrapper::new()
                    .expect("Failed to create native-tls connector")
            })
    )
});

static RUSTLS_CONNECTOR: Lazy<Arc<rustls_impl::RustlsConnectorWrapper>> = Lazy::new(|| {
    Arc::new(
        rustls_impl::RustlsConnectorWrapper::with_dangerous_config()
            .expect("Failed to create rustls connector")
    )
});

pub fn get_tls_connector(backend: TlsBackend) -> Arc<dyn CustomTlsConnector> {
    match backend {
        TlsBackend::Native => NATIVE_TLS_CONNECTOR.clone() as Arc<dyn CustomTlsConnector>,
        TlsBackend::Rustls => RUSTLS_CONNECTOR.clone() as Arc<dyn CustomTlsConnector>,
    }
}

pub fn configure_connector_builder(
    backend: TlsBackend,
    builder: ConnectorBuilder,
) -> ConnectorBuilder {
    builder.custom_tls_connector(get_tls_connector(backend))
}

pub fn configure_client_builder(
    backend: TlsBackend,
    builder: ClientBuilder,
    proxy: Option<&slinger::Proxy>,
) -> ClientBuilder {
    let tls_connector = get_tls_connector(backend);
    let mut connector_builder = ConnectorBuilder::default()
        .custom_tls_connector(tls_connector);

    if let Some(proxy) = proxy {
        connector_builder = connector_builder.proxy(Some(proxy.clone()));
    }

    builder.connector_builder(connector_builder)
}

pub fn get_backend_info(backend: TlsBackend) -> String {
    match backend {
        TlsBackend::Native => {
            #[cfg(target_os = "windows")]
            let info = "SChannel (Windows native)";
            #[cfg(target_os = "macos")]
            let info = "Secure Transport (macOS native)";
            #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
            let info = "OpenSSL (Linux/Unix)";
            
            format!("Native-TLS ({})", info)
        },
        TlsBackend::Rustls => {
            "Rustls (Pure Rust implementation)".to_string()
        }
    }
}
