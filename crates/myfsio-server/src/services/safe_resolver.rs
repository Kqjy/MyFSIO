use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use reqwest::dns::{Addrs, Name as ReqwestName, Resolve, Resolving};

use crate::handlers::ui_api::reject_internal_ip;

#[derive(Clone, Debug)]
pub struct SafeResolver {
    allow_internal: bool,
}

impl SafeResolver {
    pub fn new(allow_internal: bool) -> Self {
        Self { allow_internal }
    }

    async fn lookup_filtered(
        host: String,
        allow_internal: bool,
    ) -> Result<Vec<SocketAddr>, std::io::Error> {
        let lookup = format!("{}:0", host);
        let resolved: Vec<SocketAddr> = match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host(lookup),
        )
        .await
        {
            Ok(Ok(it)) => it.collect(),
            Ok(Err(e)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("DNS resolution failed for '{}': {}", host, e),
                ));
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("DNS resolution timed out for '{}'", host),
                ));
            }
        };

        let filtered: Vec<SocketAddr> = if allow_internal {
            resolved
        } else {
            let mut out = Vec::new();
            for sa in resolved {
                if let Err(reason) = reject_internal_ip(sa.ip()) {
                    tracing::warn!(
                        "SafeResolver dropped {} for host '{}': {}",
                        sa.ip(),
                        host,
                        reason
                    );
                    continue;
                }
                out.push(sa);
            }
            out
        };

        if filtered.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "all resolved addresses for '{}' were rejected by ALLOW_INTERNAL_ENDPOINTS=false",
                    host
                ),
            ));
        }

        Ok(filtered)
    }
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: ReqwestName) -> Resolving {
        let allow_internal = self.allow_internal;
        let host = name.as_str().to_string();
        Box::pin(async move {
            match Self::lookup_filtered(host, allow_internal).await {
                Ok(filtered) => {
                    let addrs: Addrs = Box::new(filtered.into_iter());
                    Ok(addrs)
                }
                Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

impl tower_service::Service<hyper_util::client::legacy::connect::dns::Name> for SafeResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: hyper_util::client::legacy::connect::dns::Name) -> Self::Future {
        let allow_internal = self.allow_internal;
        let host = name.as_str().to_string();
        Box::pin(async move {
            let filtered = Self::lookup_filtered(host, allow_internal).await?;
            Ok(filtered.into_iter())
        })
    }
}

pub fn shared(allow_internal: bool) -> Arc<SafeResolver> {
    Arc::new(SafeResolver::new(allow_internal))
}
