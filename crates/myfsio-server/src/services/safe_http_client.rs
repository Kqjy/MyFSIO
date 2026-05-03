use std::sync::Arc;
use std::sync::Once;

static INSTALL_PROVIDER: Once = Once::new();

fn ensure_crypto_provider() {
    INSTALL_PROVIDER.call_once(|| {
        // Idempotent: only the first installation across the process succeeds;
        // subsequent attempts return Err which we deliberately ignore.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use aws_smithy_runtime_api::client::http::{
    HttpConnector as SmithyHttpConnector, HttpConnectorFuture, SharedHttpClient,
    SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_types::body::SdkBody;
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use hyper_rustls::HttpsConnector;

use crate::services::safe_resolver::SafeResolver;

type SafeHyperClient = HyperClient<HttpsConnector<HttpConnector<SafeResolver>>, SdkBody>;

#[derive(Debug)]
struct SafeConnector {
    inner: Arc<SafeHyperClient>,
}

impl SmithyHttpConnector for SafeConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let client = self.inner.clone();
        HttpConnectorFuture::new(async move {
            let hyper_request: http::Request<SdkBody> = request
                .try_into_http1x()
                .map_err(|e| ConnectorError::other(Box::new(e), None))?;

            let hyper_response = client
                .request(hyper_request)
                .await
                .map_err(|e| ConnectorError::io(Box::new(e)))?;

            let (parts, body) = hyper_response.into_parts();
            let sdk_body = SdkBody::from_body_1_x(body.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                Box::new(e)
            }));
            let response = http::Response::from_parts(parts, sdk_body);
            HttpResponse::try_from(response).map_err(|e| ConnectorError::other(Box::new(e), None))
        })
    }
}

#[derive(Debug, Clone)]
pub struct SafeHttpClient {
    connector: SharedHttpConnector,
}

impl SafeHttpClient {
    pub fn new(allow_internal: bool) -> Self {
        ensure_crypto_provider();
        let resolver = SafeResolver::new(allow_internal);

        let mut http_connector = HttpConnector::new_with_resolver(resolver);
        http_connector.enforce_http(false);
        http_connector.set_nodelay(true);

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap_or_else(|_| {
                hyper_rustls::HttpsConnectorBuilder::new().with_webpki_roots()
            })
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        let hyper_client: SafeHyperClient = HyperClient::builder(TokioExecutor::new())
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build(https_connector);

        let connector = SharedHttpConnector::new(SafeConnector {
            inner: Arc::new(hyper_client),
        });
        Self { connector }
    }

    pub fn into_shared(self) -> SharedHttpClient {
        let connector = self.connector.clone();
        aws_smithy_runtime_api::client::http::http_client_fn(move |_settings, _components| {
            connector.clone()
        })
    }
}

pub fn build(allow_internal: bool) -> SharedHttpClient {
    SafeHttpClient::new(allow_internal).into_shared()
}
