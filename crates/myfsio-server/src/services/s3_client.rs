use std::time::Duration;

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_sdk_s3::config::{AppName, Region, SharedCredentialsProvider};
use aws_sdk_s3::Client;

use crate::stores::connections::RemoteConnection;

pub const REPLICATION_USER_AGENT_TAG: &str = "MyFSIO-Replication";

pub struct ClientOptions {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_attempts: u32,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(30),
            max_attempts: 2,
        }
    }
}

pub fn build_client(connection: &RemoteConnection, options: &ClientOptions) -> Client {
    let credentials = Credentials::new(
        connection.access_key.clone(),
        connection.secret_key.clone(),
        None,
        None,
        "myfsio-replication",
    );

    let timeout_config = aws_smithy_types::timeout::TimeoutConfig::builder()
        .connect_timeout(options.connect_timeout)
        .read_timeout(options.read_timeout)
        .build();

    let retry_config =
        aws_smithy_types::retry::RetryConfig::standard().with_max_attempts(options.max_attempts);

    let mut builder = aws_sdk_s3::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .credentials_provider(SharedCredentialsProvider::new(credentials))
        .region(Region::new(connection.region.clone()))
        .endpoint_url(connection.endpoint_url.clone())
        .force_path_style(true)
        .timeout_config(timeout_config)
        .retry_config(retry_config);

    if let Ok(app_name) = AppName::new(REPLICATION_USER_AGENT_TAG) {
        builder = builder.app_name(app_name);
    }

    Client::from_conf(builder.build())
}

pub fn build_health_client(connection: &RemoteConnection, options: &ClientOptions) -> Client {
    let fast_fail = ClientOptions {
        connect_timeout: options.connect_timeout,
        read_timeout: options.read_timeout,
        max_attempts: 1,
    };
    build_client(connection, &fast_fail)
}

pub async fn check_endpoint_health(client: &Client) -> bool {
    match client.list_buckets().send().await {
        Ok(_) => true,
        Err(err) => {
            tracing::warn!("Endpoint health check failed: {:?}", err);
            false
        }
    }
}

pub async fn check_target_bucket_reachable(client: &Client, target_bucket: &str) -> bool {
    match client.head_bucket().bucket(target_bucket).send().await {
        Ok(_) => true,
        Err(err) => match &err {
            aws_sdk_s3::error::SdkError::ServiceError(_)
            | aws_sdk_s3::error::SdkError::ResponseError(_) => {
                tracing::debug!(
                    "Target-bucket reachability probe for {} got a server response; treating as reachable: {:?}",
                    target_bucket,
                    err
                );
                true
            }
            _ => {
                tracing::warn!(
                    "Target-bucket reachability probe for {} failed at transport layer: {:?}",
                    target_bucket,
                    err
                );
                false
            }
        },
    }
}
