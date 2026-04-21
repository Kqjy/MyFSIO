use crate::state::AppState;
use chrono::{DateTime, Utc};
use myfsio_storage::traits::StorageEngine;
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDestination {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationConfiguration {
    pub id: String,
    pub events: Vec<String>,
    pub destination: WebhookDestination,
    pub prefix_filter: String,
    pub suffix_filter: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationEvent {
    #[serde(rename = "eventVersion")]
    event_version: &'static str,
    #[serde(rename = "eventSource")]
    event_source: &'static str,
    #[serde(rename = "awsRegion")]
    aws_region: &'static str,
    #[serde(rename = "eventTime")]
    event_time: String,
    #[serde(rename = "eventName")]
    event_name: String,
    #[serde(rename = "userIdentity")]
    user_identity: serde_json::Value,
    #[serde(rename = "requestParameters")]
    request_parameters: serde_json::Value,
    #[serde(rename = "responseElements")]
    response_elements: serde_json::Value,
    s3: serde_json::Value,
}

impl NotificationConfiguration {
    pub fn matches_event(&self, event_name: &str, object_key: &str) -> bool {
        let event_match = self.events.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix('*') {
                event_name.starts_with(prefix)
            } else {
                pattern == event_name
            }
        });
        if !event_match {
            return false;
        }
        if !self.prefix_filter.is_empty() && !object_key.starts_with(&self.prefix_filter) {
            return false;
        }
        if !self.suffix_filter.is_empty() && !object_key.ends_with(&self.suffix_filter) {
            return false;
        }
        true
    }
}

pub fn parse_notification_configurations(
    xml: &str,
) -> Result<Vec<NotificationConfiguration>, String> {
    let doc = roxmltree::Document::parse(xml).map_err(|err| err.to_string())?;
    let mut configs = Vec::new();

    for webhook in doc
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "WebhookConfiguration")
    {
        let id = child_text(&webhook, "Id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let events = webhook
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "Event")
            .filter_map(|node| node.text())
            .map(|text| text.trim().to_string())
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>();

        let destination = webhook
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "Destination");
        let url = destination
            .as_ref()
            .and_then(|node| child_text(node, "Url"))
            .unwrap_or_default();
        if url.trim().is_empty() {
            return Err("Destination URL is required".to_string());
        }

        let mut prefix_filter = String::new();
        let mut suffix_filter = String::new();
        if let Some(filter) = webhook
            .children()
            .find(|node| node.is_element() && node.tag_name().name() == "Filter")
        {
            if let Some(key) = filter
                .children()
                .find(|node| node.is_element() && node.tag_name().name() == "S3Key")
            {
                for rule in key
                    .children()
                    .filter(|node| node.is_element() && node.tag_name().name() == "FilterRule")
                {
                    let name = child_text(&rule, "Name").unwrap_or_default();
                    let value = child_text(&rule, "Value").unwrap_or_default();
                    if name == "prefix" {
                        prefix_filter = value;
                    } else if name == "suffix" {
                        suffix_filter = value;
                    }
                }
            }
        }

        configs.push(NotificationConfiguration {
            id,
            events,
            destination: WebhookDestination { url },
            prefix_filter,
            suffix_filter,
        });
    }

    Ok(configs)
}

pub fn emit_object_created(
    state: &AppState,
    bucket: &str,
    key: &str,
    size: u64,
    etag: Option<&str>,
    request_id: &str,
    source_ip: &str,
    user_identity: &str,
    operation: &str,
) {
    emit_notifications(
        state.clone(),
        bucket.to_string(),
        key.to_string(),
        format!("s3:ObjectCreated:{}", operation),
        size,
        etag.unwrap_or_default().to_string(),
        request_id.to_string(),
        source_ip.to_string(),
        user_identity.to_string(),
    );
}

pub fn emit_object_removed(
    state: &AppState,
    bucket: &str,
    key: &str,
    request_id: &str,
    source_ip: &str,
    user_identity: &str,
    operation: &str,
) {
    emit_notifications(
        state.clone(),
        bucket.to_string(),
        key.to_string(),
        format!("s3:ObjectRemoved:{}", operation),
        0,
        String::new(),
        request_id.to_string(),
        source_ip.to_string(),
        user_identity.to_string(),
    );
}

fn emit_notifications(
    state: AppState,
    bucket: String,
    key: String,
    event_name: String,
    size: u64,
    etag: String,
    request_id: String,
    source_ip: String,
    user_identity: String,
) {
    tokio::spawn(async move {
        let config = match state.storage.get_bucket_config(&bucket).await {
            Ok(config) => config,
            Err(_) => return,
        };
        let raw = match config.notification {
            Some(serde_json::Value::String(raw)) => raw,
            _ => return,
        };
        let configs = match parse_notification_configurations(&raw) {
            Ok(configs) => configs,
            Err(err) => {
                tracing::warn!("Invalid notification config for bucket {}: {}", bucket, err);
                return;
            }
        };

        let record = NotificationEvent {
            event_version: "2.1",
            event_source: "myfsio:s3",
            aws_region: "local",
            event_time: format_event_time(Utc::now()),
            event_name: event_name.clone(),
            user_identity: json!({ "principalId": if user_identity.is_empty() { "ANONYMOUS" } else { &user_identity } }),
            request_parameters: json!({ "sourceIPAddress": if source_ip.is_empty() { "127.0.0.1" } else { &source_ip } }),
            response_elements: json!({
                "x-amz-request-id": request_id,
                "x-amz-id-2": request_id,
            }),
            s3: json!({
                "s3SchemaVersion": "1.0",
                "configurationId": "notification",
                "bucket": {
                    "name": bucket,
                    "ownerIdentity": { "principalId": "local" },
                    "arn": format!("arn:aws:s3:::{}", bucket),
                },
                "object": {
                    "key": key,
                    "size": size,
                    "eTag": etag,
                    "versionId": "null",
                    "sequencer": format!("{:016X}", Utc::now().timestamp_millis()),
                }
            }),
        };
        let payload = json!({ "Records": [record] });
        let client = reqwest::Client::new();

        for config in configs {
            if !config.matches_event(&event_name, &key) {
                continue;
            }
            let result = client
                .post(&config.destination.url)
                .header("content-type", "application/json")
                .json(&payload)
                .send()
                .await;
            if let Err(err) = result {
                tracing::warn!(
                    "Failed to deliver notification for {} to {}: {}",
                    event_name,
                    config.destination.url,
                    err
                );
            }
        }
    });
}

fn format_event_time(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()
}

fn child_text(node: &roxmltree::Node<'_, '_>, name: &str) -> Option<String> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
        .and_then(|child| child.text())
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_webhook_configuration() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
            <NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
              <WebhookConfiguration>
                <Id>upload</Id>
                <Event>s3:ObjectCreated:*</Event>
                <Destination><Url>https://example.com/hook</Url></Destination>
                <Filter>
                  <S3Key>
                    <FilterRule><Name>prefix</Name><Value>logs/</Value></FilterRule>
                    <FilterRule><Name>suffix</Name><Value>.txt</Value></FilterRule>
                  </S3Key>
                </Filter>
              </WebhookConfiguration>
            </NotificationConfiguration>"#;
        let configs = parse_notification_configurations(xml).unwrap();
        assert_eq!(configs.len(), 1);
        assert!(configs[0].matches_event("s3:ObjectCreated:Put", "logs/test.txt"));
        assert!(!configs[0].matches_event("s3:ObjectRemoved:Delete", "logs/test.txt"));
    }
}
