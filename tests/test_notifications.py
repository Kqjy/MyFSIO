import json
import time
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.notifications import (
    NotificationConfiguration,
    NotificationEvent,
    NotificationService,
    WebhookDestination,
)


class TestNotificationEvent:
    def test_default_values(self):
        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="test-bucket",
            object_key="test/key.txt",
        )
        assert event.event_name == "s3:ObjectCreated:Put"
        assert event.bucket_name == "test-bucket"
        assert event.object_key == "test/key.txt"
        assert event.object_size == 0
        assert event.etag == ""
        assert event.version_id is None
        assert event.request_id != ""

    def test_to_s3_event(self):
        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="my-bucket",
            object_key="my/object.txt",
            object_size=1024,
            etag="abc123",
            version_id="v1",
            source_ip="192.168.1.1",
            user_identity="user123",
        )
        result = event.to_s3_event()

        assert "Records" in result
        assert len(result["Records"]) == 1

        record = result["Records"][0]
        assert record["eventVersion"] == "2.1"
        assert record["eventSource"] == "myfsio:s3"
        assert record["eventName"] == "s3:ObjectCreated:Put"
        assert record["s3"]["bucket"]["name"] == "my-bucket"
        assert record["s3"]["object"]["key"] == "my/object.txt"
        assert record["s3"]["object"]["size"] == 1024
        assert record["s3"]["object"]["eTag"] == "abc123"
        assert record["s3"]["object"]["versionId"] == "v1"
        assert record["userIdentity"]["principalId"] == "user123"
        assert record["requestParameters"]["sourceIPAddress"] == "192.168.1.1"


class TestWebhookDestination:
    def test_default_values(self):
        dest = WebhookDestination(url="http://example.com/webhook")
        assert dest.url == "http://example.com/webhook"
        assert dest.headers == {}
        assert dest.timeout_seconds == 30
        assert dest.retry_count == 3
        assert dest.retry_delay_seconds == 1

    def test_to_dict(self):
        dest = WebhookDestination(
            url="http://example.com/webhook",
            headers={"X-Custom": "value"},
            timeout_seconds=60,
            retry_count=5,
            retry_delay_seconds=2,
        )
        result = dest.to_dict()
        assert result["url"] == "http://example.com/webhook"
        assert result["headers"] == {"X-Custom": "value"}
        assert result["timeout_seconds"] == 60
        assert result["retry_count"] == 5
        assert result["retry_delay_seconds"] == 2

    def test_from_dict(self):
        data = {
            "url": "http://hook.example.com",
            "headers": {"Authorization": "Bearer token"},
            "timeout_seconds": 45,
            "retry_count": 2,
            "retry_delay_seconds": 5,
        }
        dest = WebhookDestination.from_dict(data)
        assert dest.url == "http://hook.example.com"
        assert dest.headers == {"Authorization": "Bearer token"}
        assert dest.timeout_seconds == 45
        assert dest.retry_count == 2
        assert dest.retry_delay_seconds == 5


class TestNotificationConfiguration:
    def test_matches_event_exact_match(self):
        config = NotificationConfiguration(
            id="config1",
            events=["s3:ObjectCreated:Put"],
            destination=WebhookDestination(url="http://example.com"),
        )
        assert config.matches_event("s3:ObjectCreated:Put", "any/key.txt") is True
        assert config.matches_event("s3:ObjectCreated:Post", "any/key.txt") is False

    def test_matches_event_wildcard(self):
        config = NotificationConfiguration(
            id="config1",
            events=["s3:ObjectCreated:*"],
            destination=WebhookDestination(url="http://example.com"),
        )
        assert config.matches_event("s3:ObjectCreated:Put", "key.txt") is True
        assert config.matches_event("s3:ObjectCreated:Copy", "key.txt") is True
        assert config.matches_event("s3:ObjectRemoved:Delete", "key.txt") is False

    def test_matches_event_with_prefix_filter(self):
        config = NotificationConfiguration(
            id="config1",
            events=["s3:ObjectCreated:*"],
            destination=WebhookDestination(url="http://example.com"),
            prefix_filter="logs/",
        )
        assert config.matches_event("s3:ObjectCreated:Put", "logs/app.log") is True
        assert config.matches_event("s3:ObjectCreated:Put", "data/file.txt") is False

    def test_matches_event_with_suffix_filter(self):
        config = NotificationConfiguration(
            id="config1",
            events=["s3:ObjectCreated:*"],
            destination=WebhookDestination(url="http://example.com"),
            suffix_filter=".jpg",
        )
        assert config.matches_event("s3:ObjectCreated:Put", "photos/image.jpg") is True
        assert config.matches_event("s3:ObjectCreated:Put", "photos/image.png") is False

    def test_matches_event_with_both_filters(self):
        config = NotificationConfiguration(
            id="config1",
            events=["s3:ObjectCreated:*"],
            destination=WebhookDestination(url="http://example.com"),
            prefix_filter="images/",
            suffix_filter=".png",
        )
        assert config.matches_event("s3:ObjectCreated:Put", "images/photo.png") is True
        assert config.matches_event("s3:ObjectCreated:Put", "images/photo.jpg") is False
        assert config.matches_event("s3:ObjectCreated:Put", "documents/file.png") is False

    def test_to_dict(self):
        config = NotificationConfiguration(
            id="my-config",
            events=["s3:ObjectCreated:Put", "s3:ObjectRemoved:Delete"],
            destination=WebhookDestination(url="http://example.com"),
            prefix_filter="logs/",
            suffix_filter=".log",
        )
        result = config.to_dict()
        assert result["Id"] == "my-config"
        assert result["Events"] == ["s3:ObjectCreated:Put", "s3:ObjectRemoved:Delete"]
        assert "Destination" in result
        assert result["Filter"]["Key"]["FilterRules"][0]["Value"] == "logs/"
        assert result["Filter"]["Key"]["FilterRules"][1]["Value"] == ".log"

    def test_from_dict(self):
        data = {
            "Id": "parsed-config",
            "Events": ["s3:ObjectCreated:*"],
            "Destination": {"url": "http://hook.example.com"},
            "Filter": {
                "Key": {
                    "FilterRules": [
                        {"Name": "prefix", "Value": "data/"},
                        {"Name": "suffix", "Value": ".csv"},
                    ]
                }
            },
        }
        config = NotificationConfiguration.from_dict(data)
        assert config.id == "parsed-config"
        assert config.events == ["s3:ObjectCreated:*"]
        assert config.destination.url == "http://hook.example.com"
        assert config.prefix_filter == "data/"
        assert config.suffix_filter == ".csv"


@pytest.fixture
def notification_service(tmp_path: Path):
    service = NotificationService(tmp_path, worker_count=1)
    yield service
    service.shutdown()


class TestNotificationService:
    def test_get_bucket_notifications_empty(self, notification_service):
        result = notification_service.get_bucket_notifications("nonexistent-bucket")
        assert result == []

    def test_set_and_get_bucket_notifications(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="config1",
                events=["s3:ObjectCreated:*"],
                destination=WebhookDestination(url="http://example.com/webhook1"),
            ),
            NotificationConfiguration(
                id="config2",
                events=["s3:ObjectRemoved:*"],
                destination=WebhookDestination(url="http://example.com/webhook2"),
            ),
        ]
        notification_service.set_bucket_notifications("my-bucket", configs)

        retrieved = notification_service.get_bucket_notifications("my-bucket")
        assert len(retrieved) == 2
        assert retrieved[0].id == "config1"
        assert retrieved[1].id == "config2"

    def test_delete_bucket_notifications(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="to-delete",
                events=["s3:ObjectCreated:*"],
                destination=WebhookDestination(url="http://example.com"),
            ),
        ]
        notification_service.set_bucket_notifications("delete-bucket", configs)
        assert len(notification_service.get_bucket_notifications("delete-bucket")) == 1

        notification_service.delete_bucket_notifications("delete-bucket")
        notification_service._configs.clear()
        assert len(notification_service.get_bucket_notifications("delete-bucket")) == 0

    def test_emit_event_no_config(self, notification_service):
        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="no-config-bucket",
            object_key="test.txt",
        )
        notification_service.emit_event(event)
        assert notification_service._stats["events_queued"] == 0

    def test_emit_event_matching_config(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="match-config",
                events=["s3:ObjectCreated:*"],
                destination=WebhookDestination(url="http://example.com/webhook"),
            ),
        ]
        notification_service.set_bucket_notifications("event-bucket", configs)

        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="event-bucket",
            object_key="test.txt",
        )
        notification_service.emit_event(event)
        assert notification_service._stats["events_queued"] == 1

    def test_emit_event_non_matching_config(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="delete-only",
                events=["s3:ObjectRemoved:*"],
                destination=WebhookDestination(url="http://example.com/webhook"),
            ),
        ]
        notification_service.set_bucket_notifications("delete-bucket", configs)

        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="delete-bucket",
            object_key="test.txt",
        )
        notification_service.emit_event(event)
        assert notification_service._stats["events_queued"] == 0

    def test_emit_object_created(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="create-config",
                events=["s3:ObjectCreated:Put"],
                destination=WebhookDestination(url="http://example.com/webhook"),
            ),
        ]
        notification_service.set_bucket_notifications("create-bucket", configs)

        notification_service.emit_object_created(
            "create-bucket",
            "new-file.txt",
            size=1024,
            etag="abc123",
            operation="Put",
        )
        assert notification_service._stats["events_queued"] == 1

    def test_emit_object_removed(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="remove-config",
                events=["s3:ObjectRemoved:Delete"],
                destination=WebhookDestination(url="http://example.com/webhook"),
            ),
        ]
        notification_service.set_bucket_notifications("remove-bucket", configs)

        notification_service.emit_object_removed(
            "remove-bucket",
            "deleted-file.txt",
            operation="Delete",
        )
        assert notification_service._stats["events_queued"] == 1

    def test_get_stats(self, notification_service):
        stats = notification_service.get_stats()
        assert "events_queued" in stats
        assert "events_sent" in stats
        assert "events_failed" in stats

    @patch("app.notifications.requests.post")
    def test_send_notification_success(self, mock_post, notification_service):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="test-bucket",
            object_key="test.txt",
        )
        destination = WebhookDestination(url="http://example.com/webhook")

        notification_service._send_notification(event, destination)
        mock_post.assert_called_once()

    @patch("app.notifications.requests.post")
    def test_send_notification_retry_on_failure(self, mock_post, notification_service):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.return_value = mock_response

        event = NotificationEvent(
            event_name="s3:ObjectCreated:Put",
            bucket_name="test-bucket",
            object_key="test.txt",
        )
        destination = WebhookDestination(
            url="http://example.com/webhook",
            retry_count=2,
            retry_delay_seconds=0,
        )

        with pytest.raises(RuntimeError) as exc_info:
            notification_service._send_notification(event, destination)
        assert "Failed after 2 attempts" in str(exc_info.value)
        assert mock_post.call_count == 2

    def test_notification_caching(self, notification_service):
        configs = [
            NotificationConfiguration(
                id="cached-config",
                events=["s3:ObjectCreated:*"],
                destination=WebhookDestination(url="http://example.com"),
            ),
        ]
        notification_service.set_bucket_notifications("cached-bucket", configs)

        notification_service.get_bucket_notifications("cached-bucket")
        assert "cached-bucket" in notification_service._configs
