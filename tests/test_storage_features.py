import io
import os
from pathlib import Path

import pytest

from app.storage import ObjectStorage, StorageError


def test_multipart_upload_round_trip(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("media")
    upload_id = storage.initiate_multipart_upload("media", "large.bin", metadata={"env": "test"})

    first_etag = storage.upload_multipart_part("media", upload_id, 1, io.BytesIO(b"hello "))
    second_etag = storage.upload_multipart_part("media", upload_id, 2, io.BytesIO(b"world"))

    meta = storage.complete_multipart_upload(
        "media",
        upload_id,
        [
            {"part_number": 1, "etag": first_etag},
            {"part_number": 2, "etag": second_etag},
        ],
    )

    assert meta.key == "large.bin"
    assert meta.size == len(b"hello world")
    assert meta.metadata == {"env": "test"}
    assert (tmp_path / "media" / "large.bin").read_bytes() == b"hello world"


def test_abort_multipart_upload(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("docs")
    upload_id = storage.initiate_multipart_upload("docs", "draft.txt")

    storage.abort_multipart_upload("docs", upload_id)

    with pytest.raises(StorageError):
        storage.upload_multipart_part("docs", upload_id, 1, io.BytesIO(b"data"))


def test_bucket_versioning_toggle_and_restore(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("history")
    assert storage.is_versioning_enabled("history") is False
    storage.set_bucket_versioning("history", True)
    assert storage.is_versioning_enabled("history") is True

    storage.put_object("history", "note.txt", io.BytesIO(b"v1"))
    storage.put_object("history", "note.txt", io.BytesIO(b"v2"))
    versions = storage.list_object_versions("history", "note.txt")
    assert versions
    assert versions[0]["size"] == len(b"v1")

    storage.delete_object("history", "note.txt")
    versions = storage.list_object_versions("history", "note.txt")
    assert len(versions) >= 2

    target_version = versions[-1]["version_id"]
    storage.restore_object_version("history", "note.txt", target_version)
    restored = (tmp_path / "history" / "note.txt").read_bytes()
    assert restored == b"v1"


def test_bucket_configuration_helpers(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("cfg")

    assert storage.get_bucket_tags("cfg") == []
    storage.set_bucket_tags("cfg", [{"Key": "env", "Value": "dev"}])
    tags = storage.get_bucket_tags("cfg")
    assert tags == [{"Key": "env", "Value": "dev"}]
    storage.set_bucket_tags("cfg", None)
    assert storage.get_bucket_tags("cfg") == []

    assert storage.get_bucket_cors("cfg") == []
    cors_rules = [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"], "AllowedHeaders": ["*"]}]
    storage.set_bucket_cors("cfg", cors_rules)
    assert storage.get_bucket_cors("cfg") == cors_rules
    storage.set_bucket_cors("cfg", None)
    assert storage.get_bucket_cors("cfg") == []

    assert storage.get_bucket_encryption("cfg") == {}
    encryption = {"Rules": [{"SSEAlgorithm": "AES256"}]}
    storage.set_bucket_encryption("cfg", encryption)
    assert storage.get_bucket_encryption("cfg") == encryption
    storage.set_bucket_encryption("cfg", None)
    assert storage.get_bucket_encryption("cfg") == {}


def test_delete_object_retries_when_locked(tmp_path, monkeypatch):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    storage.put_object("demo", "video.mp4", io.BytesIO(b"data"))

    target_path = tmp_path / "demo" / "video.mp4"
    original_unlink = Path.unlink
    attempts = {"count": 0}

    def flaky_unlink(self):
        if self == target_path and attempts["count"] < 1:
            attempts["count"] += 1
            raise PermissionError("locked")
        return original_unlink(self)

    monkeypatch.setattr(Path, "unlink", flaky_unlink)

    storage.delete_object("demo", "video.mp4")
    assert attempts["count"] == 1


def test_delete_bucket_handles_metadata_residue(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    storage.put_object("demo", "file.txt", io.BytesIO(b"data"), metadata={"env": "test"})
    storage.delete_object("demo", "file.txt")
    meta_dir = tmp_path / ".myfsio.sys" / "buckets" / "demo" / "meta"
    assert meta_dir.exists()

    storage.delete_bucket("demo")
    assert not (tmp_path / "demo").exists()
    assert not (tmp_path / ".myfsio.sys" / "buckets" / "demo").exists()


def test_delete_bucket_requires_archives_removed(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    storage.set_bucket_versioning("demo", True)
    storage.put_object("demo", "file.txt", io.BytesIO(b"data"))
    storage.delete_object("demo", "file.txt")
    versions_dir = tmp_path / ".myfsio.sys" / "buckets" / "demo" / "versions"
    assert versions_dir.exists()

    with pytest.raises(StorageError):
        storage.delete_bucket("demo")

    storage.purge_object("demo", "file.txt")
    storage.delete_bucket("demo")
    assert not (tmp_path / "demo").exists()
    assert not (tmp_path / ".myfsio.sys" / "buckets" / "demo").exists()


def test_delete_bucket_handles_multipart_residue(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    upload_id = storage.initiate_multipart_upload("demo", "file.txt")
    # Leave upload incomplete so the system multipart directory sticks around.
    multipart_dir = tmp_path / ".myfsio.sys" / "multipart" / "demo"
    assert multipart_dir.exists()
    assert (multipart_dir / upload_id).exists()

    with pytest.raises(StorageError):
        storage.delete_bucket("demo")

    storage.abort_multipart_upload("demo", upload_id)
    storage.delete_bucket("demo")
    assert not (tmp_path / "demo").exists()
    assert not multipart_dir.exists()


def test_purge_object_raises_when_file_in_use(tmp_path, monkeypatch):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    storage.put_object("demo", "clip.mp4", io.BytesIO(b"data"))

    target_path = tmp_path / "demo" / "clip.mp4"
    original_unlink = Path.unlink

    def always_locked(self):
        if self == target_path:
            raise PermissionError("still locked")
        return original_unlink(self)

    monkeypatch.setattr(Path, "unlink", always_locked)

    with pytest.raises(StorageError) as exc:
        storage.purge_object("demo", "clip.mp4")
    assert "in use" in str(exc.value)


@pytest.mark.parametrize(
    "object_key",
    [
        "../secret.txt",
        "folder/../secret.txt",
        "/absolute.txt",
        "\\backslash.txt",
        "bad\x00key",
    ],
)
def test_object_key_sanitization_blocks_traversal(object_key):
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key(object_key)


def test_object_key_length_limit_enforced():
    key = "a" * 1025
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key(key)


@pytest.mark.parametrize(
    "object_key",
    [
        ".meta/data.bin",
        ".versions/foo.bin",
        ".multipart/upload.part",
        ".myfsio.sys/system.bin",
    ],
)
def test_object_key_blocks_reserved_paths(object_key):
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key(object_key)


def test_bucket_config_filename_allowed(tmp_path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("demo")
    storage.put_object("demo", ".bucket.json", io.BytesIO(b"{}"))

    objects = storage.list_objects("demo")
    assert any(meta.key == ".bucket.json" for meta in objects)


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific filename rules")
def test_windows_filename_rules_enforced():
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key("CON/file.txt")
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key("folder/spaces ")
    with pytest.raises(StorageError):
        ObjectStorage._sanitize_object_key("C:drivepath.txt")
