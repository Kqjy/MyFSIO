import io
import pytest
from pathlib import Path
from app.storage import ObjectStorage, StorageError

def test_concurrent_bucket_deletion(tmp_path: Path):
    # This is a simplified test since true concurrency is hard to simulate deterministically in this setup
    # We verify that deleting a non-existent bucket raises StorageError
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("race")
    storage.delete_bucket("race")
    
    with pytest.raises(StorageError, match="Bucket does not exist"):
        storage.delete_bucket("race")

def test_maximum_object_key_length(tmp_path: Path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("maxkey")
    
    # AWS S3 max key length is 1024 bytes (UTF-8)
    # Our implementation relies on the filesystem, so we might hit OS limits before 1024
    # But let's test a reasonably long key that should work
    long_key = "a" * 200
    storage.put_object("maxkey", long_key, io.BytesIO(b"data"))
    assert storage.get_object_path("maxkey", long_key).exists()

def test_unicode_bucket_and_object_names(tmp_path: Path):
    storage = ObjectStorage(tmp_path)
    # Bucket names must be lowercase, numbers, hyphens, periods
    # So unicode in bucket names is NOT allowed by our validation
    with pytest.raises(StorageError):
        storage.create_bucket("café")

    storage.create_bucket("unicode-test")
    # Unicode in object keys IS allowed
    key = "café/image.jpg"
    storage.put_object("unicode-test", key, io.BytesIO(b"data"))
    assert storage.get_object_path("unicode-test", key).exists()
    
    # Verify listing
    objects = storage.list_objects("unicode-test")
    assert any(o.key == key for o in objects)

def test_special_characters_in_metadata(tmp_path: Path):
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("meta-test")
    
    metadata = {"key": "value with spaces", "special": "!@#$%^&*()"}
    storage.put_object("meta-test", "obj", io.BytesIO(b"data"), metadata=metadata)
    
    meta = storage.get_object_metadata("meta-test", "obj")
    assert meta["key"] == "value with spaces"
    assert meta["special"] == "!@#$%^&*()"

def test_disk_full_scenario(tmp_path: Path, monkeypatch):
    # Simulate disk full by mocking write to fail
    storage = ObjectStorage(tmp_path)
    storage.create_bucket("full")
    
    def mock_copyfileobj(*args, **kwargs):
        raise OSError(28, "No space left on device")
        
    import shutil
    monkeypatch.setattr(shutil, "copyfileobj", mock_copyfileobj)
    
    with pytest.raises(OSError, match="No space left on device"):
        storage.put_object("full", "file", io.BytesIO(b"data"))
