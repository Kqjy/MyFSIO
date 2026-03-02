import hashlib
import io
import os
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import myfsio_core as _rc
    HAS_RUST = True
except ImportError:
    _rc = None
    HAS_RUST = False

pytestmark = pytest.mark.skipif(not HAS_RUST, reason="myfsio_core not available")


class TestStreamToFileWithMd5:
    def test_basic_write(self, tmp_path):
        data = b"hello world" * 1000
        stream = io.BytesIO(data)
        tmp_dir = str(tmp_path / "tmp")

        tmp_path_str, md5_hex, size = _rc.stream_to_file_with_md5(stream, tmp_dir)

        assert size == len(data)
        assert md5_hex == hashlib.md5(data).hexdigest()
        assert Path(tmp_path_str).exists()
        assert Path(tmp_path_str).read_bytes() == data

    def test_empty_stream(self, tmp_path):
        stream = io.BytesIO(b"")
        tmp_dir = str(tmp_path / "tmp")

        tmp_path_str, md5_hex, size = _rc.stream_to_file_with_md5(stream, tmp_dir)

        assert size == 0
        assert md5_hex == hashlib.md5(b"").hexdigest()
        assert Path(tmp_path_str).read_bytes() == b""

    def test_large_data(self, tmp_path):
        data = os.urandom(1024 * 1024 * 2)
        stream = io.BytesIO(data)
        tmp_dir = str(tmp_path / "tmp")

        tmp_path_str, md5_hex, size = _rc.stream_to_file_with_md5(stream, tmp_dir)

        assert size == len(data)
        assert md5_hex == hashlib.md5(data).hexdigest()

    def test_custom_chunk_size(self, tmp_path):
        data = b"x" * 10000
        stream = io.BytesIO(data)
        tmp_dir = str(tmp_path / "tmp")

        tmp_path_str, md5_hex, size = _rc.stream_to_file_with_md5(
            stream, tmp_dir, chunk_size=128
        )

        assert size == len(data)
        assert md5_hex == hashlib.md5(data).hexdigest()


class TestAssemblePartsWithMd5:
    def test_basic_assembly(self, tmp_path):
        parts = []
        combined = b""
        for i in range(3):
            data = f"part{i}data".encode() * 100
            combined += data
            p = tmp_path / f"part{i}"
            p.write_bytes(data)
            parts.append(str(p))

        dest = str(tmp_path / "output")
        md5_hex = _rc.assemble_parts_with_md5(parts, dest)

        assert md5_hex == hashlib.md5(combined).hexdigest()
        assert Path(dest).read_bytes() == combined

    def test_single_part(self, tmp_path):
        data = b"single part data"
        p = tmp_path / "part0"
        p.write_bytes(data)

        dest = str(tmp_path / "output")
        md5_hex = _rc.assemble_parts_with_md5([str(p)], dest)

        assert md5_hex == hashlib.md5(data).hexdigest()
        assert Path(dest).read_bytes() == data

    def test_empty_parts_list(self):
        with pytest.raises(ValueError, match="No parts"):
            _rc.assemble_parts_with_md5([], "dummy")

    def test_missing_part_file(self, tmp_path):
        with pytest.raises(OSError):
            _rc.assemble_parts_with_md5(
                [str(tmp_path / "nonexistent")], str(tmp_path / "out")
            )

    def test_large_parts(self, tmp_path):
        parts = []
        combined = b""
        for i in range(5):
            data = os.urandom(512 * 1024)
            combined += data
            p = tmp_path / f"part{i}"
            p.write_bytes(data)
            parts.append(str(p))

        dest = str(tmp_path / "output")
        md5_hex = _rc.assemble_parts_with_md5(parts, dest)

        assert md5_hex == hashlib.md5(combined).hexdigest()
        assert Path(dest).read_bytes() == combined


class TestEncryptDecryptStreamChunked:
    def _python_derive_chunk_nonce(self, base_nonce, chunk_index):
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=base_nonce,
            info=chunk_index.to_bytes(4, "big"),
        )
        return hkdf.derive(b"chunk_nonce")

    def test_encrypt_decrypt_roundtrip(self, tmp_path):
        data = b"Hello, encryption!" * 500
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)

        input_path = str(tmp_path / "plaintext")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(data)

        chunk_count = _rc.encrypt_stream_chunked(
            input_path, encrypted_path, key, base_nonce
        )
        assert chunk_count > 0

        chunk_count_dec = _rc.decrypt_stream_chunked(
            encrypted_path, decrypted_path, key, base_nonce
        )
        assert chunk_count_dec == chunk_count
        assert Path(decrypted_path).read_bytes() == data

    def test_empty_file(self, tmp_path):
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)

        input_path = str(tmp_path / "empty")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(b"")

        chunk_count = _rc.encrypt_stream_chunked(
            input_path, encrypted_path, key, base_nonce
        )
        assert chunk_count == 0

        chunk_count_dec = _rc.decrypt_stream_chunked(
            encrypted_path, decrypted_path, key, base_nonce
        )
        assert chunk_count_dec == 0
        assert Path(decrypted_path).read_bytes() == b""

    def test_custom_chunk_size(self, tmp_path):
        data = os.urandom(10000)
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)

        input_path = str(tmp_path / "plaintext")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(data)

        chunk_count = _rc.encrypt_stream_chunked(
            input_path, encrypted_path, key, base_nonce, chunk_size=1024
        )
        assert chunk_count == 10

        _rc.decrypt_stream_chunked(encrypted_path, decrypted_path, key, base_nonce)
        assert Path(decrypted_path).read_bytes() == data

    def test_invalid_key_length(self, tmp_path):
        input_path = str(tmp_path / "in")
        Path(input_path).write_bytes(b"data")

        with pytest.raises(ValueError, match="32 bytes"):
            _rc.encrypt_stream_chunked(
                input_path, str(tmp_path / "out"), b"short", secrets.token_bytes(12)
            )

    def test_invalid_nonce_length(self, tmp_path):
        input_path = str(tmp_path / "in")
        Path(input_path).write_bytes(b"data")

        with pytest.raises(ValueError, match="12 bytes"):
            _rc.encrypt_stream_chunked(
                input_path, str(tmp_path / "out"), secrets.token_bytes(32), b"short"
            )

    def test_wrong_key_fails_decrypt(self, tmp_path):
        data = b"sensitive data"
        key = secrets.token_bytes(32)
        wrong_key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)

        input_path = str(tmp_path / "plaintext")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(data)
        _rc.encrypt_stream_chunked(input_path, encrypted_path, key, base_nonce)

        with pytest.raises((ValueError, OSError)):
            _rc.decrypt_stream_chunked(
                encrypted_path, decrypted_path, wrong_key, base_nonce
            )

    def test_cross_compat_python_encrypt_rust_decrypt(self, tmp_path):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data = b"cross compat test data" * 100
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)
        chunk_size = 1024

        encrypted_path = str(tmp_path / "py_encrypted")
        with open(encrypted_path, "wb") as f:
            f.write(b"\x00\x00\x00\x00")
            aesgcm = AESGCM(key)
            chunk_index = 0
            offset = 0
            while offset < len(data):
                chunk = data[offset:offset + chunk_size]
                nonce = self._python_derive_chunk_nonce(base_nonce, chunk_index)
                enc = aesgcm.encrypt(nonce, chunk, None)
                f.write(len(enc).to_bytes(4, "big"))
                f.write(enc)
                chunk_index += 1
                offset += chunk_size
            f.seek(0)
            f.write(chunk_index.to_bytes(4, "big"))

        decrypted_path = str(tmp_path / "rust_decrypted")
        _rc.decrypt_stream_chunked(encrypted_path, decrypted_path, key, base_nonce)
        assert Path(decrypted_path).read_bytes() == data

    def test_cross_compat_rust_encrypt_python_decrypt(self, tmp_path):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data = b"cross compat reverse test" * 100
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)
        chunk_size = 1024

        input_path = str(tmp_path / "plaintext")
        encrypted_path = str(tmp_path / "rust_encrypted")
        Path(input_path).write_bytes(data)

        chunk_count = _rc.encrypt_stream_chunked(
            input_path, encrypted_path, key, base_nonce, chunk_size=chunk_size
        )

        aesgcm = AESGCM(key)
        with open(encrypted_path, "rb") as f:
            count_bytes = f.read(4)
            assert int.from_bytes(count_bytes, "big") == chunk_count

            decrypted = b""
            for i in range(chunk_count):
                size = int.from_bytes(f.read(4), "big")
                enc_chunk = f.read(size)
                nonce = self._python_derive_chunk_nonce(base_nonce, i)
                decrypted += aesgcm.decrypt(nonce, enc_chunk, None)

        assert decrypted == data

    def test_large_file_roundtrip(self, tmp_path):
        data = os.urandom(1024 * 1024)
        key = secrets.token_bytes(32)
        base_nonce = secrets.token_bytes(12)

        input_path = str(tmp_path / "large")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(data)

        _rc.encrypt_stream_chunked(input_path, encrypted_path, key, base_nonce)
        _rc.decrypt_stream_chunked(encrypted_path, decrypted_path, key, base_nonce)

        assert Path(decrypted_path).read_bytes() == data


class TestStreamingEncryptorFileMethods:
    def test_encrypt_file_decrypt_file_roundtrip(self, tmp_path):
        from app.encryption import LocalKeyEncryption, StreamingEncryptor

        master_key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(master_key_path)
        encryptor = StreamingEncryptor(provider, chunk_size=512)

        data = b"file method test data" * 200
        input_path = str(tmp_path / "input")
        encrypted_path = str(tmp_path / "encrypted")
        decrypted_path = str(tmp_path / "decrypted")

        Path(input_path).write_bytes(data)

        metadata = encryptor.encrypt_file(input_path, encrypted_path)
        assert metadata.algorithm == "AES256"

        encryptor.decrypt_file(encrypted_path, decrypted_path, metadata)
        assert Path(decrypted_path).read_bytes() == data

    def test_encrypt_file_matches_encrypt_stream(self, tmp_path):
        from app.encryption import LocalKeyEncryption, StreamingEncryptor

        master_key_path = tmp_path / "master.key"
        provider = LocalKeyEncryption(master_key_path)
        encryptor = StreamingEncryptor(provider, chunk_size=512)

        data = b"stream vs file comparison" * 100
        input_path = str(tmp_path / "input")
        Path(input_path).write_bytes(data)

        file_encrypted_path = str(tmp_path / "file_enc")
        metadata_file = encryptor.encrypt_file(input_path, file_encrypted_path)

        file_decrypted_path = str(tmp_path / "file_dec")
        encryptor.decrypt_file(file_encrypted_path, file_decrypted_path, metadata_file)
        assert Path(file_decrypted_path).read_bytes() == data

        stream_enc, metadata_stream = encryptor.encrypt_stream(io.BytesIO(data))
        stream_dec = encryptor.decrypt_stream(stream_enc, metadata_stream)
        assert stream_dec.read() == data
