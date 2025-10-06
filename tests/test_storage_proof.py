"""
Test cases for the storage proof system.
"""

import os
import sys
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add privacy directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "privacy"))

from storage_proof import StorageProofClient, StorageRecord, TombstoneRecord, VerificationResult


class TestStorageProofClient:
    """Test cases for StorageProofClient."""
    
    def test_initialization(self):
        """Test storage proof client initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            assert client.storage_path.exists()
            assert client.storage_records == {}
            assert client.tombstone_records == {}
    
    def test_record_storage(self):
        """Test recording storage of a blob."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            success = client.record_storage(
                blob_hash="abc123def456",
                storage_uri="file:///tmp/test.enc",
                provider_id="local",
                region="local",
                conversation_hash="conv123"
            )
            
            assert success is True
            assert "abc123def456" in client.storage_records
            record = client.storage_records["abc123def456"]
            assert record.storage_uri == "file:///tmp/test.enc"
            assert record.provider_id == "local"
            assert record.conversation_hash == "conv123"
    
    def test_create_tombstone(self):
        """Test creating tombstone for a blob."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # First record storage
            client.record_storage(
                blob_hash="abc123def456",
                storage_uri="file:///tmp/test.enc",
                provider_id="local",
                region="local",
                conversation_hash="conv123"
            )
            
            # Create tombstone
            success = client.create_tombstone("abc123def456", "consent_revoked")
            
            assert success is True
            assert "abc123def456" in client.tombstone_records
            tombstone = client.tombstone_records["abc123def456"]
            assert tombstone.reason == "consent_revoked"
            assert client.storage_records["abc123def456"].is_active is False
    
    def test_verify_storage_local_file(self):
        """Test verifying storage of a local file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Create a test file
            test_file = Path(temp_dir) / "test.enc"
            test_file.write_bytes(b"test encrypted data")
            
            # Record storage
            client.record_storage(
                blob_hash="abc123def456",
                storage_uri=f"file://{test_file}",
                provider_id="local",
                region="local",
                conversation_hash="conv123"
            )
            
            # Verify storage
            result = client.verify_storage("abc123def456")
            
            assert result.verified is True
            assert result.accessible is True
            assert result.error_message is None
    
    def test_verify_storage_nonexistent_file(self):
        """Test verifying storage of a nonexistent file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record storage for nonexistent file
            client.record_storage(
                blob_hash="abc123def456",
                storage_uri="file:///nonexistent/path.enc",
                provider_id="local",
                region="local",
                conversation_hash="conv123"
            )
            
            # Verify storage
            result = client.verify_storage("abc123def456")
            
            assert result.verified is False
            assert result.accessible is False
            assert result.error_message is not None
    
    def test_verify_storage_tombstoned(self):
        """Test verifying storage of a tombstoned blob."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record storage
            client.record_storage(
                blob_hash="abc123def456",
                storage_uri="file:///tmp/test.enc",
                provider_id="local",
                region="local",
                conversation_hash="conv123"
            )
            
            # Create tombstone
            client.create_tombstone("abc123def456", "consent_revoked")
            
            # Verify storage
            result = client.verify_storage("abc123def456")
            
            assert result.verified is False
            assert result.accessible is False
            assert "tombstoned" in result.error_message
    
    def test_verify_storage_nonexistent_record(self):
        """Test verifying storage of a nonexistent record."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Verify nonexistent storage
            result = client.verify_storage("nonexistent_hash")
            
            assert result.verified is False
            assert result.accessible is False
            assert "not found" in result.error_message
    
    @patch('requests.head')
    def test_verify_storage_http(self, mock_head):
        """Test verifying storage of an HTTP URL."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Mock successful HTTP response
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_head.return_value = mock_response
            
            # Record storage
            client.record_storage(
                blob_hash="abc123def456",
                storage_uri="https://example.com/blob.enc",
                provider_id="http",
                region="global",
                conversation_hash="conv123"
            )
            
            # Verify storage
            result = client.verify_storage("abc123def456")
            
            assert result.verified is True
            assert result.accessible is True
            mock_head.assert_called_once_with("https://example.com/blob.enc", timeout=10)
    
    def test_get_blobs_for_conversation(self):
        """Test getting blobs for a conversation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record multiple blobs for same conversation
            client.record_storage("hash1", "uri1", "provider1", "region1", "conv123")
            client.record_storage("hash2", "uri2", "provider2", "region2", "conv123")
            client.record_storage("hash3", "uri3", "provider3", "region3", "conv456")
            
            # Get blobs for conversation
            blobs = client.get_blobs_for_conversation("conv123")
            
            assert len(blobs) == 2
            assert any(blob.blob_hash == "hash1" for blob in blobs)
            assert any(blob.blob_hash == "hash2" for blob in blobs)
            assert not any(blob.blob_hash == "hash3" for blob in blobs)
    
    def test_get_blobs_for_provider(self):
        """Test getting blobs for a provider."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record multiple blobs for same provider
            client.record_storage("hash1", "uri1", "provider1", "region1", "conv123")
            client.record_storage("hash2", "uri2", "provider1", "region2", "conv456")
            client.record_storage("hash3", "uri3", "provider2", "region3", "conv789")
            
            # Get blobs for provider
            blobs = client.get_blobs_for_provider("provider1")
            
            assert len(blobs) == 2
            assert any(blob.blob_hash == "hash1" for blob in blobs)
            assert any(blob.blob_hash == "hash2" for blob in blobs)
            assert not any(blob.blob_hash == "hash3" for blob in blobs)
    
    def test_search_by_uri_pattern(self):
        """Test searching blobs by URI pattern."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record blobs with different URI patterns
            client.record_storage("hash1", "s3://bucket/blob1.enc", "s3", "us-east-1", "conv123")
            client.record_storage("hash2", "s3://bucket/blob2.enc", "s3", "us-east-1", "conv456")
            client.record_storage("hash3", "file:///local/blob.enc", "local", "local", "conv789")
            
            # Search by pattern
            blobs = client.search_by_uri_pattern("s3://bucket/")
            
            assert len(blobs) == 2
            assert all("s3://bucket/" in blob.storage_uri for blob in blobs)
    
    def test_get_storage_stats(self):
        """Test getting storage statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            client = StorageProofClient()
            
            # Record some blobs
            client.record_storage("hash1", "uri1", "provider1", "region1", "conv123")
            client.record_storage("hash2", "uri2", "provider2", "region2", "conv456")
            
            # Create tombstone for one
            client.create_tombstone("hash1", "consent_revoked")
            
            # Get stats
            stats = client.get_storage_stats()
            
            assert stats["total"] == 2
            assert stats["active"] == 1
            assert stats["tombstoned"] == 1
            assert stats["inactive"] == 0
    
    def test_storage_persistence(self):
        """Test that storage records persist across client instances."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create first client and record storage
            client1 = StorageProofClient()
            client1.record_storage("hash1", "uri1", "provider1", "region1", "conv123")
            
            # Create second client and check if record exists
            client2 = StorageProofClient()
            assert "hash1" in client2.storage_records
            assert client2.storage_records["hash1"].storage_uri == "uri1"


class TestStorageRecord:
    """Test cases for StorageRecord."""
    
    def test_storage_record_creation(self):
        """Test StorageRecord creation."""
        record = StorageRecord(
            blob_hash="abc123",
            storage_uri="file:///tmp/test.enc",
            provider_id="local",
            region="local",
            timestamp=1234567890.0,
            conversation_hash="conv123",
            is_active=True
        )
        
        assert record.blob_hash == "abc123"
        assert record.storage_uri == "file:///tmp/test.enc"
        assert record.provider_id == "local"
        assert record.region == "local"
        assert record.conversation_hash == "conv123"
        assert record.is_active is True


class TestTombstoneRecord:
    """Test cases for TombstoneRecord."""
    
    def test_tombstone_record_creation(self):
        """Test TombstoneRecord creation."""
        tombstone = TombstoneRecord(
            blob_hash="abc123",
            reason="consent_revoked",
            timestamp=1234567890.0
        )
        
        assert tombstone.blob_hash == "abc123"
        assert tombstone.reason == "consent_revoked"
        assert tombstone.timestamp == 1234567890.0


class TestVerificationResult:
    """Test cases for VerificationResult."""
    
    def test_verification_result_creation(self):
        """Test VerificationResult creation."""
        result = VerificationResult(
            blob_hash="abc123",
            verified=True,
            accessible=True,
            last_checked=1234567890.0,
            error_message=None
        )
        
        assert result.blob_hash == "abc123"
        assert result.verified is True
        assert result.accessible is True
        assert result.error_message is None
