"""
Test cases for the key broker system.
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

from keybroker import KeyBroker, DataEncryptionKey, EncryptedBlob, ThresholdEncryption


class TestThresholdEncryption:
    """Test cases for ThresholdEncryption."""
    
    def test_key_share_generation(self):
        """Test generating key shares."""
        threshold = ThresholdEncryption(threshold=3, total_shares=5)
        master_key = b"test_master_key_32_bytes_long"
        
        shares = threshold.generate_key_shares(master_key)
        
        assert len(shares) == 5
        assert all(share.threshold == 3 for share in shares)
        assert all(share.total_shares == 5 for share in shares)
    
    def test_key_reconstruction(self):
        """Test reconstructing master key from shares."""
        threshold = ThresholdEncryption(threshold=2, total_shares=3)
        master_key = b"test_master_key_32_bytes_long"
        
        shares = threshold.generate_key_shares(master_key)
        
        # Reconstruct with threshold shares
        reconstructed = threshold.reconstruct_key(shares[:2])
        assert reconstructed is not None
        
        # Should fail with insufficient shares
        insufficient_shares = shares[:1]
        reconstructed = threshold.reconstruct_key(insufficient_shares)
        assert reconstructed is None
    
    def test_key_wrapping(self):
        """Test key wrapping and unwrapping."""
        threshold = ThresholdEncryption()
        key = b"test_key_32_bytes_long"
        viewer_did = "did:example:viewer"
        
        wrapped = threshold.wrap_key(key, viewer_did)
        assert wrapped is not None
        
        unwrapped = threshold.unwrap_key(wrapped, viewer_did)
        assert unwrapped is not None


class TestKeyBroker:
    """Test cases for KeyBroker."""
    
    def test_initialization(self):
        """Test key broker initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            assert broker.storage_type == "local"
            assert broker.storage_path == Path(temp_dir)
            assert broker.threshold_encryption is not None
    
    def test_dek_generation(self):
        """Test Data Encryption Key generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            dek = broker._generate_dek("did:example:user", "health_data", 24)
            
            assert dek.key_id is not None
            assert len(dek.key_material) == 32  # 256 bits
            assert dek.owner_did == "did:example:user"
            assert dek.scope == "health_data"
            assert dek.expires_at > dek.created_at
    
    def test_encryption_decryption(self):
        """Test AES-256-GCM encryption and decryption."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            key = b"test_key_32_bytes_long_exactly"
            data = b"test data to encrypt"
            
            # Encrypt
            encrypted_data, nonce = broker._encrypt_data(data, key)
            assert encrypted_data != data
            assert len(nonce) == 12  # 96 bits for GCM
            
            # Decrypt
            decrypted_data = broker._decrypt_data(encrypted_data, nonce, key)
            assert decrypted_data == data
    
    def test_consent_checking(self):
        """Test consent checking functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Mock consent manager
            with patch.object(broker, 'consent_manager') as mock_consent:
                mock_consent.list_consents_for_subject.return_value = []
                mock_consent.check_consent_active.return_value = False
                
                # Should fail without consent
                result = broker._check_consent("did:example:user", "health_data")
                assert result is False
    
    def test_store_blob(self):
        """Test storing encrypted blob."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Mock consent check to return True
            with patch.object(broker, '_check_consent', return_value=True):
                record_id = broker.store_blob(
                    "did:example:user",
                    "sensitive health data",
                    "health_data"
                )
                
                assert record_id is not None
                assert record_id in broker.encrypted_blobs
    
    def test_fetch_blob(self):
        """Test fetching and decrypting blob."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Mock consent check
            with patch.object(broker, '_check_consent', return_value=True):
                # Store blob first
                record_id = broker.store_blob(
                    "did:example:user",
                    "sensitive health data",
                    "health_data"
                )
                
                assert record_id is not None
                
                # Fetch blob
                decrypted_data = broker.fetch_blob(
                    "did:example:user",
                    record_id,
                    "health_data"
                )
                
                assert decrypted_data == "sensitive health data"
    
    def test_share_access(self):
        """Test sharing access to encrypted data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Share access
            result = broker.share_access(
                "did:example:owner",
                "did:example:viewer",
                "health_data"
            )
            
            assert result is True
            
            # Check that wrapped key was created
            deks = [dek for dek in broker.deks.values() 
                   if dek.owner_did == "did:example:owner" and dek.scope == "health_data"]
            assert len(deks) > 0
            assert "did:example:viewer" in deks[0].wrapped_keys
    
    def test_revoke_access(self):
        """Test revoking access to encrypted data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Share access first
            broker.share_access(
                "did:example:owner",
                "did:example:viewer",
                "health_data"
            )
            
            # Revoke access
            result = broker.revoke_access(
                "did:example:owner",
                "did:example:viewer",
                "health_data"
            )
            
            assert result is True
            
            # Check that wrapped key was removed
            deks = [dek for dek in broker.deks.values() 
                   if dek.owner_did == "did:example:owner" and dek.scope == "health_data"]
            assert len(deks) > 0
            assert "did:example:viewer" not in deks[0].wrapped_keys
    
    def test_list_user_blobs(self):
        """Test listing user's blobs."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Mock consent check
            with patch.object(broker, '_check_consent', return_value=True):
                # Store some blobs
                broker.store_blob("did:example:user", "data1", "health_data")
                broker.store_blob("did:example:user", "data2", "conversation_data")
                broker.store_blob("did:example:other", "data3", "health_data")
                
                # List user's blobs
                blobs = broker.list_user_blobs("did:example:user")
                assert len(blobs) == 2
                
                # List with scope filter
                health_blobs = broker.list_user_blobs("did:example:user", "health_data")
                assert len(health_blobs) == 1
                assert health_blobs[0]['scope'] == "health_data"
    
    def test_cleanup_expired_keys(self):
        """Test cleaning up expired keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            broker = KeyBroker(storage_type="local", storage_path=temp_dir)
            
            # Create expired DEK
            expired_dek = DataEncryptionKey(
                key_id="expired_key",
                key_material=b"test_key",
                created_at=0,
                expires_at=1,  # Expired
                scope="test",
                owner_did="did:example:user",
                wrapped_keys={}
            )
            broker.deks["expired_key"] = expired_dek
            
            # Cleanup
            broker.cleanup_expired_keys()
            
            # Check that expired key was removed
            assert "expired_key" not in broker.deks


class TestDataEncryptionKey:
    """Test cases for DataEncryptionKey."""
    
    def test_data_encryption_key_creation(self):
        """Test DataEncryptionKey creation."""
        dek = DataEncryptionKey(
            key_id="test_key",
            key_material=b"test_material",
            created_at=1234567890.0,
            expires_at=1234567890.0 + 3600,
            scope="test_scope",
            owner_did="did:example:user",
            wrapped_keys={"did:example:viewer": "wrapped_key"}
        )
        
        assert dek.key_id == "test_key"
        assert dek.key_material == b"test_material"
        assert dek.scope == "test_scope"
        assert dek.owner_did == "did:example:user"
        assert "did:example:viewer" in dek.wrapped_keys


class TestEncryptedBlob:
    """Test cases for EncryptedBlob."""
    
    def test_encrypted_blob_creation(self):
        """Test EncryptedBlob creation."""
        blob = EncryptedBlob(
            record_id="test_record",
            encrypted_data=b"encrypted_data",
            nonce=b"test_nonce",
            key_id="test_key",
            scope="test_scope",
            owner_did="did:example:user",
            created_at=1234567890.0,
            content_type="text/plain",
            size=100
        )
        
        assert blob.record_id == "test_record"
        assert blob.encrypted_data == b"encrypted_data"
        assert blob.scope == "test_scope"
        assert blob.owner_did == "did:example:user"
        assert blob.size == 100
