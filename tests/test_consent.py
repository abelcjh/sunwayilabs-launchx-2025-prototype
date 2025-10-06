"""
Test cases for the consent management system.
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

from consent import ConsentManager, ConsentReceipt, VerifiableCredential


class TestConsentManager:
    """Test cases for ConsentManager."""
    
    def test_consent_receipt_creation(self):
        """Test creating a consent receipt."""
        manager = ConsentManager()
        
        receipt = manager.create_consent_receipt(
            subject_did="did:example:user123",
            controller_did="did:example:bot",
            purpose="Mental health support",
            data_categories=["health_data", "conversation_data"],
            processing_activities=["analysis", "storage"],
            legal_basis="consent",
            retention_period_days=365
        )
        
        assert receipt.consent_id is not None
        assert receipt.subject_did == "did:example:user123"
        assert receipt.controller_did == "did:example:bot"
        assert receipt.consent_hash is not None
        assert len(receipt.consent_hash) == 64  # SHA-256 hex length
    
    def test_verifiable_credential_creation(self):
        """Test creating a Verifiable Credential."""
        manager = ConsentManager()
        
        receipt = ConsentReceipt(
            consent_id="test_consent_123",
            subject_did="did:example:user123",
            controller_did="did:example:bot",
            purpose="Test purpose",
            data_categories=["test_data"],
            processing_activities=["test_activity"],
            legal_basis="consent",
            retention_period=365,
            expires_at=1234567890,
            created_at=1234567890,
            consent_hash="test_hash"
        )
        
        vc = manager.create_verifiable_credential(receipt, "did:example:issuer")
        
        assert vc.id is not None
        assert vc.issuer == "did:example:issuer"
        assert vc.type == ["VerifiableCredential", "ConsentCredential"]
        assert "https://www.w3.org/2018/credentials/v1" in vc.context
    
    def test_consent_storage(self):
        """Test consent storage and retrieval."""
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_path = os.path.join(temp_dir, "consent_storage.json")
            
            with patch('privacy.consent.ConsentManager.consent_storage_path', storage_path):
                manager = ConsentManager()
                
                # Create consent
                receipt = manager.create_consent_receipt(
                    subject_did="did:example:user123",
                    controller_did="did:example:bot",
                    purpose="Test purpose",
                    data_categories=["test_data"],
                    processing_activities=["test_activity"]
                )
                
                # Check it's stored
                assert receipt.consent_id in manager.consent_receipts
                
                # Create new manager instance (should load from storage)
                manager2 = ConsentManager()
                assert receipt.consent_id in manager2.consent_receipts
    
    def test_consent_validation(self):
        """Test consent validation."""
        manager = ConsentManager()
        
        # Create consent
        receipt = manager.create_consent_receipt(
            subject_did="did:example:user123",
            controller_did="did:example:bot",
            purpose="Test purpose",
            data_categories=["test_data"],
            processing_activities=["test_activity"]
        )
        
        # Should be active
        assert manager.check_consent_active(receipt.consent_id) is True
        
        # Revoke consent
        manager.revoke_consent(receipt.consent_id)
        
        # Should be inactive
        assert manager.check_consent_active(receipt.consent_id) is False
    
    def test_encryption_with_consent(self):
        """Test encryption/decryption with consent validation."""
        manager = ConsentManager()
        
        # Create consent
        receipt = manager.create_consent_receipt(
            subject_did="did:example:user123",
            controller_did="did:example:bot",
            purpose="Test purpose",
            data_categories=["test_data"],
            processing_activities=["test_activity"]
        )
        
        # Test data
        test_data = "This is sensitive mental health data"
        
        # Encrypt with valid consent
        encrypted = manager.encrypt_data(test_data, receipt.consent_id)
        assert encrypted is not None
        
        # Decrypt with valid consent
        decrypted = manager.decrypt_data(encrypted, receipt.consent_id)
        assert decrypted == test_data
        
        # Try to encrypt without consent
        encrypted_no_consent = manager.encrypt_data(test_data, "nonexistent_consent")
        assert encrypted_no_consent is None
    
    def test_consent_lists(self):
        """Test listing consents by subject and controller."""
        manager = ConsentManager()
        
        # Create consents for different subjects
        receipt1 = manager.create_consent_receipt(
            subject_did="did:example:user1",
            controller_did="did:example:bot",
            purpose="Purpose 1",
            data_categories=["data1"],
            processing_activities=["activity1"]
        )
        
        receipt2 = manager.create_consent_receipt(
            subject_did="did:example:user2",
            controller_did="did:example:bot",
            purpose="Purpose 2",
            data_categories=["data2"],
            processing_activities=["activity2"]
        )
        
        # Test subject consents
        user1_consents = manager.list_consents_for_subject("did:example:user1")
        assert len(user1_consents) == 1
        assert user1_consents[0].consent_id == receipt1.consent_id
        
        # Test controller consents
        bot_consents = manager.list_consents_for_controller("did:example:bot")
        assert len(bot_consents) == 2


class TestConsentReceipt:
    """Test cases for ConsentReceipt."""
    
    def test_consent_receipt_creation(self):
        """Test ConsentReceipt creation."""
        receipt = ConsentReceipt(
            consent_id="test_123",
            subject_did="did:example:user",
            controller_did="did:example:controller",
            purpose="Test purpose",
            data_categories=["health_data"],
            processing_activities=["analysis"],
            legal_basis="consent",
            retention_period=365,
            expires_at=1234567890,
            created_at=1234567890,
            consent_hash="abc123"
        )
        
        assert receipt.consent_id == "test_123"
        assert receipt.subject_did == "did:example:user"
        assert receipt.purpose == "Test purpose"
        assert "health_data" in receipt.data_categories


class TestVerifiableCredential:
    """Test cases for VerifiableCredential."""
    
    def test_verifiable_credential_creation(self):
        """Test VerifiableCredential creation."""
        vc = VerifiableCredential(
            context=["https://www.w3.org/2018/credentials/v1"],
            type=["VerifiableCredential"],
            id="did:example:vc123",
            issuer="did:example:issuer",
            issuance_date="2023-01-01T00:00:00Z",
            expiration_date="2024-01-01T00:00:00Z",
            credential_subject={"id": "did:example:subject"},
            proof={"type": "EcdsaSecp256k1Signature2019"}
        )
        
        assert vc.id == "did:example:vc123"
        assert vc.issuer == "did:example:issuer"
        assert "VerifiableCredential" in vc.type
