"""
Test cases for the audit system.
"""

import os
import sys
import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add audit directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "audit"))

from anchor import ConversationAuditor, Conversation, MerkleTree, verify_digest, get_latest_root


class TestConversationAuditor:
    """Test cases for ConversationAuditor."""
    
    def test_conversation_hashing(self):
        """Test that conversation hashing is deterministic."""
        auditor = ConversationAuditor(salt="test_salt")
        
        conv1 = Conversation(
            user_input="Hello",
            reply="Hi there!",
            timestamp=1234567890.0,
            language="en"
        )
        
        conv2 = Conversation(
            user_input="Hello",
            reply="Hi there!",
            timestamp=1234567890.0,
            language="en"
        )
        
        # Same conversation should produce same hash
        hash1 = auditor.hash_conversation(conv1)
        hash2 = auditor.hash_conversation(conv2)
        assert hash1 == hash2
        
        # Different conversation should produce different hash
        conv3 = Conversation(
            user_input="Goodbye",
            reply="See you later!",
            timestamp=1234567890.0,
            language="en"
        )
        hash3 = auditor.hash_conversation(conv3)
        assert hash1 != hash3
    
    def test_merkle_tree_construction(self):
        """Test Merkle tree construction."""
        hashes = [
            "hash1",
            "hash2", 
            "hash3",
            "hash4"
        ]
        
        tree = MerkleTree(hashes)
        root = tree.get_root_hash()
        
        assert root is not None
        assert len(root) == 64  # SHA-256 hex length
    
    def test_merkle_tree_single_hash(self):
        """Test Merkle tree with single hash."""
        hashes = ["single_hash"]
        tree = MerkleTree(hashes)
        root = tree.get_root_hash()
        
        assert root == "single_hash"
    
    def test_merkle_tree_empty(self):
        """Test Merkle tree with empty hash list."""
        tree = MerkleTree([])
        root = tree.get_root_hash()
        
        assert root is None
    
    def test_add_conversation(self):
        """Test adding conversations to auditor."""
        auditor = ConversationAuditor()
        
        auditor.add_conversation("Hello", "Hi!", "en")
        assert len(auditor.pending_conversations) == 1
        
        auditor.add_conversation("Hola", "¡Hola!", "es")
        assert len(auditor.pending_conversations) == 2
    
    @patch('audit.anchor.ConversationAuditor._anchor_to_blockchain')
    def test_batch_and_anchor_without_blockchain(self, mock_anchor):
        """Test batching and anchoring without blockchain."""
        auditor = ConversationAuditor()
        
        # Add some conversations
        for i in range(5):
            auditor.add_conversation(f"Message {i}", f"Reply {i}", "en")
        
        # Force anchor
        root_hash = auditor.batch_and_anchor(force=True)
        
        assert root_hash is not None
        assert len(auditor.pending_conversations) == 0
    
    def test_verify_digest(self):
        """Test conversation digest verification."""
        # Create a temporary audit log
        with tempfile.TemporaryDirectory() as temp_dir:
            audit_log_path = Path(temp_dir) / "audit_log.json"
            
            # Mock the audit log path
            with patch('audit.anchor.Path') as mock_path:
                mock_path.return_value = audit_log_path
                
                # Create test audit log
                audit_log = {
                    "entries": [{
                        "timestamp": 1234567890.0,
                        "merkle_root": "test_root_hash",
                        "conversation_count": 1,
                        "conversations": [{
                            "user_input": "Hello",
                            "reply": "Hi!",
                            "timestamp": 1234567890.0,
                            "language": "en",
                            "hash": "test_conversation_hash"
                        }]
                    }]
                }
                
                with open(audit_log_path, 'w') as f:
                    json.dump(audit_log, f)
                
                # Test verification
                conv = Conversation("Hello", "Hi!", 1234567890.0, "en")
                
                # Mock the hash computation to return the expected hash
                with patch('audit.anchor.ConversationAuditor.hash_conversation') as mock_hash:
                    mock_hash.return_value = "test_conversation_hash"
                    
                    result = verify_digest(conv, "test_root_hash")
                    assert result is True
    
    def test_get_latest_root_no_log(self):
        """Test get_latest_root when no audit log exists."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch('audit.anchor.Path') as mock_path:
                mock_path.return_value = Path(temp_dir) / "nonexistent.json"
                
                result = get_latest_root()
                assert result is None


class TestMerkleTree:
    """Test cases for MerkleTree class."""
    
    def test_tree_properties(self):
        """Test Merkle tree properties."""
        hashes = ["a", "b", "c", "d"]
        tree = MerkleTree(hashes)
        
        assert tree.root is not None
        assert tree.root.left is not None
        assert tree.root.right is not None
    
    def test_tree_with_odd_number_of_hashes(self):
        """Test Merkle tree with odd number of hashes."""
        hashes = ["a", "b", "c"]
        tree = MerkleTree(hashes)
        
        root = tree.get_root_hash()
        assert root is not None
