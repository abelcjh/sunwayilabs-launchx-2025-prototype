"""
Conversation audit and blockchain anchoring system.

This module provides cryptographic proof of conversation integrity by:
1. Computing salted SHA-256 hashes of conversations
2. Batching hashes into Merkle trees
3. Anchoring Merkle roots to blockchain (Polygon/Base testnet)
"""

import os
import json
import time
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from web3 import Web3
from web3.middleware import geth_poa_middleware


@dataclass
class Conversation:
    """Represents a conversation with user input and AI reply."""
    user_input: str
    reply: str
    timestamp: float
    language: str


@dataclass
class MerkleNode:
    """Represents a node in the Merkle tree."""
    hash: str
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None


class MerkleTree:
    """Merkle tree implementation for batching conversation hashes."""
    
    def __init__(self, hashes: List[str]):
        self.hashes = hashes
        self.root = self._build_tree()
    
    def _build_tree(self) -> Optional[MerkleNode]:
        """Build Merkle tree from list of hashes."""
        if not self.hashes:
            return None
        
        if len(self.hashes) == 1:
            return MerkleNode(hash=self.hashes[0])
        
        # Convert to MerkleNode objects
        nodes = [MerkleNode(hash=h) for h in self.hashes]
        
        while len(nodes) > 1:
            next_level = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                right = nodes[i + 1] if i + 1 < len(nodes) else left
                
                # Combine hashes
                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                
                parent = MerkleNode(
                    hash=parent_hash,
                    left=left,
                    right=right
                )
                next_level.append(parent)
            
            nodes = next_level
        
        return nodes[0] if nodes else None
    
    def get_root_hash(self) -> Optional[str]:
        """Get the root hash of the Merkle tree."""
        return self.root.hash if self.root else None


class ConversationAuditor:
    """Main auditor class for conversation integrity and blockchain anchoring."""
    
    def __init__(self, 
                 salt: str = None,
                 rpc_url: str = None,
                 private_key: str = None,
                 contract_address: str = None):
        """
        Initialize the conversation auditor.
        
        Args:
            salt: Salt for hashing (defaults to env var AUDIT_SALT)
            rpc_url: Blockchain RPC URL (defaults to env var BLOCKCHAIN_RPC_URL)
            private_key: Private key for transactions (defaults to env var PRIVATE_KEY)
            contract_address: Smart contract address (defaults to env var CONTRACT_ADDRESS)
        """
        self.salt = salt or os.getenv("AUDIT_SALT", "default_audit_salt_2025")
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        self.contract_address = contract_address or os.getenv("CONTRACT_ADDRESS")
        
        # Initialize Web3 if blockchain config is available
        self.w3 = None
        self.contract = None
        if self.rpc_url and self.private_key and self.contract_address:
            self._init_blockchain()
        
        # Storage for pending conversations
        self.pending_conversations: List[Conversation] = []
        self.audit_log_path = Path("audit/audit_log.json")
        self.audit_log_path.parent.mkdir(exist_ok=True)
    
    def _init_blockchain(self):
        """Initialize Web3 connection and contract."""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            # Add PoA middleware for Polygon/Base
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Simple contract ABI for storing Merkle roots
            contract_abi = [
                {
                    "inputs": [
                        {"name": "root", "type": "bytes32"},
                        {"name": "timestamp", "type": "uint256"}
                    ],
                    "name": "storeRoot",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [],
                    "name": "getLatestRoot",
                    "outputs": [
                        {"name": "root", "type": "bytes32"},
                        {"name": "timestamp", "type": "uint256"}
                    ],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )
            
            print(f"✅ Blockchain initialized: {self.w3.eth.chain_id}")
        except Exception as e:
            print(f"⚠️ Blockchain initialization failed: {e}")
            self.w3 = None
            self.contract = None
    
    def hash_conversation(self, conversation: Conversation) -> str:
        """
        Compute salted SHA-256 hash of a conversation.
        
        Args:
            conversation: Conversation object to hash
            
        Returns:
            Hexadecimal hash string
        """
        # Create a structured representation for hashing
        data = {
            "user_input": conversation.user_input,
            "reply": conversation.reply,
            "timestamp": conversation.timestamp,
            "language": conversation.language
        }
        
        # Convert to JSON string and add salt
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        salted_data = f"{json_str}:{self.salt}"
        
        # Compute SHA-256 hash
        return hashlib.sha256(salted_data.encode()).hexdigest()
    
    def add_conversation(self, user_input: str, reply: str, language: str = "en"):
        """
        Add a conversation to the audit queue.
        
        Args:
            user_input: User's input message
            reply: AI's reply message
            language: Language code (en/ms)
        """
        conversation = Conversation(
            user_input=user_input,
            reply=reply,
            timestamp=time.time(),
            language=language
        )
        
        self.pending_conversations.append(conversation)
        print(f"📝 Added conversation to audit queue (total: {len(self.pending_conversations)})")
    
    def batch_and_anchor(self, force: bool = False) -> Optional[str]:
        """
        Batch pending conversations into Merkle tree and anchor to blockchain.
        
        Args:
            force: Force anchoring even if batch is small
            
        Returns:
            Merkle root hash if successful, None otherwise
        """
        if not self.pending_conversations:
            print("ℹ️ No conversations to anchor")
            return None
        
        # Check if we should batch (every hour or force)
        if not force and len(self.pending_conversations) < 10:
            print(f"⏳ Waiting for more conversations (current: {len(self.pending_conversations)})")
            return None
        
        print(f"🌳 Building Merkle tree with {len(self.pending_conversations)} conversations...")
        
        # Compute hashes for all conversations
        hashes = [self.hash_conversation(conv) for conv in self.pending_conversations]
        
        # Build Merkle tree
        merkle_tree = MerkleTree(hashes)
        root_hash = merkle_tree.get_root_hash()
        
        if not root_hash:
            print("❌ Failed to build Merkle tree")
            return None
        
        # Anchor to blockchain if available
        if self.w3 and self.contract:
            try:
                self._anchor_to_blockchain(root_hash)
                print(f"🔗 Anchored Merkle root to blockchain: {root_hash[:16]}...")
            except Exception as e:
                print(f"❌ Blockchain anchoring failed: {e}")
                # Continue with local storage even if blockchain fails
        
        # Store audit log locally
        self._store_audit_log(root_hash, self.pending_conversations)
        
        # Clear pending conversations
        self.pending_conversations.clear()
        
        return root_hash
    
    def _anchor_to_blockchain(self, root_hash: str):
        """Anchor Merkle root to blockchain."""
        if not self.w3 or not self.contract:
            raise RuntimeError("Blockchain not initialized")
        
        # Convert hex string to bytes32
        root_bytes = bytes.fromhex(root_hash)
        timestamp = int(time.time())
        
        # Build transaction
        account = self.w3.eth.account.from_key(self.private_key)
        
        transaction = self.contract.functions.storeRoot(
            root_bytes,
            timestamp
        ).build_transaction({
            'from': account.address,
            'gas': 100000,
            'gasPrice': self.w3.eth.gas_price,
            'nonce': self.w3.eth.get_transaction_count(account.address),
        })
        
        # Sign and send transaction
        signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
        
        # Wait for confirmation
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"✅ Transaction confirmed: {receipt.transactionHash.hex()}")
    
    def _store_audit_log(self, root_hash: str, conversations: List[Conversation]):
        """Store audit log locally."""
        audit_entry = {
            "timestamp": time.time(),
            "merkle_root": root_hash,
            "conversation_count": len(conversations),
            "conversations": [
                {
                    "user_input": conv.user_input,
                    "reply": conv.reply,
                    "timestamp": conv.timestamp,
                    "language": conv.language,
                    "hash": self.hash_conversation(conv)
                }
                for conv in conversations
            ]
        }
        
        # Load existing log
        if self.audit_log_path.exists():
            with open(self.audit_log_path, 'r') as f:
                audit_log = json.load(f)
        else:
            audit_log = {"entries": []}
        
        # Add new entry
        audit_log["entries"].append(audit_entry)
        
        # Save updated log
        with open(self.audit_log_path, 'w') as f:
            json.dump(audit_log, f, indent=2)
        
        print(f"💾 Stored audit log: {self.audit_log_path}")


def verify_digest(conversation: Conversation, root_hash: str, salt: str = None) -> bool:
    """
    Verify that a conversation digest matches a Merkle root.
    
    Args:
        conversation: Conversation to verify
        root_hash: Expected Merkle root hash
        salt: Salt used for hashing (defaults to env var)
        
    Returns:
        True if conversation is part of the Merkle tree
    """
    if salt is None:
        salt = os.getenv("AUDIT_SALT", "default_audit_salt_2025")
    
    # Compute conversation hash
    auditor = ConversationAuditor(salt=salt)
    conversation_hash = auditor.hash_conversation(conversation)
    
    # For now, we can only verify if the conversation hash matches
    # In a full implementation, you'd need to reconstruct the Merkle tree
    # and verify the path from conversation to root
    
    # Load audit log to find the Merkle tree
    audit_log_path = Path("audit/audit_log.json")
    if not audit_log_path.exists():
        return False
    
    with open(audit_log_path, 'r') as f:
        audit_log = json.load(f)
    
    # Find the entry with matching root
    for entry in audit_log.get("entries", []):
        if entry["merkle_root"] == root_hash:
            # Check if conversation hash is in this batch
            for conv_data in entry.get("conversations", []):
                if conv_data["hash"] == conversation_hash:
                    return True
    
    return False


def get_latest_root() -> Optional[Tuple[str, float]]:
    """
    Get the latest Merkle root and timestamp.
    
    Returns:
        Tuple of (root_hash, timestamp) or None if no roots exist
    """
    # Try blockchain first
    auditor = ConversationAuditor()
    if auditor.w3 and auditor.contract:
        try:
            result = auditor.contract.functions.getLatestRoot().call()
            root_bytes, timestamp = result
            root_hash = root_bytes.hex()
            return root_hash, timestamp
        except Exception as e:
            print(f"⚠️ Failed to get latest root from blockchain: {e}")
    
    # Fallback to local audit log
    audit_log_path = Path("audit/audit_log.json")
    if not audit_log_path.exists():
        return None
    
    with open(audit_log_path, 'r') as f:
        audit_log = json.load(f)
    
    entries = audit_log.get("entries", [])
    if not entries:
        return None
    
    # Get the most recent entry
    latest_entry = max(entries, key=lambda x: x["timestamp"])
    return latest_entry["merkle_root"], latest_entry["timestamp"]


def main():
    """CLI entry point for manual anchoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Conversation Audit and Blockchain Anchoring")
    parser.add_argument("--force", action="store_true", help="Force anchoring even with small batch")
    parser.add_argument("--add-sample", action="store_true", help="Add sample conversation for testing")
    
    args = parser.parse_args()
    
    # Initialize auditor
    auditor = ConversationAuditor()
    
    if args.add_sample:
        # Add some sample conversations for testing
        sample_conversations = [
            ("I feel anxious about work", "It sounds like work is causing you some anxiety. Would you like to talk about what specifically feels overwhelming?", "en"),
            ("Saya rasa tertekan", "Kedengaran seperti anda sedang menanggung tekanan. Mahu ceritakan apa yang membuatkannya terasa berat?", "ms"),
            ("I'm having trouble sleeping", "Sleep difficulties can be really challenging. What's been keeping you awake at night?", "en"),
        ]
        
        for user_input, reply, lang in sample_conversations:
            auditor.add_conversation(user_input, reply, lang)
    
    # Attempt to batch and anchor
    root_hash = auditor.batch_and_anchor(force=args.force)
    
    if root_hash:
        print(f"✅ Successfully anchored Merkle root: {root_hash}")
        
        # Show latest root info
        latest = get_latest_root()
        if latest:
            root, timestamp = latest
            dt = datetime.fromtimestamp(timestamp)
            print(f"📊 Latest root: {root[:16]}... (anchored at {dt})")
    else:
        print("ℹ️ No anchoring performed")


if __name__ == "__main__":
    main()
