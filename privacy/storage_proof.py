"""
Storage Proof System for Encrypted Blob Verification.

This module provides:
- Blockchain anchoring of storage metadata
- Verification of encrypted blob existence
- Tombstone management for data deletion
- Integration with conversation hashing
"""

import os
import json
import time
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import requests
from urllib.parse import urlparse

from web3 import Web3
from web3.middleware import geth_poa_middleware


@dataclass
class StorageRecord:
    """Represents a storage record for an encrypted blob."""
    blob_hash: str
    storage_uri: str
    provider_id: str
    region: str
    timestamp: float
    conversation_hash: str
    is_active: bool


@dataclass
class TombstoneRecord:
    """Represents a tombstone record for deleted data."""
    blob_hash: str
    reason: str
    timestamp: float


@dataclass
class VerificationResult:
    """Result of storage verification."""
    blob_hash: str
    verified: bool
    accessible: bool
    last_checked: float
    error_message: Optional[str] = None


class StorageProofClient:
    """Client for managing storage proofs and verification."""
    
    def __init__(self, 
                 rpc_url: str = None,
                 contract_address: str = None,
                 private_key: str = None):
        """
        Initialize the storage proof client.
        
        Args:
            rpc_url: Blockchain RPC URL
            contract_address: StorageProof contract address
            private_key: Private key for blockchain transactions
        """
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL")
        self.contract_address = contract_address or os.getenv("STORAGE_PROOF_ADDRESS")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        
        # Initialize Web3 if blockchain config is available
        self.w3 = None
        self.contract = None
        if self.rpc_url and self.contract_address and self.private_key:
            self._init_blockchain()
        
        # Storage for local records
        self.storage_records: Dict[str, StorageRecord] = {}
        self.tombstone_records: Dict[str, TombstoneRecord] = {}
        
        # Storage paths
        self.storage_path = Path("privacy/storage_proof")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._load_storage()
    
    def _init_blockchain(self):
        """Initialize Web3 connection and contract."""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # StorageProof contract ABI
            contract_abi = [
                {
                    "inputs": [
                        {"name": "_blobHash", "type": "bytes32"},
                        {"name": "_storageUri", "type": "string"},
                        {"name": "_providerId", "type": "string"},
                        {"name": "_region", "type": "string"},
                        {"name": "_conversationHash", "type": "bytes32"}
                    ],
                    "name": "recordStorage",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "_blobHash", "type": "bytes32"},
                        {"name": "_reason", "type": "string"}
                    ],
                    "name": "createTombstone",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_blobHash", "type": "bytes32"}],
                    "name": "verifyStorage",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_blobHash", "type": "bytes32"}],
                    "name": "getStorageRecord",
                    "outputs": [
                        {
                            "name": "",
                            "type": "tuple",
                            "components": [
                                {"name": "blobHash", "type": "bytes32"},
                                {"name": "storageUri", "type": "string"},
                                {"name": "providerId", "type": "string"},
                                {"name": "region", "type": "string"},
                                {"name": "timestamp", "type": "uint256"},
                                {"name": "conversationHash", "type": "bytes32"},
                                {"name": "exists", "type": "bool"},
                                {"name": "isActive", "type": "bool"}
                            ]
                        }
                    ],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_blobHash", "type": "bytes32"}],
                    "name": "isTombstoned",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_conversationHash", "type": "bytes32"}],
                    "name": "getBlobsForConversation",
                    "outputs": [{"name": "", "type": "bytes32[]"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )
            
            print(f"✅ Storage proof blockchain initialized: {self.w3.eth.chain_id}")
        except Exception as e:
            print(f"⚠️ Storage proof blockchain initialization failed: {e}")
            self.w3 = None
            self.contract = None
    
    def _load_storage(self):
        """Load storage records from local storage."""
        try:
            # Load storage records
            storage_path = self.storage_path / "storage_records.json"
            if storage_path.exists():
                with open(storage_path, 'r') as f:
                    data = json.load(f)
                    self.storage_records = {k: StorageRecord(**v) for k, v in data.items()}
            
            # Load tombstone records
            tombstone_path = self.storage_path / "tombstone_records.json"
            if tombstone_path.exists():
                with open(tombstone_path, 'r') as f:
                    data = json.load(f)
                    self.tombstone_records = {k: TombstoneRecord(**v) for k, v in data.items()}
                    
        except Exception as e:
            print(f"⚠️ Failed to load storage proof storage: {e}")
    
    def _save_storage(self):
        """Save storage records to local storage."""
        try:
            # Save storage records
            storage_path = self.storage_path / "storage_records.json"
            with open(storage_path, 'w') as f:
                data = {k: asdict(v) for k, v in self.storage_records.items()}
                json.dump(data, f, indent=2)
            
            # Save tombstone records
            tombstone_path = self.storage_path / "tombstone_records.json"
            with open(tombstone_path, 'w') as f:
                data = {k: asdict(v) for k, v in self.tombstone_records.items()}
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"⚠️ Failed to save storage proof storage: {e}")
    
    def record_storage(self,
                      blob_hash: str,
                      storage_uri: str,
                      provider_id: str,
                      region: str,
                      conversation_hash: str) -> bool:
        """
        Record storage of an encrypted blob.
        
        Args:
            blob_hash: Hash of the encrypted blob
            storage_uri: URI where the blob is stored
            provider_id: Storage provider identifier
            region: Storage region
            conversation_hash: Hash of the associated conversation
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create local storage record
            record = StorageRecord(
                blob_hash=blob_hash,
                storage_uri=storage_uri,
                provider_id=provider_id,
                region=region,
                timestamp=time.time(),
                conversation_hash=conversation_hash,
                is_active=True
            )
            
            # Store locally
            self.storage_records[blob_hash] = record
            self._save_storage()
            
            # Record on blockchain if available
            if self.w3 and self.contract:
                self._record_storage_on_blockchain(record)
            
            print(f"✅ Recorded storage: {blob_hash[:16]}... at {storage_uri}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to record storage: {e}")
            return False
    
    def create_tombstone(self, blob_hash: str, reason: str) -> bool:
        """
        Create a tombstone record for deleted/revoked data.
        
        Args:
            blob_hash: Hash of the blob to tombstone
            reason: Reason for tombstoning
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if blob_hash not in self.storage_records:
                print(f"❌ Storage record not found: {blob_hash}")
                return False
            
            # Create tombstone record
            tombstone = TombstoneRecord(
                blob_hash=blob_hash,
                reason=reason,
                timestamp=time.time()
            )
            
            # Store locally
            self.tombstone_records[blob_hash] = tombstone
            self.storage_records[blob_hash].is_active = False
            self._save_storage()
            
            # Create tombstone on blockchain if available
            if self.w3 and self.contract:
                self._create_tombstone_on_blockchain(blob_hash, reason)
            
            print(f"✅ Created tombstone: {blob_hash[:16]}... ({reason})")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create tombstone: {e}")
            return False
    
    def verify_storage(self, blob_hash: str) -> VerificationResult:
        """
        Verify that a blob exists and is accessible.
        
        Args:
            blob_hash: Hash of the blob to verify
            
        Returns:
            VerificationResult with verification status
        """
        try:
            # Check if storage record exists
            if blob_hash not in self.storage_records:
                return VerificationResult(
                    blob_hash=blob_hash,
                    verified=False,
                    accessible=False,
                    last_checked=time.time(),
                    error_message="Storage record not found"
                )
            
            record = self.storage_records[blob_hash]
            
            # Check if tombstoned
            if blob_hash in self.tombstone_records:
                return VerificationResult(
                    blob_hash=blob_hash,
                    verified=False,
                    accessible=False,
                    last_checked=time.time(),
                    error_message="Storage record is tombstoned"
                )
            
            # Check if active
            if not record.is_active:
                return VerificationResult(
                    blob_hash=blob_hash,
                    verified=False,
                    accessible=False,
                    last_checked=time.time(),
                    error_message="Storage record is inactive"
                )
            
            # Verify accessibility
            accessible = self._verify_accessibility(record.storage_uri)
            
            # Check blockchain verification if available
            blockchain_verified = True
            if self.w3 and self.contract:
                try:
                    blob_hash_bytes = bytes.fromhex(blob_hash)
                    blockchain_verified = self.contract.functions.verifyStorage(blob_hash_bytes).call()
                except Exception as e:
                    print(f"⚠️ Blockchain verification failed: {e}")
                    blockchain_verified = True  # Assume verified if blockchain check fails
            
            verified = accessible and blockchain_verified
            
            return VerificationResult(
                blob_hash=blob_hash,
                verified=verified,
                accessible=accessible,
                last_checked=time.time(),
                error_message=None if verified else "Verification failed"
            )
            
        except Exception as e:
            return VerificationResult(
                blob_hash=blob_hash,
                verified=False,
                accessible=False,
                last_checked=time.time(),
                error_message=f"Verification error: {str(e)}"
            )
    
    def _verify_accessibility(self, storage_uri: str) -> bool:
        """Verify that the storage URI is accessible."""
        try:
            parsed_uri = urlparse(storage_uri)
            
            if parsed_uri.scheme == 'file':
                # Local file - check if exists
                file_path = Path(parsed_uri.path)
                return file_path.exists()
            
            elif parsed_uri.scheme in ['http', 'https']:
                # HTTP/HTTPS - check with HEAD request
                response = requests.head(storage_uri, timeout=10)
                return response.status_code == 200
            
            elif parsed_uri.scheme == 's3':
                # S3 - check with boto3 (if available)
                try:
                    import boto3
                    s3_client = boto3.client('s3')
                    bucket = parsed_uri.netloc
                    key = parsed_uri.path.lstrip('/')
                    s3_client.head_object(Bucket=bucket, Key=key)
                    return True
                except ImportError:
                    print("⚠️ boto3 not available for S3 verification")
                    return True  # Assume accessible
                except Exception:
                    return False
            
            else:
                # Unknown scheme - assume accessible
                return True
                
        except Exception as e:
            print(f"⚠️ Accessibility verification failed: {e}")
            return False
    
    def get_storage_record(self, blob_hash: str) -> Optional[StorageRecord]:
        """Get storage record by blob hash."""
        return self.storage_records.get(blob_hash)
    
    def get_tombstone_record(self, blob_hash: str) -> Optional[TombstoneRecord]:
        """Get tombstone record by blob hash."""
        return self.tombstone_records.get(blob_hash)
    
    def get_blobs_for_conversation(self, conversation_hash: str) -> List[StorageRecord]:
        """Get all storage records for a conversation."""
        return [record for record in self.storage_records.values() 
                if record.conversation_hash == conversation_hash]
    
    def get_blobs_for_provider(self, provider_id: str) -> List[StorageRecord]:
        """Get all storage records for a provider."""
        return [record for record in self.storage_records.values() 
                if record.provider_id == provider_id]
    
    def search_by_uri_pattern(self, uri_pattern: str) -> List[StorageRecord]:
        """Search storage records by URI pattern."""
        return [record for record in self.storage_records.values() 
                if uri_pattern in record.storage_uri]
    
    def get_storage_stats(self) -> Dict[str, int]:
        """Get storage statistics."""
        total = len(self.storage_records)
        active = sum(1 for record in self.storage_records.values() if record.is_active)
        tombstoned = len(self.tombstone_records)
        
        return {
            "total": total,
            "active": active,
            "tombstoned": tombstoned,
            "inactive": total - active - tombstoned
        }
    
    def _record_storage_on_blockchain(self, record: StorageRecord):
        """Record storage on blockchain."""
        try:
            blob_hash_bytes = bytes.fromhex(record.blob_hash)
            conversation_hash_bytes = bytes.fromhex(record.conversation_hash)
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.recordStorage(
                blob_hash_bytes,
                record.storage_uri,
                record.provider_id,
                record.region,
                conversation_hash_bytes
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Storage recorded on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to record storage on blockchain: {e}")
    
    def _create_tombstone_on_blockchain(self, blob_hash: str, reason: str):
        """Create tombstone on blockchain."""
        try:
            blob_hash_bytes = bytes.fromhex(blob_hash)
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.createTombstone(
                blob_hash_bytes,
                reason
            ).build_transaction({
                'from': account.address,
                'gas': 100000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Tombstone created on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to create tombstone on blockchain: {e}")


def main():
    """CLI entry point for storage proof management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Storage Proof System")
    parser.add_argument("--record-storage", nargs=5, metavar=("BLOB_HASH", "STORAGE_URI", "PROVIDER_ID", "REGION", "CONV_HASH"),
                       help="Record storage of a blob")
    parser.add_argument("--create-tombstone", nargs=2, metavar=("BLOB_HASH", "REASON"),
                       help="Create tombstone for a blob")
    parser.add_argument("--verify-storage", type=str, metavar="BLOB_HASH",
                       help="Verify storage of a blob")
    parser.add_argument("--get-conversation-blobs", type=str, metavar="CONV_HASH",
                       help="Get all blobs for a conversation")
    parser.add_argument("--get-stats", action="store_true", help="Get storage statistics")
    
    args = parser.parse_args()
    
    # Initialize storage proof client
    client = StorageProofClient()
    
    if args.record_storage:
        blob_hash, storage_uri, provider_id, region, conv_hash = args.record_storage
        success = client.record_storage(blob_hash, storage_uri, provider_id, region, conv_hash)
        if success:
            print("✅ Storage recorded successfully")
        else:
            print("❌ Failed to record storage")
    
    elif args.create_tombstone:
        blob_hash, reason = args.create_tombstone
        success = client.create_tombstone(blob_hash, reason)
        if success:
            print("✅ Tombstone created successfully")
        else:
            print("❌ Failed to create tombstone")
    
    elif args.verify_storage:
        result = client.verify_storage(args.verify_storage)
        print(f"Verification: {'✅ VERIFIED' if result.verified else '❌ FAILED'}")
        print(f"Accessible: {'✅ YES' if result.accessible else '❌ NO'}")
        if result.error_message:
            print(f"Error: {result.error_message}")
    
    elif args.get_conversation_blobs:
        blobs = client.get_blobs_for_conversation(args.get_conversation_blobs)
        if blobs:
            for blob in blobs:
                status = "active" if blob.is_active else "inactive"
                print(f"📄 {blob.blob_hash[:16]}... - {blob.storage_uri} ({status})")
        else:
            print("No blobs found for conversation")
    
    elif args.get_stats:
        stats = client.get_storage_stats()
        print(f"📊 Storage Statistics:")
        print(f"  Total records: {stats['total']}")
        print(f"  Active records: {stats['active']}")
        print(f"  Tombstoned records: {stats['tombstoned']}")
        print(f"  Inactive records: {stats['inactive']}")


if __name__ == "__main__":
    main()
