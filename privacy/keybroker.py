"""
Key Broker System for Secure Data Storage and Access Control.

This module provides:
- AES-256-GCM encryption/decryption
- Per-session Data Encryption Keys (DEKs)
- Threshold encryption for key sharing
- On-chain consent validation
- Local/S3 storage with CID/path management
"""

import os
import json
import time
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import boto3
from botocore.exceptions import ClientError

# Import consent system
try:
    from .consent import ConsentManager
    CONSENT_AVAILABLE = True
except ImportError:
    CONSENT_AVAILABLE = False
    print("⚠️ Consent system not available - key broker will run without consent validation")

# Import storage proof system
try:
    from .storage_proof import StorageProofClient
    STORAGE_PROOF_AVAILABLE = True
except ImportError:
    STORAGE_PROOF_AVAILABLE = False
    print("⚠️ Storage proof system not available - storage will not be anchored")


@dataclass
class DataEncryptionKey:
    """Per-session Data Encryption Key."""
    key_id: str
    key_material: bytes
    created_at: float
    expires_at: float
    scope: str
    owner_did: str
    wrapped_keys: Dict[str, str]  # viewer_did -> wrapped_key


@dataclass
class EncryptedBlob:
    """Encrypted data blob with metadata."""
    record_id: str
    encrypted_data: bytes
    nonce: bytes
    key_id: str
    scope: str
    owner_did: str
    created_at: float
    content_type: str
    size: int


@dataclass
class ThresholdKey:
    """Threshold encryption key share."""
    share_id: str
    key_share: bytes
    threshold: int
    total_shares: int
    created_at: float


class ThresholdEncryption:
    """Mock threshold encryption system for key sharing."""
    
    def __init__(self, threshold: int = 3, total_shares: int = 5):
        self.threshold = threshold
        self.total_shares = total_shares
        self.key_shares: Dict[str, ThresholdKey] = {}
    
    def generate_key_shares(self, master_key: bytes) -> List[ThresholdKey]:
        """Generate threshold key shares from master key."""
        shares = []
        for i in range(self.total_shares):
            # Mock implementation - in production, use Shamir's Secret Sharing
            share_data = hashlib.sha256(master_key + str(i).encode()).digest()
            
            share = ThresholdKey(
                share_id=f"share_{i}",
                key_share=share_data,
                threshold=self.threshold,
                total_shares=self.total_shares,
                created_at=time.time()
            )
            shares.append(share)
            self.key_shares[share.share_id] = share
        
        return shares
    
    def reconstruct_key(self, shares: List[ThresholdKey]) -> Optional[bytes]:
        """Reconstruct master key from threshold shares."""
        if len(shares) < self.threshold:
            return None
        
        # Mock reconstruction - in production, use Shamir's Secret Sharing
        combined = b"".join(share.key_share for share in shares[:self.threshold])
        return hashlib.sha256(combined).digest()
    
    def wrap_key(self, key: bytes, viewer_did: str) -> str:
        """Wrap key for specific viewer using threshold encryption."""
        # Mock implementation - in production, use proxy re-encryption
        wrapped = hashlib.sha256(key + viewer_did.encode()).digest()
        return base64.b64encode(wrapped).decode()
    
    def unwrap_key(self, wrapped_key: str, viewer_did: str) -> Optional[bytes]:
        """Unwrap key for specific viewer."""
        # Mock implementation - in production, use proxy re-encryption
        try:
            wrapped_bytes = base64.b64decode(wrapped_key)
            # This is a simplified mock - real implementation would be more complex
            return wrapped_bytes
        except Exception:
            return None


class KeyBroker:
    """Main key broker for secure data storage and access control."""
    
    def __init__(self, 
                 storage_type: str = "local",
                 s3_bucket: str = None,
                 aws_access_key: str = None,
                 aws_secret_key: str = None,
                 storage_path: str = "privacy/storage",
                 enable_storage_proof: bool = True):
        """
        Initialize the key broker.
        
        Args:
            storage_type: "local" or "s3"
            s3_bucket: S3 bucket name for cloud storage
            aws_access_key: AWS access key
            aws_secret_key: AWS secret key
            storage_path: Local storage path
            enable_storage_proof: Enable storage proof anchoring
        """
        self.storage_type = storage_type
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize S3 if configured
        self.s3_client = None
        self.s3_bucket = s3_bucket
        if storage_type == "s3" and s3_bucket:
            try:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=aws_access_key or os.getenv("AWS_ACCESS_KEY_ID"),
                    aws_secret_access_key=aws_secret_key or os.getenv("AWS_SECRET_ACCESS_KEY")
                )
                print(f"✅ S3 storage initialized: {s3_bucket}")
            except Exception as e:
                print(f"⚠️ S3 initialization failed: {e}")
                self.storage_type = "local"
        
        # Initialize threshold encryption
        self.threshold_encryption = ThresholdEncryption()
        
        # Initialize consent manager if available
        self.consent_manager = None
        if CONSENT_AVAILABLE:
            try:
                self.consent_manager = ConsentManager()
            except Exception as e:
                print(f"⚠️ Consent manager initialization failed: {e}")
        
        # Initialize storage proof client if available
        self.storage_proof_client = None
        if STORAGE_PROOF_AVAILABLE and enable_storage_proof:
            try:
                self.storage_proof_client = StorageProofClient()
            except Exception as e:
                print(f"⚠️ Storage proof client initialization failed: {e}")
        
        # Storage for DEKs and metadata
        self.deks: Dict[str, DataEncryptionKey] = {}
        self.encrypted_blobs: Dict[str, EncryptedBlob] = {}
        self.metadata_path = self.storage_path / "metadata.json"
        self._load_metadata()
    
    def _load_metadata(self):
        """Load metadata from storage."""
        try:
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    data = json.load(f)
                    self.deks = {k: DataEncryptionKey(**v) for k, v in data.get('deks', {}).items()}
                    self.encrypted_blobs = {k: EncryptedBlob(**v) for k, v in data.get('blobs', {}).items()}
        except Exception as e:
            print(f"⚠️ Failed to load metadata: {e}")
    
    def _save_metadata(self):
        """Save metadata to storage."""
        try:
            data = {
                'deks': {k: asdict(v) for k, v in self.deks.items()},
                'blobs': {k: asdict(v) for k, v in self.encrypted_blobs.items()}
            }
            with open(self.metadata_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save metadata: {e}")
    
    def _check_consent(self, user_did: str, scope: str) -> bool:
        """Check if user has valid consent for the given scope."""
        if not self.consent_manager:
            return True  # No consent system, allow access
        
        try:
            # Get user's consents
            user_consents = self.consent_manager.list_consents_for_subject(user_did)
            
            # Check if any consent is active and covers the scope
            for consent in user_consents:
                if (self.consent_manager.check_consent_active(consent.consent_id) and
                    scope in consent.data_categories):
                    return True
            
            return False
        except Exception as e:
            print(f"⚠️ Consent check failed: {e}")
            return False
    
    def _generate_dek(self, owner_did: str, scope: str, expires_hours: int = 24) -> DataEncryptionKey:
        """Generate a new Data Encryption Key."""
        key_id = f"dek_{uuid.uuid4().hex[:16]}"
        key_material = secrets.token_bytes(32)  # 256 bits
        
        dek = DataEncryptionKey(
            key_id=key_id,
            key_material=key_material,
            created_at=time.time(),
            expires_at=time.time() + (expires_hours * 3600),
            scope=scope,
            owner_did=owner_did,
            wrapped_keys={}
        )
        
        self.deks[key_id] = dek
        self._save_metadata()
        
        return dek
    
    def _get_or_create_dek(self, owner_did: str, scope: str) -> Optional[DataEncryptionKey]:
        """Get existing DEK or create new one."""
        # Check for existing valid DEK
        for dek in self.deks.values():
            if (dek.owner_did == owner_did and 
                dek.scope == scope and 
                dek.expires_at > time.time()):
                return dek
        
        # Create new DEK
        return self._generate_dek(owner_did, scope)
    
    def _encrypt_data(self, data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM."""
        nonce = secrets.token_bytes(12)  # 96 bits for GCM
        aesgcm = AESGCM(key)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        return encrypted_data, nonce
    
    def _decrypt_data(self, encrypted_data: bytes, nonce: bytes, key: bytes) -> Optional[bytes]:
        """Decrypt data using AES-256-GCM."""
        try:
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            return decrypted_data
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return None
    
    def _store_blob_data(self, blob: EncryptedBlob) -> str:
        """Store encrypted blob data and return CID/path."""
        if self.storage_type == "s3":
            return self._store_s3(blob)
        else:
            return self._store_local(blob)
    
    def _store_local(self, blob: EncryptedBlob) -> str:
        """Store blob locally and return file path."""
        blob_path = self.storage_path / "blobs" / f"{blob.record_id}.enc"
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(blob_path, 'wb') as f:
            f.write(blob.encrypted_data)
        
        return str(blob_path)
    
    def _store_s3(self, blob: EncryptedBlob) -> str:
        """Store blob in S3 and return S3 key."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized")
        
        s3_key = f"blobs/{blob.record_id}.enc"
        
        try:
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=s3_key,
                Body=blob.encrypted_data,
                ContentType='application/octet-stream',
                Metadata={
                    'record_id': blob.record_id,
                    'owner_did': blob.owner_did,
                    'scope': blob.scope,
                    'created_at': str(blob.created_at)
                }
            )
            return s3_key
        except ClientError as e:
            raise RuntimeError(f"S3 storage failed: {e}")
    
    def _fetch_blob_data(self, record_id: str) -> Optional[EncryptedBlob]:
        """Fetch blob data from storage."""
        if record_id not in self.encrypted_blobs:
            return None
        
        blob = self.encrypted_blobs[record_id]
        
        if self.storage_type == "s3":
            return self._fetch_s3(blob)
        else:
            return self._fetch_local(blob)
    
    def _fetch_local(self, blob: EncryptedBlob) -> Optional[EncryptedBlob]:
        """Fetch blob from local storage."""
        blob_path = self.storage_path / "blobs" / f"{blob.record_id}.enc"
        
        if not blob_path.exists():
            return None
        
        with open(blob_path, 'rb') as f:
            blob.encrypted_data = f.read()
        
        return blob
    
    def _fetch_s3(self, blob: EncryptedBlob) -> Optional[EncryptedBlob]:
        """Fetch blob from S3."""
        if not self.s3_client:
            return None
        
        s3_key = f"blobs/{blob.record_id}.enc"
        
        try:
            response = self.s3_client.get_object(Bucket=self.s3_bucket, Key=s3_key)
            blob.encrypted_data = response['Body'].read()
            return blob
        except ClientError as e:
            print(f"❌ S3 fetch failed: {e}")
            return None
    
    def store_blob(self, user_did: str, plaintext: str, scope: str) -> Optional[str]:
        """
        Store encrypted blob with consent validation.
        
        Args:
            user_did: User's Decentralized Identifier
            plaintext: Data to encrypt and store
            scope: Data scope/category
            
        Returns:
            Record ID if successful, None otherwise
        """
        # Check consent
        if not self._check_consent(user_did, scope):
            print(f"❌ No valid consent for user {user_did} and scope {scope}")
            return None
        
        try:
            # Get or create DEK
            dek = self._get_or_create_dek(user_did, scope)
            if not dek:
                print("❌ Failed to get/create DEK")
                return None
            
            # Encrypt data
            data_bytes = plaintext.encode('utf-8')
            encrypted_data, nonce = self._encrypt_data(data_bytes, dek.key_material)
            
            # Create encrypted blob
            record_id = f"blob_{uuid.uuid4().hex[:16]}"
            blob = EncryptedBlob(
                record_id=record_id,
                encrypted_data=encrypted_data,
                nonce=nonce,
                key_id=dek.key_id,
                scope=scope,
                owner_did=user_did,
                created_at=time.time(),
                content_type="text/plain",
                size=len(data_bytes)
            )
            
            # Store blob data
            storage_path = self._store_blob_data(blob)
            
            # Store metadata
            self.encrypted_blobs[record_id] = blob
            self._save_metadata()
            
            # Record storage proof if available
            if self.storage_proof_client:
                try:
                    # Compute blob hash
                    blob_hash = hashlib.sha256(encrypted_data).hexdigest()
                    
                    # Compute conversation hash (simplified - in production, get from context)
                    conversation_hash = hashlib.sha256(f"{user_did}:{scope}:{time.time()}".encode()).hexdigest()
                    
                    # Record storage proof
                    self.storage_proof_client.record_storage(
                        blob_hash=blob_hash,
                        storage_uri=storage_path,
                        provider_id=self.storage_type,
                        region=self._get_storage_region(),
                        conversation_hash=conversation_hash
                    )
                except Exception as e:
                    print(f"⚠️ Failed to record storage proof: {e}")
            
            print(f"✅ Stored blob {record_id} at {storage_path}")
            return record_id
            
        except Exception as e:
            print(f"❌ Failed to store blob: {e}")
            return None
    
    def fetch_blob(self, viewer_did: str, record_id: str, scope: str) -> Optional[str]:
        """
        Fetch and decrypt blob with consent validation.
        
        Args:
            viewer_did: Viewer's Decentralized Identifier
            record_id: Record ID to fetch
            scope: Data scope/category
            
        Returns:
            Decrypted plaintext if successful, None otherwise
        """
        # Check consent
        if not self._check_consent(viewer_did, scope):
            print(f"❌ No valid consent for viewer {viewer_did} and scope {scope}")
            return None
        
        try:
            # Get blob metadata
            if record_id not in self.encrypted_blobs:
                print(f"❌ Blob {record_id} not found")
                return None
            
            blob = self.encrypted_blobs[record_id]
            
            # Check if viewer has access (simplified - in production, use proper access control)
            if blob.owner_did != viewer_did:
                # Check if owner has shared access with viewer
                if blob.key_id not in self.deks:
                    print(f"❌ DEK {blob.key_id} not found")
                    return None
                
                dek = self.deks[blob.key_id]
                if viewer_did not in dek.wrapped_keys:
                    print(f"❌ No access granted to {viewer_did}")
                    return None
            
            # Fetch blob data
            blob = self._fetch_blob_data(record_id)
            if not blob:
                print(f"❌ Failed to fetch blob data for {record_id}")
                return None
            
            # Get decryption key
            if blob.owner_did == viewer_did:
                # Owner accessing their own data
                if blob.key_id not in self.deks:
                    print(f"❌ DEK {blob.key_id} not found")
                    return None
                key = self.deks[blob.key_id].key_material
            else:
                # Viewer accessing shared data
                if blob.key_id not in self.deks:
                    print(f"❌ DEK {blob.key_id} not found")
                    return None
                
                dek = self.deks[blob.key_id]
                if viewer_did not in dek.wrapped_keys:
                    print(f"❌ No wrapped key for {viewer_did}")
                    return None
                
                # Unwrap key for viewer
                wrapped_key = dek.wrapped_keys[viewer_did]
                key = self.threshold_encryption.unwrap_key(wrapped_key, viewer_did)
                if not key:
                    print(f"❌ Failed to unwrap key for {viewer_did}")
                    return None
            
            # Decrypt data
            decrypted_data = self._decrypt_data(blob.encrypted_data, blob.nonce, key)
            if not decrypted_data:
                print(f"❌ Failed to decrypt blob {record_id}")
                return None
            
            print(f"✅ Fetched and decrypted blob {record_id}")
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            print(f"❌ Failed to fetch blob: {e}")
            return None
    
    def share_access(self, owner_did: str, viewer_did: str, scope: str) -> bool:
        """
        Share access to encrypted data with another user.
        
        Args:
            owner_did: Owner's Decentralized Identifier
            viewer_did: Viewer's Decentralized Identifier
            scope: Data scope/category
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get owner's DEK
            dek = self._get_or_create_dek(owner_did, scope)
            if not dek:
                print("❌ Failed to get owner's DEK")
                return False
            
            # Wrap key for viewer
            wrapped_key = self.threshold_encryption.wrap_key(dek.key_material, viewer_did)
            dek.wrapped_keys[viewer_did] = wrapped_key
            
            self._save_metadata()
            print(f"✅ Shared access to {scope} data with {viewer_did}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to share access: {e}")
            return False
    
    def revoke_access(self, owner_did: str, viewer_did: str, scope: str) -> bool:
        """
        Revoke access to encrypted data.
        
        Args:
            owner_did: Owner's Decentralized Identifier
            viewer_did: Viewer's Decentralized Identifier
            scope: Data scope/category
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get owner's DEK
            dek = self._get_or_create_dek(owner_did, scope)
            if not dek:
                return False
            
            # Remove wrapped key for viewer
            if viewer_did in dek.wrapped_keys:
                del dek.wrapped_keys[viewer_did]
                self._save_metadata()
                print(f"✅ Revoked access to {scope} data for {viewer_did}")
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Failed to revoke access: {e}")
            return False
    
    def list_user_blobs(self, user_did: str, scope: str = None) -> List[Dict[str, Any]]:
        """
        List all blobs for a user.
        
        Args:
            user_did: User's Decentralized Identifier
            scope: Optional scope filter
            
        Returns:
            List of blob metadata
        """
        blobs = []
        for blob in self.encrypted_blobs.values():
            if blob.owner_did == user_did:
                if scope is None or blob.scope == scope:
                    blobs.append({
                        'record_id': blob.record_id,
                        'scope': blob.scope,
                        'created_at': blob.created_at,
                        'size': blob.size,
                        'content_type': blob.content_type
                    })
        return blobs
    
    def _get_storage_region(self) -> str:
        """Get storage region based on storage type."""
        if self.storage_type == "s3" and self.s3_bucket:
            # Try to get region from S3 client
            try:
                if self.s3_client:
                    response = self.s3_client.get_bucket_location(Bucket=self.s3_bucket)
                    region = response.get('LocationConstraint', 'us-east-1')
                    return region if region else 'us-east-1'
            except Exception:
                pass
            return 'us-east-1'  # Default AWS region
        else:
            return 'local'
    
    def cleanup_expired_keys(self):
        """Clean up expired DEKs."""
        current_time = time.time()
        expired_keys = []
        
        for key_id, dek in self.deks.items():
            if dek.expires_at <= current_time:
                expired_keys.append(key_id)
        
        for key_id in expired_keys:
            del self.deks[key_id]
        
        if expired_keys:
            self._save_metadata()
            print(f"🧹 Cleaned up {len(expired_keys)} expired keys")
    
    def create_tombstone(self, record_id: str, reason: str = "consent_revoked") -> bool:
        """
        Create a tombstone for a blob record.
        
        Args:
            record_id: Record ID to tombstone
            reason: Reason for tombstoning
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if record_id not in self.encrypted_blobs:
                print(f"❌ Blob record not found: {record_id}")
                return False
            
            blob = self.encrypted_blobs[record_id]
            
            # Create tombstone in storage proof system
            if self.storage_proof_client:
                try:
                    # Compute blob hash
                    blob_hash = hashlib.sha256(blob.encrypted_data).hexdigest()
                    
                    # Create tombstone
                    self.storage_proof_client.create_tombstone(blob_hash, reason)
                except Exception as e:
                    print(f"⚠️ Failed to create storage proof tombstone: {e}")
            
            # Mark blob as inactive locally
            blob.size = 0  # Mark as deleted
            self._save_metadata()
            
            print(f"✅ Created tombstone for {record_id}: {reason}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to create tombstone: {e}")
            return False


def main():
    """CLI entry point for key broker."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Key Broker System")
    parser.add_argument("--store", nargs=3, metavar=("USER_DID", "PLAINTEXT", "SCOPE"), 
                       help="Store encrypted blob")
    parser.add_argument("--fetch", nargs=3, metavar=("VIEWER_DID", "RECORD_ID", "SCOPE"),
                       help="Fetch and decrypt blob")
    parser.add_argument("--share", nargs=3, metavar=("OWNER_DID", "VIEWER_DID", "SCOPE"),
                       help="Share access to data")
    parser.add_argument("--list", nargs=2, metavar=("USER_DID", "SCOPE"),
                       help="List user's blobs")
    
    args = parser.parse_args()
    
    # Initialize key broker
    broker = KeyBroker()
    
    if args.store:
        user_did, plaintext, scope = args.store
        record_id = broker.store_blob(user_did, plaintext, scope)
        if record_id:
            print(f"✅ Stored blob: {record_id}")
        else:
            print("❌ Failed to store blob")
    
    elif args.fetch:
        viewer_did, record_id, scope = args.fetch
        plaintext = broker.fetch_blob(viewer_did, record_id, scope)
        if plaintext:
            print(f"✅ Decrypted data: {plaintext}")
        else:
            print("❌ Failed to fetch blob")
    
    elif args.share:
        owner_did, viewer_did, scope = args.share
        if broker.share_access(owner_did, viewer_did, scope):
            print("✅ Access shared successfully")
        else:
            print("❌ Failed to share access")
    
    elif args.list:
        user_did, scope = args.list
        blobs = broker.list_user_blobs(user_did, scope)
        if blobs:
            for blob in blobs:
                print(f"📄 {blob['record_id']} - {blob['scope']} ({blob['size']} bytes)")
        else:
            print("No blobs found")


if __name__ == "__main__":
    main()
