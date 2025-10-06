"""
Consent management system with Verifiable Credentials and blockchain integration.

This module provides:
- Verifiable Credential creation for consent receipts
- Blockchain integration with ConsentRegistry contract
- Consent validation before data processing
- Encryption/decryption with consent checks
"""

import os
import json
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

from web3 import Web3
from web3.middleware import geth_poa_middleware


@dataclass
class ConsentReceipt:
    """Represents a consent receipt with all necessary information."""
    consent_id: str
    subject_did: str
    controller_did: str
    purpose: str
    data_categories: List[str]
    processing_activities: List[str]
    legal_basis: str
    retention_period: int  # days
    expires_at: int  # unix timestamp
    created_at: int  # unix timestamp
    consent_hash: str


@dataclass
class VerifiableCredential:
    """Represents a Verifiable Credential for consent."""
    context: List[str]
    type: List[str]
    id: str
    issuer: str
    issuance_date: str
    expiration_date: str
    credential_subject: Dict[str, Any]
    proof: Dict[str, Any]


class ConsentManager:
    """Main class for managing consent and data protection."""
    
    def __init__(self, 
                 rpc_url: str = None,
                 contract_address: str = None,
                 private_key: str = None,
                 encryption_key: str = None):
        """
        Initialize the consent manager.
        
        Args:
            rpc_url: Blockchain RPC URL
            contract_address: ConsentRegistry contract address
            private_key: Private key for blockchain transactions
            encryption_key: Key for data encryption (defaults to env var)
        """
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL")
        self.contract_address = contract_address or os.getenv("CONSENT_REGISTRY_ADDRESS")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        self.encryption_key = encryption_key or os.getenv("ENCRYPTION_KEY")
        
        # Initialize Web3 if blockchain config is available
        self.w3 = None
        self.contract = None
        if self.rpc_url and self.contract_address and self.private_key:
            self._init_blockchain()
        
        # Initialize encryption
        self._init_encryption()
        
        # Storage for consent receipts
        self.consent_receipts: Dict[str, ConsentReceipt] = {}
        self.consent_storage_path = "privacy/consent_storage.json"
        self._load_consent_storage()
    
    def _init_blockchain(self):
        """Initialize Web3 connection and contract."""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # ConsentRegistry contract ABI
            contract_abi = [
                {
                    "inputs": [
                        {"name": "_consentId", "type": "bytes32"},
                        {"name": "_subjectDid", "type": "string"},
                        {"name": "_controllerDid", "type": "string"},
                        {"name": "_consentHash", "type": "string"},
                        {"name": "_expiresAt", "type": "uint256"}
                    ],
                    "name": "setConsent",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_consentId", "type": "bytes32"}],
                    "name": "revokeConsent",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_consentId", "type": "bytes32"}],
                    "name": "isActive",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_consentId", "type": "bytes32"}],
                    "name": "consentExists",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )
            
            print(f"✅ Consent blockchain initialized: {self.w3.eth.chain_id}")
        except Exception as e:
            print(f"⚠️ Blockchain initialization failed: {e}")
            self.w3 = None
            self.contract = None
    
    def _init_encryption(self):
        """Initialize encryption system."""
        if not self.encryption_key:
            # Generate a new key if none provided
            self.encryption_key = Fernet.generate_key().decode()
            print(f"🔑 Generated new encryption key: {self.encryption_key[:16]}...")
        else:
            self.encryption_key = self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key
        
        self.cipher = Fernet(self.encryption_key)
    
    def _load_consent_storage(self):
        """Load consent storage from file."""
        try:
            if os.path.exists(self.consent_storage_path):
                with open(self.consent_storage_path, 'r') as f:
                    data = json.load(f)
                    for consent_id, receipt_data in data.items():
                        self.consent_receipts[consent_id] = ConsentReceipt(**receipt_data)
        except Exception as e:
            print(f"⚠️ Failed to load consent storage: {e}")
    
    def _save_consent_storage(self):
        """Save consent storage to file."""
        try:
            os.makedirs(os.path.dirname(self.consent_storage_path), exist_ok=True)
            data = {k: asdict(v) for k, v in self.consent_receipts.items()}
            with open(self.consent_storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save consent storage: {e}")
    
    def create_verifiable_credential(self, 
                                   consent_receipt: ConsentReceipt,
                                   issuer_did: str,
                                   issuer_private_key: str = None) -> VerifiableCredential:
        """
        Create a Verifiable Credential for consent.
        
        Args:
            consent_receipt: The consent receipt to create VC for
            issuer_did: DID of the issuer
            issuer_private_key: Private key for signing (optional)
            
        Returns:
            VerifiableCredential object
        """
        # Create credential ID
        credential_id = f"did:example:consent:{consent_receipt.consent_id}"
        
        # Create credential subject
        credential_subject = {
            "id": consent_receipt.subject_did,
            "consentId": consent_receipt.consent_id,
            "purpose": consent_receipt.purpose,
            "dataCategories": consent_receipt.data_categories,
            "processingActivities": consent_receipt.processing_activities,
            "legalBasis": consent_receipt.legal_basis,
            "retentionPeriod": consent_receipt.retention_period,
            "expiresAt": consent_receipt.expires_at,
            "createdAt": consent_receipt.created_at
        }
        
        # Create proof (simplified for demo)
        proof = {
            "type": "EcdsaSecp256k1Signature2019",
            "created": datetime.utcnow().isoformat() + "Z",
            "verificationMethod": f"{issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "jws": "eyJhbGciOiJFUzI1NksiLCJjcml0IjpbImI2NCJdLCJiNjQiOmZhbHNlfQ..."  # Placeholder
        }
        
        return VerifiableCredential(
            context=[
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/consent/v1"
            ],
            type=[
                "VerifiableCredential",
                "ConsentCredential"
            ],
            id=credential_id,
            issuer=issuer_did,
            issuance_date=datetime.utcnow().isoformat() + "Z",
            expiration_date=datetime.fromtimestamp(consent_receipt.expires_at).isoformat() + "Z",
            credential_subject=credential_subject,
            proof=proof
        )
    
    def create_consent_receipt(self,
                             subject_did: str,
                             controller_did: str,
                             purpose: str,
                             data_categories: List[str],
                             processing_activities: List[str],
                             legal_basis: str = "consent",
                             retention_period_days: int = 365) -> ConsentReceipt:
        """
        Create a consent receipt.
        
        Args:
            subject_did: DID of the subject (user)
            controller_did: DID of the controller (service)
            purpose: Purpose of data processing
            data_categories: Categories of data being processed
            processing_activities: Activities being performed
            legal_basis: Legal basis for processing
            retention_period_days: How long to retain data
            
        Returns:
            ConsentReceipt object
        """
        # Generate unique consent ID
        consent_id = f"consent_{int(time.time())}_{secrets.token_hex(8)}"
        
        # Calculate expiration (1 year from now)
        expires_at = int(time.time()) + (retention_period_days * 24 * 60 * 60)
        
        # Create consent receipt
        receipt = ConsentReceipt(
            consent_id=consent_id,
            subject_did=subject_did,
            controller_did=controller_did,
            purpose=purpose,
            data_categories=data_categories,
            processing_activities=processing_activities,
            legal_basis=legal_basis,
            retention_period=retention_period_days,
            expires_at=expires_at,
            created_at=int(time.time()),
            consent_hash=""  # Will be computed after VC creation
        )
        
        # Create Verifiable Credential
        vc = self.create_verifiable_credential(receipt, controller_did)
        
        # Compute hash of the VC
        vc_json = json.dumps(asdict(vc), sort_keys=True, separators=(',', ':'))
        receipt.consent_hash = hashlib.sha256(vc_json.encode()).hexdigest()
        
        # Store locally
        self.consent_receipts[consent_id] = receipt
        self._save_consent_storage()
        
        return receipt
    
    def register_consent_on_blockchain(self, consent_receipt: ConsentReceipt) -> bool:
        """
        Register consent on the blockchain.
        
        Args:
            consent_receipt: The consent receipt to register
            
        Returns:
            True if successful, False otherwise
        """
        if not self.w3 or not self.contract:
            print("⚠️ Blockchain not available for consent registration")
            return False
        
        try:
            # Convert consent ID to bytes32
            consent_id_bytes = Web3.keccak(text=consent_receipt.consent_id)
            
            # Build transaction
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.setConsent(
                consent_id_bytes,
                consent_receipt.subject_did,
                consent_receipt.controller_did,
                consent_receipt.consent_hash,
                consent_receipt.expires_at
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            # Sign and send transaction
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Consent registered on blockchain: {receipt.transactionHash.hex()}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to register consent on blockchain: {e}")
            return False
    
    def check_consent_active(self, consent_id: str) -> bool:
        """
        Check if consent is active (not revoked and not expired).
        
        Args:
            consent_id: The consent ID to check
            
        Returns:
            True if consent is active, False otherwise
        """
        # Check local storage first
        if consent_id not in self.consent_receipts:
            return False
        
        local_receipt = self.consent_receipts[consent_id]
        
        # Check if expired locally
        if local_receipt.expires_at <= time.time():
            return False
        
        # Check blockchain if available
        if self.w3 and self.contract:
            try:
                consent_id_bytes = Web3.keccak(text=consent_id)
                is_active = self.contract.functions.isActive(consent_id_bytes).call()
                return is_active
            except Exception as e:
                print(f"⚠️ Failed to check consent on blockchain: {e}")
                # Fall back to local check
                return True
        
        return True
    
    def revoke_consent(self, consent_id: str) -> bool:
        """
        Revoke consent.
        
        Args:
            consent_id: The consent ID to revoke
            
        Returns:
            True if successful, False otherwise
        """
        if consent_id not in self.consent_receipts:
            print(f"❌ Consent {consent_id} not found")
            return False
        
        # Revoke on blockchain if available
        if self.w3 and self.contract:
            try:
                consent_id_bytes = Web3.keccak(text=consent_id)
                
                account = self.w3.eth.account.from_key(self.private_key)
                
                transaction = self.contract.functions.revokeConsent(
                    consent_id_bytes
                ).build_transaction({
                    'from': account.address,
                    'gas': 100000,
                    'gasPrice': self.w3.eth.gas_price,
                    'nonce': self.w3.eth.get_transaction_count(account.address),
                })
                
                signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                print(f"✅ Consent revoked on blockchain: {receipt.transactionHash.hex()}")
                
            except Exception as e:
                print(f"❌ Failed to revoke consent on blockchain: {e}")
                return False
        
        # Remove from local storage
        del self.consent_receipts[consent_id]
        self._save_consent_storage()
        
        return True
    
    def encrypt_data(self, data: str, consent_id: str) -> Optional[str]:
        """
        Encrypt data only if valid consent exists.
        
        Args:
            data: Data to encrypt
            consent_id: Consent ID to check
            
        Returns:
            Encrypted data if consent is valid, None otherwise
        """
        if not self.check_consent_active(consent_id):
            print(f"❌ No active consent for {consent_id}")
            return None
        
        try:
            encrypted_data = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return None
    
    def decrypt_data(self, encrypted_data: str, consent_id: str) -> Optional[str]:
        """
        Decrypt data only if valid consent exists.
        
        Args:
            encrypted_data: Data to decrypt
            consent_id: Consent ID to check
            
        Returns:
            Decrypted data if consent is valid, None otherwise
        """
        if not self.check_consent_active(consent_id):
            print(f"❌ No active consent for {consent_id}")
            return None
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return None
    
    def get_consent_receipt(self, consent_id: str) -> Optional[ConsentReceipt]:
        """Get consent receipt by ID."""
        return self.consent_receipts.get(consent_id)
    
    def list_consents_for_subject(self, subject_did: str) -> List[ConsentReceipt]:
        """Get all consents for a subject."""
        return [receipt for receipt in self.consent_receipts.values() 
                if receipt.subject_did == subject_did]
    
    def list_consents_for_controller(self, controller_did: str) -> List[ConsentReceipt]:
        """Get all consents for a controller."""
        return [receipt for receipt in self.consent_receipts.values() 
                if receipt.controller_did == controller_did]


def main():
    """CLI entry point for consent management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Consent Management System")
    parser.add_argument("--create-consent", action="store_true", help="Create a new consent")
    parser.add_argument("--check-consent", type=str, help="Check if consent is active")
    parser.add_argument("--revoke-consent", type=str, help="Revoke a consent")
    parser.add_argument("--list-consents", action="store_true", help="List all consents")
    
    args = parser.parse_args()
    
    # Initialize consent manager
    manager = ConsentManager()
    
    if args.create_consent:
        # Create sample consent
        receipt = manager.create_consent_receipt(
            subject_did="did:example:user123",
            controller_did="did:example:mentalhealthbot",
            purpose="Mental health support and counseling",
            data_categories=["health_data", "conversation_data", "sentiment_data"],
            processing_activities=["analysis", "storage", "anonymization"],
            legal_basis="consent",
            retention_period_days=365
        )
        
        print(f"✅ Created consent: {receipt.consent_id}")
        print(f"📋 Consent hash: {receipt.consent_hash}")
        
        # Register on blockchain
        if manager.register_consent_on_blockchain(receipt):
            print("🔗 Consent registered on blockchain")
    
    elif args.check_consent:
        is_active = manager.check_consent_active(args.check_consent)
        print(f"Consent {args.check_consent} is {'active' if is_active else 'inactive'}")
    
    elif args.revoke_consent:
        if manager.revoke_consent(args.revoke_consent):
            print(f"✅ Consent {args.revoke_consent} revoked")
        else:
            print(f"❌ Failed to revoke consent {args.revoke_consent}")
    
    elif args.list_consents:
        consents = list(manager.consent_receipts.values())
        if consents:
            for consent in consents:
                status = "active" if manager.check_consent_active(consent.consent_id) else "inactive"
                print(f"📋 {consent.consent_id} - {status} (expires: {datetime.fromtimestamp(consent.expires_at)})")
        else:
            print("No consents found")


if __name__ == "__main__":
    main()
