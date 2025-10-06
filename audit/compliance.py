"""
Compliance Module for Lightweight Policy Checking and Blockchain Verification.

This module provides:
- Lightweight policy compliance checking
- Digital signing of compliance results
- Blockchain storage of compliance hashes
- Verification against blockchain data
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
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from web3 import Web3
from web3.middleware import geth_poa_middleware

# Import policy system
try:
    from .policy import PolicyRuleEngine
    POLICY_AVAILABLE = True
except ImportError:
    POLICY_AVAILABLE = False
    print("⚠️ Policy system not available - compliance will use basic checks")


@dataclass
class ComplianceMetrics:
    """Metrics for compliance checking."""
    rogerian_score: float
    diagnostic_language_score: float
    empathy_score: float
    safety_score: float
    response_length_score: float
    overall_score: float
    checks_performed: int
    checks_passed: int


@dataclass
class ComplianceResult:
    """Result of a compliance check."""
    conversation_hash: str
    policy_check_id: str
    pass_status: bool
    metrics: ComplianceMetrics
    timestamp: float
    signature: str
    compliance_hash: str


@dataclass
class ComplianceRecord:
    """Blockchain compliance record."""
    conversation_hash: str
    policy_check_id: str
    pass_status: bool
    compliance_hash: str
    timestamp: float
    signature: str


class ComplianceChecker:
    """Lightweight compliance checker for conversation analysis."""
    
    def __init__(self):
        self.rule_engine = PolicyRuleEngine() if POLICY_AVAILABLE else None
    
    def check_rogerian_principles(self, user_input: str, response: str) -> Tuple[float, Dict[str, Any]]:
        """
        Check if response follows Rogerian principles.
        
        Returns:
            Tuple of (score, details)
        """
        rogerian_patterns = [
            r'\b(I hear|I understand|I can see)\b',
            r'\b(how does that feel|what is that like)\b',
            r'\b(would you like to share|tell me more)\b',
            r'\b(it sounds like|I can sense)\b',
            r'\b(that must be|that would be)\b'
        ]
        
        directive_patterns = [
            r'\b(you should|you must|you need to)\b',
            r'\b(try this|do this|follow this)\b',
            r'\b(I recommend|I suggest|I advise)\b',
            r'\b(here\'s what you do|the solution is)\b'
        ]
        
        rogerian_count = sum(len(re.findall(pattern, response, re.I)) for pattern in rogerian_patterns)
        directive_count = sum(len(re.findall(pattern, response, re.I)) for pattern in directive_patterns)
        
        # Calculate score (higher Rogerian, lower directive = better)
        if rogerian_count > 0 and directive_count == 0:
            score = 1.0
        elif rogerian_count > directive_count:
            score = 0.8
        elif rogerian_count == directive_count:
            score = 0.5
        else:
            score = 0.2
        
        return score, {
            "rogerian_indicators": rogerian_count,
            "directive_indicators": directive_count,
            "score_explanation": f"Rogerian: {rogerian_count}, Directive: {directive_count}"
        }
    
    def check_diagnostic_language(self, user_input: str, response: str) -> Tuple[float, Dict[str, Any]]:
        """
        Check if response avoids diagnostic language.
        
        Returns:
            Tuple of (score, details)
        """
        diagnostic_patterns = [
            r'\b(you have|you are|you\'re)\s+(depressed|anxious|bipolar|OCD|PTSD)\b',
            r'\b(diagnosis|symptoms|disorder|condition)\b',
            r'\b(you need therapy|you need medication|you need treatment)\b',
            r'\b(clinical|pathological|abnormal)\b'
        ]
        
        diagnostic_count = sum(len(re.findall(pattern, response, re.I)) for pattern in diagnostic_patterns)
        
        # Score decreases with diagnostic language
        if diagnostic_count == 0:
            score = 1.0
        elif diagnostic_count == 1:
            score = 0.6
        elif diagnostic_count == 2:
            score = 0.3
        else:
            score = 0.0
        
        return score, {
            "diagnostic_indicators": diagnostic_count,
            "score_explanation": f"Found {diagnostic_count} diagnostic language patterns"
        }
    
    def check_empathy_indicators(self, user_input: str, response: str) -> Tuple[float, Dict[str, Any]]:
        """
        Check for empathy indicators in response.
        
        Returns:
            Tuple of (score, details)
        """
        empathy_patterns = [
            r'\b(I understand|I hear you|I can see)\b',
            r'\b(that sounds|it sounds like|I can imagine)\b',
            r'\b(that must be|that would be|I can sense)\b',
            r'\b(thank you for sharing|I appreciate you telling me)\b',
            r'\b(I\'m here for you|you\'re not alone)\b'
        ]
        
        empathy_count = sum(len(re.findall(pattern, response, re.I)) for pattern in empathy_patterns)
        
        if empathy_count >= 3:
            score = 1.0
        elif empathy_count == 2:
            score = 0.8
        elif empathy_count == 1:
            score = 0.6
        else:
            score = 0.3
        
        return score, {
            "empathy_indicators": empathy_count,
            "score_explanation": f"Found {empathy_count} empathy indicators"
        }
    
    def check_safety_protocols(self, user_input: str, response: str) -> Tuple[float, Dict[str, Any]]:
        """
        Check safety protocol compliance.
        
        Returns:
            Tuple of (score, details)
        """
        crisis_keywords = [
            r'\b(suicide|kill myself|end it|bunuh diri)\b',
            r'\b(harm myself|hurt myself|self harm)\b',
            r'\b(die|death|not worth living)\b'
        ]
        
        safety_patterns = [
            r'\b(emergency|crisis|immediate help)\b',
            r'\b(hotline|helpline|support line)\b',
            r'\b(trusted person|professional help)\b',
            r'\b(you are not alone|people care)\b'
        ]
        
        inappropriate_patterns = [
            r'\b(it\'s not that bad|you\'ll get over it)\b',
            r'\b(think positive|just be happy)\b',
            r'\b(other people have it worse)\b'
        ]
        
        has_crisis = any(re.search(pattern, user_input, re.I) for pattern in crisis_keywords)
        safety_count = sum(len(re.findall(pattern, response, re.I)) for pattern in safety_patterns)
        inappropriate_count = sum(len(re.findall(pattern, response, re.I)) for pattern in inappropriate_patterns)
        
        if has_crisis:
            if inappropriate_count > 0:
                score = 0.0
            elif safety_count >= 2:
                score = 1.0
            elif safety_count == 1:
                score = 0.6
            else:
                score = 0.2
        else:
            score = 1.0  # No crisis detected, no safety issues
        
        return score, {
            "crisis_detected": has_crisis,
            "safety_indicators": safety_count,
            "inappropriate_indicators": inappropriate_count,
            "score_explanation": f"Crisis: {has_crisis}, Safety: {safety_count}, Inappropriate: {inappropriate_count}"
        }
    
    def check_response_length(self, user_input: str, response: str) -> Tuple[float, Dict[str, Any]]:
        """
        Check if response length is appropriate.
        
        Returns:
            Tuple of (score, details)
        """
        sentences = re.split(r'[.!?]+', response.strip())
        sentence_count = len([s for s in sentences if s.strip()])
        
        if 2 <= sentence_count <= 4:
            score = 1.0
        elif sentence_count == 1:
            score = 0.7
        elif sentence_count == 5:
            score = 0.8
        else:
            score = 0.5
        
        return score, {
            "sentence_count": sentence_count,
            "score_explanation": f"Response has {sentence_count} sentences"
        }
    
    def run_compliance_check(self, user_input: str, response: str, language: str = "en") -> ComplianceMetrics:
        """
        Run all compliance checks and return metrics.
        
        Args:
            user_input: User's input message
            response: AI's response message
            language: Language code (en/ms)
            
        Returns:
            ComplianceMetrics object
        """
        # Run individual checks
        rogerian_score, rogerian_details = self.check_rogerian_principles(user_input, response)
        diagnostic_score, diagnostic_details = self.check_diagnostic_language(user_input, response)
        empathy_score, empathy_details = self.check_empathy_indicators(user_input, response)
        safety_score, safety_details = self.check_safety_protocols(user_input, response)
        length_score, length_details = self.check_response_length(user_input, response)
        
        # Calculate overall score
        scores = [rogerian_score, diagnostic_score, empathy_score, safety_score, length_score]
        overall_score = sum(scores) / len(scores)
        
        # Count checks performed and passed
        checks_performed = len(scores)
        checks_passed = sum(1 for score in scores if score >= 0.7)
        
        return ComplianceMetrics(
            rogerian_score=rogerian_score,
            diagnostic_language_score=diagnostic_score,
            empathy_score=empathy_score,
            safety_score=safety_score,
            response_length_score=length_score,
            overall_score=overall_score,
            checks_performed=checks_performed,
            checks_passed=checks_passed
        )


class ComplianceManager:
    """Main compliance management system."""
    
    def __init__(self, 
                 rpc_url: str = None,
                 contract_address: str = None,
                 private_key: str = None,
                 signing_key_path: str = None):
        """
        Initialize the compliance manager.
        
        Args:
            rpc_url: Blockchain RPC URL
            contract_address: Compliance contract address
            private_key: Private key for blockchain transactions
            signing_key_path: Path to signing private key
        """
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL")
        self.contract_address = contract_address or os.getenv("COMPLIANCE_CONTRACT_ADDRESS")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        self.signing_key_path = signing_key_path or os.getenv("SIGNING_KEY_PATH")
        
        # Initialize compliance checker
        self.checker = ComplianceChecker()
        
        # Initialize signing key
        self.signing_key = self._load_signing_key()
        
        # Initialize Web3 if blockchain config is available
        self.w3 = None
        self.contract = None
        if self.rpc_url and self.contract_address and self.private_key:
            self._init_blockchain()
        
        # Storage for compliance results
        self.compliance_results: Dict[str, ComplianceResult] = {}
        self.storage_path = Path("audit/compliance_storage")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._load_storage()
    
    def _load_signing_key(self):
        """Load or generate signing key."""
        try:
            if self.signing_key_path and os.path.exists(self.signing_key_path):
                with open(self.signing_key_path, 'rb') as f:
                    key_data = f.read()
                return load_pem_private_key(key_data, password=None)
            else:
                # Generate new key
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                
                # Save key if path provided
                if self.signing_key_path:
                    os.makedirs(os.path.dirname(self.signing_key_path), exist_ok=True)
                    with open(self.signing_key_path, 'wb') as f:
                        f.write(key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ))
                
                return key
        except Exception as e:
            print(f"⚠️ Failed to load/generate signing key: {e}")
            return None
    
    def _init_blockchain(self):
        """Initialize Web3 connection and contract."""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Compliance contract ABI
            contract_abi = [
                {
                    "inputs": [
                        {"name": "_conversationHash", "type": "bytes32"},
                        {"name": "_policyCheckId", "type": "bytes32"},
                        {"name": "_passStatus", "type": "bool"},
                        {"name": "_complianceHash", "type": "bytes32"},
                        {"name": "_signature", "type": "bytes"}
                    ],
                    "name": "storeCompliance",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_conversationHash", "type": "bytes32"}],
                    "name": "getCompliance",
                    "outputs": [
                        {
                            "name": "",
                            "type": "tuple",
                            "components": [
                                {"name": "conversationHash", "type": "bytes32"},
                                {"name": "policyCheckId", "type": "bytes32"},
                                {"name": "passStatus", "type": "bool"},
                                {"name": "complianceHash", "type": "bytes32"},
                                {"name": "timestamp", "type": "uint256"},
                                {"name": "signature", "type": "bytes"},
                                {"name": "exists", "type": "bool"}
                            ]
                        }
                    ],
                    "stateMutability": "view",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "_conversationHash", "type": "bytes32"}],
                    "name": "complianceExists",
                    "outputs": [{"name": "", "type": "bool"}],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )
            
            print(f"✅ Compliance blockchain initialized: {self.w3.eth.chain_id}")
        except Exception as e:
            print(f"⚠️ Compliance blockchain initialization failed: {e}")
            self.w3 = None
            self.contract = None
    
    def _load_storage(self):
        """Load compliance results from storage."""
        try:
            storage_file = self.storage_path / "compliance_results.json"
            if storage_file.exists():
                with open(storage_file, 'r') as f:
                    data = json.load(f)
                    self.compliance_results = {k: ComplianceResult(**v) for k, v in data.items()}
        except Exception as e:
            print(f"⚠️ Failed to load compliance storage: {e}")
    
    def _save_storage(self):
        """Save compliance results to storage."""
        try:
            storage_file = self.storage_path / "compliance_results.json"
            with open(storage_file, 'w') as f:
                data = {k: asdict(v) for k, v in self.compliance_results.items()}
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save compliance storage: {e}")
    
    def _sign_data(self, data: str) -> str:
        """Sign data with private key."""
        if not self.signing_key:
            return ""
        
        try:
            signature = self.signing_key.sign(
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            print(f"⚠️ Failed to sign data: {e}")
            return ""
    
    def check_compliance(self, 
                        conversation_hash: str,
                        user_input: str,
                        response: str,
                        language: str = "en") -> ComplianceResult:
        """
        Check compliance for a conversation and store result.
        
        Args:
            conversation_hash: Hash of the conversation
            user_input: User's input message
            response: AI's response message
            language: Language code (en/ms)
            
        Returns:
            ComplianceResult object
        """
        try:
            # Run compliance check
            metrics = self.checker.run_compliance_check(user_input, response, language)
            
            # Determine pass status (70% threshold)
            pass_status = metrics.overall_score >= 0.7
            
            # Generate policy check ID
            policy_check_id = f"check_{uuid.uuid4().hex[:16]}"
            
            # Create compliance data for signing
            compliance_data = {
                "conversation_hash": conversation_hash,
                "policy_check_id": policy_check_id,
                "pass_status": pass_status,
                "metrics": asdict(metrics),
                "timestamp": time.time()
            }
            
            # Sign the compliance data
            data_to_sign = json.dumps(compliance_data, sort_keys=True)
            signature = self._sign_data(data_to_sign)
            
            # Create compliance hash
            compliance_hash = hashlib.sha256(data_to_sign.encode()).hexdigest()
            
            # Create compliance result
            result = ComplianceResult(
                conversation_hash=conversation_hash,
                policy_check_id=policy_check_id,
                pass_status=pass_status,
                metrics=metrics,
                timestamp=time.time(),
                signature=signature,
                compliance_hash=compliance_hash
            )
            
            # Store locally
            self.compliance_results[conversation_hash] = result
            self._save_storage()
            
            # Store on blockchain if available
            if self.w3 and self.contract:
                self._store_compliance_on_blockchain(result)
            
            print(f"✅ Compliance check completed: {'PASS' if pass_status else 'FAIL'} (score: {metrics.overall_score:.2f})")
            return result
            
        except Exception as e:
            print(f"❌ Failed to check compliance: {e}")
            return None
    
    def verify_compliance(self, conversation_hash: str) -> Optional[ComplianceResult]:
        """
        Verify compliance against blockchain data.
        
        Args:
            conversation_hash: Hash of the conversation to verify
            
        Returns:
            ComplianceResult if found and verified, None otherwise
        """
        try:
            # Check local storage first
            if conversation_hash in self.compliance_results:
                local_result = self.compliance_results[conversation_hash]
                
                # Verify against blockchain if available
                if self.w3 and self.contract:
                    blockchain_result = self._get_compliance_from_blockchain(conversation_hash)
                    if blockchain_result:
                        # Verify hash matches
                        if blockchain_result.compliance_hash == local_result.compliance_hash:
                            print(f"✅ Compliance verified against blockchain")
                            return local_result
                        else:
                            print(f"❌ Compliance hash mismatch with blockchain")
                            return None
                    else:
                        print(f"⚠️ Compliance not found on blockchain")
                        return local_result
                else:
                    return local_result
            else:
                print(f"❌ Compliance record not found locally")
                return None
                
        except Exception as e:
            print(f"❌ Failed to verify compliance: {e}")
            return None
    
    def _store_compliance_on_blockchain(self, result: ComplianceResult):
        """Store compliance result on blockchain."""
        try:
            conversation_hash_bytes = bytes.fromhex(result.conversation_hash)
            policy_check_id_bytes = bytes.fromhex(result.policy_check_id.replace("check_", ""))
            compliance_hash_bytes = bytes.fromhex(result.compliance_hash)
            signature_bytes = bytes.fromhex(result.signature)
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.storeCompliance(
                conversation_hash_bytes,
                policy_check_id_bytes,
                result.pass_status,
                compliance_hash_bytes,
                signature_bytes
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Compliance stored on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to store compliance on blockchain: {e}")
    
    def _get_compliance_from_blockchain(self, conversation_hash: str) -> Optional[ComplianceRecord]:
        """Get compliance record from blockchain."""
        try:
            conversation_hash_bytes = bytes.fromhex(conversation_hash)
            result = self.contract.functions.getCompliance(conversation_hash_bytes).call()
            
            if result[6]:  # exists field
                return ComplianceRecord(
                    conversation_hash=result[0].hex(),
                    policy_check_id=result[1].hex(),
                    pass_status=result[2],
                    compliance_hash=result[3].hex(),
                    timestamp=result[4],
                    signature=result[5].hex()
                )
            else:
                return None
                
        except Exception as e:
            print(f"❌ Failed to get compliance from blockchain: {e}")
            return None
    
    def get_compliance_stats(self) -> Dict[str, Any]:
        """Get compliance statistics."""
        if not self.compliance_results:
            return {"total": 0, "passed": 0, "failed": 0, "average_score": 0.0}
        
        total = len(self.compliance_results)
        passed = sum(1 for result in self.compliance_results.values() if result.pass_status)
        failed = total - passed
        average_score = sum(result.metrics.overall_score for result in self.compliance_results.values()) / total
        
        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "average_score": average_score
        }


def main():
    """CLI entry point for compliance management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Compliance Management System")
    parser.add_argument("--check-compliance", nargs=4, metavar=("CONV_HASH", "USER_INPUT", "RESPONSE", "LANGUAGE"),
                       help="Check compliance for a conversation")
    parser.add_argument("--verify-compliance", type=str, metavar="CONV_HASH",
                       help="Verify compliance against blockchain")
    parser.add_argument("--get-stats", action="store_true", help="Get compliance statistics")
    
    args = parser.parse_args()
    
    # Initialize compliance manager
    manager = ComplianceManager()
    
    if args.check_compliance:
        conv_hash, user_input, response, language = args.check_compliance
        result = manager.check_compliance(conv_hash, user_input, response, language)
        if result:
            print(f"✅ Compliance: {'PASS' if result.pass_status else 'FAIL'}")
            print(f"📊 Overall Score: {result.metrics.overall_score:.2f}")
            print(f"🔍 Checks Passed: {result.metrics.checks_passed}/{result.metrics.checks_performed}")
        else:
            print("❌ Failed to check compliance")
    
    elif args.verify_compliance:
        result = manager.verify_compliance(args.verify_compliance)
        if result:
            print(f"✅ Compliance verified: {'PASS' if result.pass_status else 'FAIL'}")
            print(f"📊 Score: {result.metrics.overall_score:.2f}")
        else:
            print("❌ Compliance verification failed")
    
    elif args.get_stats:
        stats = manager.get_compliance_stats()
        print(f"📊 Compliance Statistics:")
        print(f"  Total checks: {stats['total']}")
        print(f"  Passed: {stats['passed']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Average score: {stats['average_score']:.2f}")


if __name__ == "__main__":
    main()
