"""
Policy Management and Compliance System.

This module provides:
- Policy document hashing and blockchain storage
- Automated compliance checking
- Policy versioning and tracking
- Integration with conversation auditing
"""

import os
import json
import time
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import re

from web3 import Web3
from web3.middleware import geth_poa_middleware


@dataclass
class PolicyDocument:
    """Represents a policy document with versioning."""
    policy_id: str
    version: str
    document_type: str  # "system_prompt", "therapy_guideline", "safety_checklist"
    content: str
    content_hash: str
    created_at: float
    created_by: str
    is_active: bool
    metadata: Dict[str, Any]


@dataclass
class ModelConfiguration:
    """Represents a model configuration with versioning."""
    model_id: str
    version: str
    provider: str  # "openai", "ilmu", etc.
    model_name: str
    parameters: Dict[str, Any]
    config_hash: str
    created_at: float
    is_active: bool


@dataclass
class PolicyCheck:
    """Represents a policy compliance check result."""
    check_id: str
    conversation_hash: str
    model_hash: str
    policy_hash: str
    check_type: str
    rule_name: str
    status: str  # "pass", "fail", "warning"
    score: float  # 0.0 to 1.0
    details: Dict[str, Any]
    created_at: float


@dataclass
class ComplianceRecord:
    """Complete compliance record linking conversation to policies."""
    conversation_hash: str
    model_hash: str
    policy_hash: str
    compliance_pass: bool
    overall_score: float
    policy_checks: List[PolicyCheck]
    created_at: float


class PolicyRuleEngine:
    """Rule engine for automated policy compliance checking."""
    
    def __init__(self):
        self.rules = {
            "response_length": self._check_response_length,
            "non_directive_language": self._check_non_directive_language,
            "empathy_indicators": self._check_empathy_indicators,
            "safety_keywords": self._check_safety_keywords,
            "crisis_response": self._check_crisis_response,
            "language_consistency": self._check_language_consistency,
            "rogerian_principles": self._check_rogerian_principles,
            "cbt_techniques": self._check_cbt_techniques
        }
    
    def _check_response_length(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check if response length is appropriate (2-4 sentences)."""
        sentences = re.split(r'[.!?]+', response.strip())
        sentence_count = len([s for s in sentences if s.strip()])
        
        if 2 <= sentence_count <= 4:
            return {"status": "pass", "score": 1.0, "details": {"sentence_count": sentence_count}}
        elif sentence_count < 2:
            return {"status": "fail", "score": 0.3, "details": {"sentence_count": sentence_count, "issue": "too_short"}}
        else:
            return {"status": "warning", "score": 0.7, "details": {"sentence_count": sentence_count, "issue": "too_long"}}
    
    def _check_non_directive_language(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check for non-directive, Rogerian language patterns."""
        directive_patterns = [
            r'\b(you should|you must|you need to|you have to)\b',
            r'\b(try this|do this|follow this)\b',
            r'\b(I recommend|I suggest|I advise)\b',
            r'\b(here\'s what you do|the solution is)\b'
        ]
        
        directive_count = sum(len(re.findall(pattern, response, re.I)) for pattern in directive_patterns)
        
        if directive_count == 0:
            return {"status": "pass", "score": 1.0, "details": {"directive_count": directive_count}}
        elif directive_count <= 2:
            return {"status": "warning", "score": 0.6, "details": {"directive_count": directive_count}}
        else:
            return {"status": "fail", "score": 0.2, "details": {"directive_count": directive_count}}
    
    def _check_empathy_indicators(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check for empathy indicators in response."""
        empathy_patterns = [
            r'\b(I understand|I hear you|I can see)\b',
            r'\b(that sounds|it sounds like|I can imagine)\b',
            r'\b(that must be|that would be|I can sense)\b',
            r'\b(thank you for sharing|I appreciate you telling me)\b'
        ]
        
        empathy_count = sum(len(re.findall(pattern, response, re.I)) for pattern in empathy_patterns)
        
        if empathy_count >= 2:
            return {"status": "pass", "score": 1.0, "details": {"empathy_count": empathy_count}}
        elif empathy_count == 1:
            return {"status": "warning", "score": 0.6, "details": {"empathy_count": empathy_count}}
        else:
            return {"status": "fail", "score": 0.3, "details": {"empathy_count": empathy_count}}
    
    def _check_safety_keywords(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check for appropriate safety keyword handling."""
        crisis_keywords = [
            r'\b(suicide|kill myself|end it|bunuh diri)\b',
            r'\b(harm myself|hurt myself|self harm)\b',
            r'\b(die|death|not worth living)\b'
        ]
        
        has_crisis = any(re.search(pattern, user_input, re.I) for pattern in crisis_keywords)
        
        if has_crisis:
            safety_patterns = [
                r'\b(emergency|crisis|immediate help)\b',
                r'\b(hotline|helpline|support line)\b',
                r'\b(trusted person|professional help)\b',
                r'\b(you are not alone|people care)\b'
            ]
            
            safety_count = sum(len(re.findall(pattern, response, re.I)) for pattern in safety_patterns)
            
            if safety_count >= 2:
                return {"status": "pass", "score": 1.0, "details": {"crisis_detected": True, "safety_count": safety_count}}
            else:
                return {"status": "fail", "score": 0.2, "details": {"crisis_detected": True, "safety_count": safety_count}}
        else:
            return {"status": "pass", "score": 1.0, "details": {"crisis_detected": False}}
    
    def _check_crisis_response(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check crisis response appropriateness."""
        crisis_keywords = [
            r'\b(suicide|kill myself|end it|bunuh diri)\b',
            r'\b(harm myself|hurt myself|self harm)\b'
        ]
        
        has_crisis = any(re.search(pattern, user_input, re.I) for pattern in crisis_keywords)
        
        if has_crisis:
            # Check for appropriate crisis response
            inappropriate_patterns = [
                r'\b(it\'s not that bad|you\'ll get over it)\b',
                r'\b(think positive|just be happy)\b',
                r'\b(other people have it worse)\b'
            ]
            
            inappropriate_count = sum(len(re.findall(pattern, response, re.I)) for pattern in inappropriate_patterns)
            
            if inappropriate_count > 0:
                return {"status": "fail", "score": 0.1, "details": {"crisis_detected": True, "inappropriate_count": inappropriate_count}}
            else:
                return {"status": "pass", "score": 1.0, "details": {"crisis_detected": True, "appropriate_response": True}}
        else:
            return {"status": "pass", "score": 1.0, "details": {"crisis_detected": False}}
    
    def _check_language_consistency(self, user_input: str, response: str, language: str = "en", **kwargs) -> Dict[str, Any]:
        """Check language consistency between input and response."""
        if language == "ms":
            # Check for Bahasa Malaysia patterns
            malay_patterns = [
                r'\b(saya|anda|adalah|dengan|untuk|dari|ke|di|pada)\b',
                r'\b(terima kasih|maaf|tolong|boleh|mahu|perlu)\b'
            ]
            malay_count = sum(len(re.findall(pattern, response, re.I)) for pattern in malay_patterns)
            
            if malay_count >= 2:
                return {"status": "pass", "score": 1.0, "details": {"language": "ms", "consistency_score": malay_count}}
            else:
                return {"status": "warning", "score": 0.5, "details": {"language": "ms", "consistency_score": malay_count}}
        else:
            # English - check for proper English patterns
            english_patterns = [
                r'\b(I|you|we|they|he|she|it)\b',
                r'\b(thank you|please|sorry|help)\b'
            ]
            english_count = sum(len(re.findall(pattern, response, re.I)) for pattern in english_patterns)
            
            if english_count >= 2:
                return {"status": "pass", "score": 1.0, "details": {"language": "en", "consistency_score": english_count}}
            else:
                return {"status": "warning", "score": 0.5, "details": {"language": "en", "consistency_score": english_count}}
    
    def _check_rogerian_principles(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check for Rogerian therapy principles."""
        rogerian_patterns = [
            r'\b(how does that feel|what is that like for you)\b',
            r'\b(I hear that you|it sounds like you)\b',
            r'\b(would you like to share|tell me more about)\b',
            r'\b(I can sense|I can imagine)\b'
        ]
        
        rogerian_count = sum(len(re.findall(pattern, response, re.I)) for pattern in rogerian_patterns)
        
        if rogerian_count >= 1:
            return {"status": "pass", "score": 1.0, "details": {"rogerian_count": rogerian_count}}
        else:
            return {"status": "warning", "score": 0.4, "details": {"rogerian_count": rogerian_count}}
    
    def _check_cbt_techniques(self, user_input: str, response: str, **kwargs) -> Dict[str, Any]:
        """Check for appropriate CBT technique usage."""
        cbt_patterns = [
            r'\b(thought|thinking|belief|perspective)\b',
            r'\b(evidence|fact|reality)\b',
            r'\b(challenge|question|consider)\b',
            r'\b(alternative|different way)\b'
        ]
        
        cbt_count = sum(len(re.findall(pattern, response, re.I)) for pattern in cbt_patterns)
        
        if cbt_count >= 1:
            return {"status": "pass", "score": 1.0, "details": {"cbt_count": cbt_count}}
        else:
            return {"status": "pass", "score": 0.8, "details": {"cbt_count": cbt_count, "note": "CBT not required"}}
    
    def run_checks(self, user_input: str, response: str, language: str = "en", **kwargs) -> List[PolicyCheck]:
        """Run all policy compliance checks."""
        checks = []
        
        for rule_name, rule_func in self.rules.items():
            try:
                result = rule_func(user_input, response, language=language, **kwargs)
                
                check = PolicyCheck(
                    check_id=f"check_{uuid.uuid4().hex[:16]}",
                    conversation_hash="",  # Will be set by caller
                    model_hash="",  # Will be set by caller
                    policy_hash="",  # Will be set by caller
                    check_type="automated",
                    rule_name=rule_name,
                    status=result["status"],
                    score=result["score"],
                    details=result["details"],
                    created_at=time.time()
                )
                checks.append(check)
                
            except Exception as e:
                # Create failed check
                check = PolicyCheck(
                    check_id=f"check_{uuid.uuid4().hex[:16]}",
                    conversation_hash="",
                    model_hash="",
                    policy_hash="",
                    check_type="automated",
                    rule_name=rule_name,
                    status="fail",
                    score=0.0,
                    details={"error": str(e)},
                    created_at=time.time()
                )
                checks.append(check)
        
        return checks


class PolicyManager:
    """Main policy management system."""
    
    def __init__(self, 
                 rpc_url: str = None,
                 contract_address: str = None,
                 private_key: str = None):
        """
        Initialize the policy manager.
        
        Args:
            rpc_url: Blockchain RPC URL
            contract_address: Policy registry contract address
            private_key: Private key for blockchain transactions
        """
        self.rpc_url = rpc_url or os.getenv("BLOCKCHAIN_RPC_URL")
        self.contract_address = contract_address or os.getenv("POLICY_REGISTRY_ADDRESS")
        self.private_key = private_key or os.getenv("PRIVATE_KEY")
        
        # Initialize Web3 if blockchain config is available
        self.w3 = None
        self.contract = None
        if self.rpc_url and self.contract_address and self.private_key:
            self._init_blockchain()
        
        # Initialize rule engine
        self.rule_engine = PolicyRuleEngine()
        
        # Storage for policies and compliance records
        self.policies: Dict[str, PolicyDocument] = {}
        self.models: Dict[str, ModelConfiguration] = {}
        self.compliance_records: Dict[str, ComplianceRecord] = {}
        
        # Storage paths
        self.storage_path = Path("audit/policy_storage")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._load_storage()
    
    def _init_blockchain(self):
        """Initialize Web3 connection and contract."""
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)
            
            # Policy registry contract ABI
            contract_abi = [
                {
                    "inputs": [
                        {"name": "policyId", "type": "bytes32"},
                        {"name": "version", "type": "string"},
                        {"name": "policyHash", "type": "bytes32"},
                        {"name": "documentType", "type": "string"}
                    ],
                    "name": "registerPolicy",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "modelId", "type": "bytes32"},
                        {"name": "version", "type": "string"},
                        {"name": "modelHash", "type": "bytes32"},
                        {"name": "provider", "type": "string"}
                    ],
                    "name": "registerModel",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [
                        {"name": "conversationHash", "type": "bytes32"},
                        {"name": "modelHash", "type": "bytes32"},
                        {"name": "policyHash", "type": "bytes32"},
                        {"name": "compliancePass", "type": "bool"}
                    ],
                    "name": "registerCompliance",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=contract_abi
            )
            
            print(f"✅ Policy blockchain initialized: {self.w3.eth.chain_id}")
        except Exception as e:
            print(f"⚠️ Policy blockchain initialization failed: {e}")
            self.w3 = None
            self.contract = None
    
    def _load_storage(self):
        """Load policies and compliance records from storage."""
        try:
            # Load policies
            policies_path = self.storage_path / "policies.json"
            if policies_path.exists():
                with open(policies_path, 'r') as f:
                    data = json.load(f)
                    self.policies = {k: PolicyDocument(**v) for k, v in data.items()}
            
            # Load models
            models_path = self.storage_path / "models.json"
            if models_path.exists():
                with open(models_path, 'r') as f:
                    data = json.load(f)
                    self.models = {k: ModelConfiguration(**v) for k, v in data.items()}
            
            # Load compliance records
            compliance_path = self.storage_path / "compliance.json"
            if compliance_path.exists():
                with open(compliance_path, 'r') as f:
                    data = json.load(f)
                    self.compliance_records = {k: ComplianceRecord(**v) for k, v in data.items()}
                    
        except Exception as e:
            print(f"⚠️ Failed to load policy storage: {e}")
    
    def _save_storage(self):
        """Save policies and compliance records to storage."""
        try:
            # Save policies
            policies_path = self.storage_path / "policies.json"
            with open(policies_path, 'w') as f:
                data = {k: asdict(v) for k, v in self.policies.items()}
                json.dump(data, f, indent=2)
            
            # Save models
            models_path = self.storage_path / "models.json"
            with open(models_path, 'w') as f:
                data = {k: asdict(v) for k, v in self.models.items()}
                json.dump(data, f, indent=2)
            
            # Save compliance records
            compliance_path = self.storage_path / "compliance.json"
            with open(compliance_path, 'w') as f:
                data = {k: asdict(v) for k, v in self.compliance_records.items()}
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"⚠️ Failed to save policy storage: {e}")
    
    def register_policy(self, 
                       document_type: str,
                       content: str,
                       created_by: str = "system",
                       metadata: Dict[str, Any] = None) -> str:
        """
        Register a new policy document.
        
        Args:
            document_type: Type of policy ("system_prompt", "therapy_guideline", "safety_checklist")
            content: Policy content
            created_by: Creator identifier
            metadata: Additional metadata
            
        Returns:
            Policy ID if successful, None otherwise
        """
        try:
            # Generate policy ID and version
            policy_id = f"policy_{uuid.uuid4().hex[:16]}"
            version = f"v{int(time.time())}"
            
            # Compute content hash
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            
            # Create policy document
            policy = PolicyDocument(
                policy_id=policy_id,
                version=version,
                document_type=document_type,
                content=content,
                content_hash=content_hash,
                created_at=time.time(),
                created_by=created_by,
                is_active=True,
                metadata=metadata or {}
            )
            
            # Store locally
            self.policies[policy_id] = policy
            self._save_storage()
            
            # Register on blockchain if available
            if self.w3 and self.contract:
                self._register_policy_on_blockchain(policy)
            
            print(f"✅ Registered policy {policy_id} (version {version})")
            return policy_id
            
        except Exception as e:
            print(f"❌ Failed to register policy: {e}")
            return None
    
    def register_model(self,
                      provider: str,
                      model_name: str,
                      parameters: Dict[str, Any] = None) -> str:
        """
        Register a model configuration.
        
        Args:
            provider: Model provider ("openai", "ilmu", etc.)
            model_name: Model name
            parameters: Model parameters
            
        Returns:
            Model ID if successful, None otherwise
        """
        try:
            # Generate model ID and version
            model_id = f"model_{uuid.uuid4().hex[:16]}"
            version = f"v{int(time.time())}"
            
            # Compute configuration hash
            config_data = {
                "provider": provider,
                "model_name": model_name,
                "parameters": parameters or {}
            }
            config_hash = hashlib.sha256(json.dumps(config_data, sort_keys=True).encode()).hexdigest()
            
            # Create model configuration
            model = ModelConfiguration(
                model_id=model_id,
                version=version,
                provider=provider,
                model_name=model_name,
                parameters=parameters or {},
                config_hash=config_hash,
                created_at=time.time(),
                is_active=True
            )
            
            # Store locally
            self.models[model_id] = model
            self._save_storage()
            
            # Register on blockchain if available
            if self.w3 and self.contract:
                self._register_model_on_blockchain(model)
            
            print(f"✅ Registered model {model_id} (version {version})")
            return model_id
            
        except Exception as e:
            print(f"❌ Failed to register model: {e}")
            return None
    
    def check_compliance(self,
                        conversation_hash: str,
                        user_input: str,
                        response: str,
                        language: str = "en",
                        model_id: str = None,
                        policy_ids: List[str] = None) -> ComplianceRecord:
        """
        Check compliance for a conversation.
        
        Args:
            conversation_hash: Hash of the conversation
            user_input: User's input
            response: AI's response
            language: Language code
            model_id: Model ID (optional)
            policy_ids: List of policy IDs to check against
            
        Returns:
            ComplianceRecord with check results
        """
        try:
            # Get model hash
            model_hash = ""
            if model_id and model_id in self.models:
                model_hash = self.models[model_id].config_hash
            
            # Get policy hash (combine all active policies)
            policy_hash = self._get_combined_policy_hash(policy_ids)
            
            # Run compliance checks
            policy_checks = self.rule_engine.run_checks(
                user_input, response, language=language
            )
            
            # Set hashes in checks
            for check in policy_checks:
                check.conversation_hash = conversation_hash
                check.model_hash = model_hash
                check.policy_hash = policy_hash
            
            # Calculate overall compliance
            overall_score = sum(check.score for check in policy_checks) / len(policy_checks)
            compliance_pass = overall_score >= 0.7  # 70% threshold
            
            # Create compliance record
            compliance_record = ComplianceRecord(
                conversation_hash=conversation_hash,
                model_hash=model_hash,
                policy_hash=policy_hash,
                compliance_pass=compliance_pass,
                overall_score=overall_score,
                policy_checks=policy_checks,
                created_at=time.time()
            )
            
            # Store compliance record
            self.compliance_records[conversation_hash] = compliance_record
            self._save_storage()
            
            # Register on blockchain if available
            if self.w3 and self.contract:
                self._register_compliance_on_blockchain(compliance_record)
            
            print(f"✅ Compliance check completed: {compliance_pass} (score: {overall_score:.2f})")
            return compliance_record
            
        except Exception as e:
            print(f"❌ Failed to check compliance: {e}")
            return None
    
    def _get_combined_policy_hash(self, policy_ids: List[str] = None) -> str:
        """Get combined hash of all active policies."""
        if policy_ids:
            policies = [self.policies[pid] for pid in policy_ids if pid in self.policies]
        else:
            policies = [p for p in self.policies.values() if p.is_active]
        
        if not policies:
            return ""
        
        # Combine policy hashes
        combined = "".join(sorted(p.content_hash for p in policies))
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _register_policy_on_blockchain(self, policy: PolicyDocument):
        """Register policy on blockchain."""
        try:
            policy_id_bytes = bytes.fromhex(policy.policy_id.replace("policy_", ""))
            policy_hash_bytes = bytes.fromhex(policy.content_hash)
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.registerPolicy(
                policy_id_bytes,
                policy.version,
                policy_hash_bytes,
                policy.document_type
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Policy registered on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to register policy on blockchain: {e}")
    
    def _register_model_on_blockchain(self, model: ModelConfiguration):
        """Register model on blockchain."""
        try:
            model_id_bytes = bytes.fromhex(model.model_id.replace("model_", ""))
            model_hash_bytes = bytes.fromhex(model.config_hash)
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.registerModel(
                model_id_bytes,
                model.version,
                model_hash_bytes,
                model.provider
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Model registered on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to register model on blockchain: {e}")
    
    def _register_compliance_on_blockchain(self, compliance: ComplianceRecord):
        """Register compliance record on blockchain."""
        try:
            conversation_hash_bytes = bytes.fromhex(compliance.conversation_hash)
            model_hash_bytes = bytes.fromhex(compliance.model_hash) if compliance.model_hash else b""
            policy_hash_bytes = bytes.fromhex(compliance.policy_hash) if compliance.policy_hash else b""
            
            account = self.w3.eth.account.from_key(self.private_key)
            
            transaction = self.contract.functions.registerCompliance(
                conversation_hash_bytes,
                model_hash_bytes,
                policy_hash_bytes,
                compliance.compliance_pass
            ).build_transaction({
                'from': account.address,
                'gas': 200000,
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(account.address),
            })
            
            signed_txn = self.w3.eth.account.sign_transaction(transaction, self.private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"✅ Compliance registered on blockchain: {receipt.transactionHash.hex()}")
            
        except Exception as e:
            print(f"❌ Failed to register compliance on blockchain: {e}")
    
    def get_compliance_record(self, conversation_hash: str) -> Optional[ComplianceRecord]:
        """Get compliance record for a conversation."""
        return self.compliance_records.get(conversation_hash)
    
    def list_policies(self, document_type: str = None) -> List[PolicyDocument]:
        """List all policies, optionally filtered by type."""
        policies = list(self.policies.values())
        if document_type:
            policies = [p for p in policies if p.document_type == document_type]
        return policies
    
    def list_models(self) -> List[ModelConfiguration]:
        """List all model configurations."""
        return list(self.models.values())


def main():
    """CLI entry point for policy management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Policy Management System")
    parser.add_argument("--register-policy", nargs=3, metavar=("TYPE", "CONTENT_FILE", "CREATED_BY"),
                       help="Register a new policy")
    parser.add_argument("--register-model", nargs=3, metavar=("PROVIDER", "MODEL_NAME", "PARAMS_JSON"),
                       help="Register a new model")
    parser.add_argument("--check-compliance", nargs=4, metavar=("CONV_HASH", "USER_INPUT", "RESPONSE", "LANGUAGE"),
                       help="Check compliance for a conversation")
    parser.add_argument("--list-policies", action="store_true", help="List all policies")
    parser.add_argument("--list-models", action="store_true", help="List all models")
    
    args = parser.parse_args()
    
    # Initialize policy manager
    manager = PolicyManager()
    
    if args.register_policy:
        doc_type, content_file, created_by = args.register_policy
        try:
            with open(content_file, 'r') as f:
                content = f.read()
            policy_id = manager.register_policy(doc_type, content, created_by)
            if policy_id:
                print(f"✅ Policy registered: {policy_id}")
            else:
                print("❌ Failed to register policy")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    elif args.register_model:
        provider, model_name, params_json = args.register_model
        try:
            params = json.loads(params_json) if params_json != "{}" else {}
            model_id = manager.register_model(provider, model_name, params)
            if model_id:
                print(f"✅ Model registered: {model_id}")
            else:
                print("❌ Failed to register model")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    elif args.check_compliance:
        conv_hash, user_input, response, language = args.check_compliance
        compliance = manager.check_compliance(conv_hash, user_input, response, language)
        if compliance:
            print(f"✅ Compliance: {compliance.compliance_pass} (score: {compliance.overall_score:.2f})")
        else:
            print("❌ Failed to check compliance")
    
    elif args.list_policies:
        policies = manager.list_policies()
        for policy in policies:
            print(f"📄 {policy.policy_id} - {policy.document_type} (v{policy.version})")
    
    elif args.list_models:
        models = manager.list_models()
        for model in models:
            print(f"🤖 {model.model_id} - {model.provider}/{model.model_name} (v{model.version})")


if __name__ == "__main__":
    main()
