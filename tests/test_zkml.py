"""
Test cases for the ZKML proof system.
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add zk directory to path
sys.path.insert(0, str(os.path.dirname(os.path.dirname(__file__)) / "zk"))

from zkml_proof import (
    ZKMLProver,
    ZKMLVerifier,
    ZKMLComplianceManager,
    ZKMLProof,
    ComplianceCircuit,
    ProofType
)


class TestZKMLProof:
    """Test cases for ZKMLProof dataclass."""
    
    def test_zkml_proof_creation(self):
        """Test ZKMLProof creation."""
        proof = ZKMLProof(
            proof_type=ProofType.COMPLIANCE_CHECK,
            conversation_hash="abc123def456",
            compliance_score=0.85,
            policy_version="1.0.0",
            proof_data=b"mock_proof_data",
            public_inputs={"conversation_hash": "abc123def456", "language": "en"},
            timestamp=1234567890,
            prover_public_key="mock_public_key",
            circuit_id="rogerian_circuit_v1"
        )
        
        assert proof.proof_type == ProofType.COMPLIANCE_CHECK
        assert proof.conversation_hash == "abc123def456"
        assert proof.compliance_score == 0.85
        assert proof.policy_version == "1.0.0"
        assert proof.proof_data == b"mock_proof_data"
        assert proof.public_inputs["language"] == "en"
        assert proof.timestamp == 1234567890
        assert proof.prover_public_key == "mock_public_key"
        assert proof.circuit_id == "rogerian_circuit_v1"


class TestComplianceCircuit:
    """Test cases for ComplianceCircuit dataclass."""
    
    def test_compliance_circuit_creation(self):
        """Test ComplianceCircuit creation."""
        circuit = ComplianceCircuit(
            circuit_id="rogerian_circuit_v1",
            policy_rules=["Check for empathetic language", "Verify non-directive approach"],
            input_schema={"user_input": "string", "ai_response": "string"},
            output_schema={"compliance_score": "float", "rogerian_indicators": "int"},
            constraints=["rogerian_indicators >= 1", "compliance_score >= 0.0"],
            version="1.0.0"
        )
        
        assert circuit.circuit_id == "rogerian_circuit_v1"
        assert len(circuit.policy_rules) == 2
        assert circuit.input_schema["user_input"] == "string"
        assert circuit.output_schema["compliance_score"] == "float"
        assert len(circuit.constraints) == 2
        assert circuit.version == "1.0.0"


class TestZKMLProver:
    """Test cases for ZKMLProver."""
    
    def test_initialization(self):
        """Test ZKMLProver initialization."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        prover = ZKMLProver("mock_prover_key", circuits)
        
        assert prover.prover_key == "mock_prover_key"
        assert "rogerian_principles" in prover.circuits
        assert prover.proof_cache == {}
    
    def test_generate_compliance_proof(self):
        """Test compliance proof generation."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string", "ai_response": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        prover = ZKMLProver("mock_prover_key", circuits)
        
        conversation_text = "User: I feel anxious. EVE: I hear that you're feeling anxious..."
        user_input = "I feel anxious"
        ai_response = "I hear that you're feeling anxious. What is this anxiety like for you?"
        
        proof = prover.generate_compliance_proof(
            conversation_text=conversation_text,
            user_input=user_input,
            ai_response=ai_response,
            policy_type="rogerian_principles",
            language="en"
        )
        
        assert isinstance(proof, ZKMLProof)
        assert proof.proof_type == ProofType.COMPLIANCE_CHECK
        assert proof.compliance_score == 0.85  # Mock score
        assert proof.public_inputs["language"] == "en"
        assert proof.circuit_id == "rogerian_circuit_v1"
    
    def test_generate_batch_proofs(self):
        """Test batch proof generation."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string", "ai_response": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        prover = ZKMLProver("mock_prover_key", circuits)
        
        conversations = [
            {
                "conversation_text": "User: I feel sad. EVE: I understand you're feeling sad...",
                "user_input": "I feel sad",
                "ai_response": "I understand you're feeling sad. That sounds difficult...",
                "language": "en"
            },
            {
                "conversation_text": "User: I feel happy. EVE: I'm glad you're feeling happy!",
                "user_input": "I feel happy",
                "ai_response": "I'm glad you're feeling happy! What's contributing to this positive feeling?",
                "language": "en"
            }
        ]
        
        proofs = prover.generate_batch_proofs(conversations, "rogerian_principles")
        
        assert len(proofs) == 2
        assert all(isinstance(proof, ZKMLProof) for proof in proofs)
        assert proofs[0].conversation_hash != proofs[1].conversation_hash


class TestZKMLVerifier:
    """Test cases for ZKMLVerifier."""
    
    def test_initialization(self):
        """Test ZKMLVerifier initialization."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        verifier = ZKMLVerifier("mock_verifier_key", circuits)
        
        assert verifier.verification_key == "mock_verifier_key"
        assert "rogerian_principles" in verifier.circuits
    
    def test_verify_proof(self):
        """Test proof verification."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        verifier = ZKMLVerifier("mock_verifier_key", circuits)
        
        proof = ZKMLProof(
            proof_type=ProofType.COMPLIANCE_CHECK,
            conversation_hash="abc123def456",
            compliance_score=0.85,
            policy_version="1.0.0",
            proof_data=b"mock_proof_data",
            public_inputs={"conversation_hash": "abc123def456"},
            timestamp=1234567890,
            prover_public_key="mock_public_key",
            circuit_id="rogerian_circuit_v1"
        )
        
        is_valid = verifier.verify_proof(proof)
        assert is_valid is True  # Mock verification always returns True
    
    def test_verify_batch_proofs(self):
        """Test batch proof verification."""
        circuits = {
            "rogerian_principles": ComplianceCircuit(
                circuit_id="rogerian_circuit_v1",
                policy_rules=["Check for empathetic language"],
                input_schema={"user_input": "string"},
                output_schema={"compliance_score": "float"},
                constraints=["compliance_score >= 0.0"],
                version="1.0.0"
            )
        }
        
        verifier = ZKMLVerifier("mock_verifier_key", circuits)
        
        proofs = [
            ZKMLProof(
                proof_type=ProofType.COMPLIANCE_CHECK,
                conversation_hash="abc123def456",
                compliance_score=0.85,
                policy_version="1.0.0",
                proof_data=b"mock_proof_data",
                public_inputs={"conversation_hash": "abc123def456"},
                timestamp=1234567890,
                prover_public_key="mock_public_key",
                circuit_id="rogerian_circuit_v1"
            ),
            ZKMLProof(
                proof_type=ProofType.COMPLIANCE_CHECK,
                conversation_hash="def456ghi789",
                compliance_score=0.92,
                policy_version="1.0.0",
                proof_data=b"mock_proof_data_2",
                public_inputs={"conversation_hash": "def456ghi789"},
                timestamp=1234567891,
                prover_public_key="mock_public_key",
                circuit_id="rogerian_circuit_v1"
            )
        ]
        
        results = verifier.verify_batch_proofs(proofs)
        
        assert len(results) == 2
        assert all(result is True for result in results)  # Mock verification


class TestZKMLComplianceManager:
    """Test cases for ZKMLComplianceManager."""
    
    def test_initialization(self):
        """Test ZKMLComplianceManager initialization."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        assert manager.prover is not None
        assert manager.verifier is not None
        assert manager.blockchain_client is None
        assert manager.proof_storage == {}
    
    def test_check_compliance_with_zk_proof(self):
        """Test compliance checking with ZK proof generation."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        conversation_text = "User: I feel anxious. EVE: I hear that you're feeling anxious..."
        user_input = "I feel anxious"
        ai_response = "I hear that you're feeling anxious. What is this anxiety like for you?"
        
        compliance_passed, proof = manager.check_compliance_with_zk_proof(
            conversation_text=conversation_text,
            user_input=user_input,
            ai_response=ai_response,
            policy_type="rogerian_principles",
            language="en"
        )
        
        assert isinstance(compliance_passed, bool)
        assert isinstance(proof, ZKMLProof)
        assert proof.conversation_hash in manager.proof_storage
    
    def test_verify_compliance_proof(self):
        """Test compliance proof verification."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        # First generate a proof
        conversation_text = "User: I feel anxious. EVE: I hear that you're feeling anxious..."
        user_input = "I feel anxious"
        ai_response = "I hear that you're feeling anxious. What is this anxiety like for you?"
        
        compliance_passed, proof = manager.check_compliance_with_zk_proof(
            conversation_text=conversation_text,
            user_input=user_input,
            ai_response=ai_response,
            policy_type="rogerian_principles",
            language="en"
        )
        
        # Then verify it
        is_valid = manager.verify_compliance_proof(proof.conversation_hash)
        
        assert is_valid is True  # Mock verification
    
    def test_verify_compliance_proof_not_found(self):
        """Test verification of non-existent proof."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        is_valid = manager.verify_compliance_proof("nonexistent_hash")
        
        assert is_valid is None
    
    def test_load_circuits(self):
        """Test circuit loading."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        circuits = manager._load_circuits()
        
        assert "rogerian_principles" in circuits
        assert "safety_protocol" in circuits
        assert "empathy_score" in circuits
        
        # Check Rogerian circuit
        rogerian_circuit = circuits["rogerian_principles"]
        assert rogerian_circuit.circuit_id == "rogerian_circuit_v1"
        assert "Check for empathetic language" in rogerian_circuit.policy_rules
        assert rogerian_circuit.input_schema["user_input"] == "string"
        assert rogerian_circuit.output_schema["compliance_score"] == "float"
        
        # Check Safety circuit
        safety_circuit = circuits["safety_protocol"]
        assert safety_circuit.circuit_id == "safety_circuit_v1"
        assert "Detect crisis keywords" in safety_circuit.policy_rules
        assert safety_circuit.output_schema["crisis_detected"] == "bool"
        
        # Check Empathy circuit
        empathy_circuit = circuits["empathy_score"]
        assert empathy_circuit.circuit_id == "empathy_circuit_v1"
        assert "Count empathy indicators" in empathy_circuit.policy_rules
        assert empathy_circuit.output_schema["empathy_indicators"] == "int"


class TestProofType:
    """Test cases for ProofType enum."""
    
    def test_proof_type_values(self):
        """Test ProofType enum values."""
        assert ProofType.COMPLIANCE_CHECK.value == "compliance_check"
        assert ProofType.POLICY_ADHERENCE.value == "policy_adherence"
        assert ProofType.SAFETY_PROTOCOL.value == "safety_protocol"
        assert ProofType.EMPATHY_SCORE.value == "empathy_score"
        assert ProofType.ROGERIAN_PRINCIPLES.value == "rogerian_principles"


class TestIntegration:
    """Integration tests for ZKML system."""
    
    def test_full_workflow(self):
        """Test complete ZKML workflow."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        # Test conversation
        conversation_text = "User: I feel really anxious about my job interview tomorrow.\nEVE: I hear that you're feeling anxious about your job interview tomorrow. That sounds really challenging. What is this anxiety like for you?"
        user_input = "I feel really anxious about my job interview tomorrow."
        ai_response = "I hear that you're feeling anxious about your job interview tomorrow. That sounds really challenging. What is this anxiety like for you?"
        
        # Generate proof
        compliance_passed, proof = manager.check_compliance_with_zk_proof(
            conversation_text=conversation_text,
            user_input=user_input,
            ai_response=ai_response,
            policy_type="rogerian_principles",
            language="en"
        )
        
        # Verify proof
        is_valid = manager.verify_compliance_proof(proof.conversation_hash)
        
        # Assertions
        assert compliance_passed is True  # Mock compliance
        assert is_valid is True  # Mock verification
        assert proof.proof_type == ProofType.COMPLIANCE_CHECK
        assert proof.compliance_score == 0.85  # Mock score
        assert proof.public_inputs["language"] == "en"
        assert proof.conversation_hash in manager.proof_storage
    
    def test_multiple_policy_types(self):
        """Test ZKML with different policy types."""
        manager = ZKMLComplianceManager(
            prover_key="mock_prover_key",
            verifier_key="mock_verifier_key"
        )
        
        conversation_text = "User: I want to kill myself. EVE: I hear that you're having thoughts of suicide. This is a crisis situation and you need immediate help. Please call emergency services or a crisis hotline right now."
        user_input = "I want to kill myself"
        ai_response = "I hear that you're having thoughts of suicide. This is a crisis situation and you need immediate help. Please call emergency services or a crisis hotline right now."
        
        # Test different policy types
        policy_types = ["rogerian_principles", "safety_protocol", "empathy_score"]
        
        for policy_type in policy_types:
            compliance_passed, proof = manager.check_compliance_with_zk_proof(
                conversation_text=conversation_text,
                user_input=user_input,
                ai_response=ai_response,
                policy_type=policy_type,
                language="en"
            )
            
            assert isinstance(compliance_passed, bool)
            assert isinstance(proof, ZKMLProof)
            assert proof.compliance_score == 0.85  # Mock score
            assert proof.conversation_hash in manager.proof_storage
