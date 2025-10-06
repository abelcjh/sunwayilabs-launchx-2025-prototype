"""
Test cases for the policy management system.
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

from policy import PolicyManager, PolicyDocument, ModelConfiguration, PolicyCheck, ComplianceRecord, PolicyRuleEngine


class TestPolicyRuleEngine:
    """Test cases for PolicyRuleEngine."""
    
    def test_response_length_check(self):
        """Test response length compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test appropriate length (3 sentences)
        result = engine._check_response_length("Hello", "Hi there. How are you? I'm here to help.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        assert result["details"]["sentence_count"] == 3
        
        # Test too short (1 sentence)
        result = engine._check_response_length("Hello", "Hi.")
        assert result["status"] == "fail"
        assert result["score"] == 0.3
        
        # Test too long (6 sentences)
        result = engine._check_response_length("Hello", "Hi there. How are you? I'm here to help. What's on your mind? Tell me more. I'm listening.")
        assert result["status"] == "warning"
        assert result["score"] == 0.7
    
    def test_non_directive_language_check(self):
        """Test non-directive language compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test non-directive response
        result = engine._check_non_directive_language("I feel sad", "I hear that you're feeling sad. What is that like for you?")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test directive response
        result = engine._check_non_directive_language("I feel sad", "You should try to be more positive. You must think happy thoughts.")
        assert result["status"] == "fail"
        assert result["score"] == 0.2
    
    def test_empathy_indicators_check(self):
        """Test empathy indicators compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test empathetic response
        result = engine._check_empathy_indicators("I'm struggling", "I understand you're struggling. That sounds really difficult. I can see how hard this must be for you.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test non-empathetic response
        result = engine._check_empathy_indicators("I'm struggling", "That's unfortunate. You'll get over it.")
        assert result["status"] == "fail"
        assert result["score"] == 0.3
    
    def test_safety_keywords_check(self):
        """Test safety keyword compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test crisis response with safety measures
        result = engine._check_safety_keywords("I want to kill myself", "I hear that you're in a lot of pain. Please reach out to a crisis hotline or emergency services immediately. You are not alone.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test crisis response without safety measures
        result = engine._check_safety_keywords("I want to kill myself", "That's concerning. I hope you feel better soon.")
        assert result["status"] == "fail"
        assert result["score"] == 0.2
        
        # Test non-crisis response
        result = engine._check_safety_keywords("I feel sad", "I understand you're feeling sad.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
    
    def test_crisis_response_check(self):
        """Test crisis response compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test appropriate crisis response
        result = engine._check_crisis_response("I want to end it all", "I hear that you're in tremendous pain. Please contact emergency services or a crisis hotline immediately. You are not alone.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test inappropriate crisis response
        result = engine._check_crisis_response("I want to end it all", "It's not that bad. Think positive. Other people have it worse.")
        assert result["status"] == "fail"
        assert result["score"] == 0.1
    
    def test_language_consistency_check(self):
        """Test language consistency compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test English consistency
        result = engine._check_language_consistency("Hello", "Hi there. How are you today?", "en")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test Bahasa Malaysia consistency
        result = engine._check_language_consistency("Saya rasa sedih", "Saya faham perasaan anda. Bagaimana perasaan anda sekarang?", "ms")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
    
    def test_rogerian_principles_check(self):
        """Test Rogerian principles compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test Rogerian response
        result = engine._check_rogerian_principles("I feel anxious", "I hear that you're feeling anxious. How does that feel for you? Would you like to share more about what's making you feel this way?")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test non-Rogerian response
        result = engine._check_rogerian_principles("I feel anxious", "You should try to relax. Take deep breaths.")
        assert result["status"] == "warning"
        assert result["score"] == 0.4
    
    def test_cbt_techniques_check(self):
        """Test CBT techniques compliance checking."""
        engine = PolicyRuleEngine()
        
        # Test CBT response
        result = engine._check_cbt_techniques("I'm worthless", "I hear that you're having thoughts about being worthless. What evidence do you have for this belief? Let's consider alternative perspectives.")
        assert result["status"] == "pass"
        assert result["score"] == 1.0
        
        # Test non-CBT response
        result = engine._check_cbt_techniques("I'm worthless", "I understand you're feeling this way.")
        assert result["status"] == "pass"
        assert result["score"] == 0.8
    
    def test_run_checks(self):
        """Test running all compliance checks."""
        engine = PolicyRuleEngine()
        
        checks = engine.run_checks(
            "I feel depressed",
            "I hear that you're feeling depressed. That sounds really difficult. How does this feeling affect your daily life?",
            language="en"
        )
        
        assert len(checks) == 8  # All 8 rule types
        assert all(check.rule_name in engine.rules for check in checks)
        assert all(0.0 <= check.score <= 1.0 for check in checks)


class TestPolicyManager:
    """Test cases for PolicyManager."""
    
    def test_initialization(self):
        """Test policy manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            assert manager.rule_engine is not None
            assert manager.storage_path.exists()
    
    def test_register_policy(self):
        """Test policy registration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            policy_id = manager.register_policy(
                document_type="system_prompt",
                content="You are a helpful mental health assistant.",
                created_by="test_user"
            )
            
            assert policy_id is not None
            assert policy_id in manager.policies
            assert manager.policies[policy_id].document_type == "system_prompt"
            assert manager.policies[policy_id].content_hash is not None
    
    def test_register_model(self):
        """Test model registration."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            model_id = manager.register_model(
                provider="openai",
                model_name="gpt-4o-mini",
                parameters={"temperature": 0.8, "max_tokens": 220}
            )
            
            assert model_id is not None
            assert model_id in manager.models
            assert manager.models[model_id].provider == "openai"
            assert manager.models[model_id].config_hash is not None
    
    def test_check_compliance(self):
        """Test compliance checking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            compliance = manager.check_compliance(
                conversation_hash="test_hash_123",
                user_input="I feel anxious",
                response="I hear that you're feeling anxious. How does that feel for you?",
                language="en"
            )
            
            assert compliance is not None
            assert compliance.conversation_hash == "test_hash_123"
            assert compliance.compliance_pass is not None
            assert 0.0 <= compliance.overall_score <= 1.0
            assert len(compliance.policy_checks) == 8
    
    def test_get_combined_policy_hash(self):
        """Test combined policy hash generation."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            # Register some policies
            policy1 = manager.register_policy("system_prompt", "Content 1")
            policy2 = manager.register_policy("therapy_guideline", "Content 2")
            
            # Get combined hash
            combined_hash = manager._get_combined_policy_hash()
            assert combined_hash is not None
            assert len(combined_hash) == 64  # SHA-256 hex length
    
    def test_list_policies(self):
        """Test policy listing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            # Register policies
            manager.register_policy("system_prompt", "Content 1")
            manager.register_policy("therapy_guideline", "Content 2")
            manager.register_policy("safety_checklist", "Content 3")
            
            # List all policies
            all_policies = manager.list_policies()
            assert len(all_policies) == 3
            
            # List by type
            system_policies = manager.list_policies("system_prompt")
            assert len(system_policies) == 1
            assert system_policies[0].document_type == "system_prompt"
    
    def test_list_models(self):
        """Test model listing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = PolicyManager()
            
            # Register models
            manager.register_model("openai", "gpt-4o-mini")
            manager.register_model("ilmu", "ilmu-model")
            
            # List models
            models = manager.list_models()
            assert len(models) == 2
            assert any(m.provider == "openai" for m in models)
            assert any(m.provider == "ilmu" for m in models)


class TestPolicyDocument:
    """Test cases for PolicyDocument."""
    
    def test_policy_document_creation(self):
        """Test PolicyDocument creation."""
        policy = PolicyDocument(
            policy_id="test_policy",
            version="v1.0",
            document_type="system_prompt",
            content="Test content",
            content_hash="abc123",
            created_at=1234567890.0,
            created_by="test_user",
            is_active=True,
            metadata={"key": "value"}
        )
        
        assert policy.policy_id == "test_policy"
        assert policy.version == "v1.0"
        assert policy.document_type == "system_prompt"
        assert policy.content == "Test content"
        assert policy.is_active is True


class TestModelConfiguration:
    """Test cases for ModelConfiguration."""
    
    def test_model_configuration_creation(self):
        """Test ModelConfiguration creation."""
        model = ModelConfiguration(
            model_id="test_model",
            version="v1.0",
            provider="openai",
            model_name="gpt-4o-mini",
            parameters={"temperature": 0.8},
            config_hash="def456",
            created_at=1234567890.0,
            is_active=True
        )
        
        assert model.model_id == "test_model"
        assert model.provider == "openai"
        assert model.model_name == "gpt-4o-mini"
        assert model.parameters["temperature"] == 0.8
        assert model.is_active is True


class TestPolicyCheck:
    """Test cases for PolicyCheck."""
    
    def test_policy_check_creation(self):
        """Test PolicyCheck creation."""
        check = PolicyCheck(
            check_id="test_check",
            conversation_hash="conv_hash",
            model_hash="model_hash",
            policy_hash="policy_hash",
            check_type="automated",
            rule_name="response_length",
            status="pass",
            score=0.9,
            details={"sentence_count": 3},
            created_at=1234567890.0
        )
        
        assert check.check_id == "test_check"
        assert check.rule_name == "response_length"
        assert check.status == "pass"
        assert check.score == 0.9


class TestComplianceRecord:
    """Test cases for ComplianceRecord."""
    
    def test_compliance_record_creation(self):
        """Test ComplianceRecord creation."""
        record = ComplianceRecord(
            conversation_hash="conv_hash",
            model_hash="model_hash",
            policy_hash="policy_hash",
            compliance_pass=True,
            overall_score=0.85,
            policy_checks=[],
            created_at=1234567890.0
        )
        
        assert record.conversation_hash == "conv_hash"
        assert record.compliance_pass is True
        assert record.overall_score == 0.85
