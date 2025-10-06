"""
Test cases for the compliance system.
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

from compliance import ComplianceManager, ComplianceResult, ComplianceMetrics, ComplianceChecker


class TestComplianceChecker:
    """Test cases for ComplianceChecker."""
    
    def test_check_rogerian_principles(self):
        """Test Rogerian principles checking."""
        checker = ComplianceChecker()
        
        # Test Rogerian response
        user_input = "I feel really anxious about my job"
        rogerian_response = "I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?"
        
        score, details = checker.check_rogerian_principles(user_input, rogerian_response)
        
        assert score > 0.7  # Should be high for Rogerian response
        assert details["rogerian_indicators"] > 0
        assert details["directive_indicators"] == 0
    
    def test_check_diagnostic_language(self):
        """Test diagnostic language checking."""
        checker = ComplianceChecker()
        
        # Test non-diagnostic response
        user_input = "I feel sad"
        good_response = "I understand you're feeling sad. That sounds really difficult."
        
        score, details = checker.check_diagnostic_language(user_input, good_response)
        
        assert score == 1.0  # Should be perfect for non-diagnostic response
        assert details["diagnostic_indicators"] == 0
        
        # Test diagnostic response
        bad_response = "You have depression and need therapy."
        
        score, details = checker.check_diagnostic_language(user_input, bad_response)
        
        assert score < 0.5  # Should be low for diagnostic response
        assert details["diagnostic_indicators"] > 0
    
    def test_check_empathy_indicators(self):
        """Test empathy indicators checking."""
        checker = ComplianceChecker()
        
        # Test empathetic response
        user_input = "I'm struggling with my relationship"
        empathetic_response = "I hear that you're struggling with your relationship. That sounds really difficult. I can imagine how challenging this must be for you."
        
        score, details = checker.check_empathy_indicators(user_input, empathetic_response)
        
        assert score > 0.7  # Should be high for empathetic response
        assert details["empathy_indicators"] >= 3
    
    def test_check_safety_protocols_crisis(self):
        """Test safety protocol checking with crisis."""
        checker = ComplianceChecker()
        
        # Test crisis input with good response
        crisis_input = "I want to kill myself"
        good_response = "I hear that you're having thoughts of suicide. This is a crisis situation and you need immediate help. Please call the emergency services or a crisis hotline right now."
        
        score, details = checker.check_safety_protocols(crisis_input, good_response)
        
        assert score > 0.7  # Should be high for appropriate crisis response
        assert details["crisis_detected"] is True
        assert details["safety_indicators"] >= 2
        
        # Test crisis input with bad response
        bad_response = "It's not that bad, you'll get over it."
        
        score, details = checker.check_safety_protocols(crisis_input, bad_response)
        
        assert score == 0.0  # Should be zero for inappropriate crisis response
        assert details["inappropriate_indicators"] > 0
    
    def test_check_safety_protocols_no_crisis(self):
        """Test safety protocol checking without crisis."""
        checker = ComplianceChecker()
        
        # Test normal input
        normal_input = "I'm feeling a bit down today"
        normal_response = "I understand you're feeling down. That sounds difficult. What's contributing to these feelings?"
        
        score, details = checker.check_safety_protocols(normal_input, normal_response)
        
        assert score == 1.0  # Should be perfect for non-crisis
        assert details["crisis_detected"] is False
    
    def test_check_response_length(self):
        """Test response length checking."""
        checker = ComplianceChecker()
        
        # Test appropriate length (3 sentences)
        appropriate_response = "I hear that you're feeling sad. That sounds really difficult. What is this sadness like for you?"
        
        score, details = checker.check_response_length("", appropriate_response)
        
        assert score == 1.0  # Should be perfect for appropriate length
        assert details["sentence_count"] == 3
        
        # Test too short (1 sentence)
        short_response = "I understand you're feeling sad."
        
        score, details = checker.check_response_length("", short_response)
        
        assert score < 1.0  # Should be lower for too short
        assert details["sentence_count"] == 1
        
        # Test too long (6 sentences)
        long_response = "I hear that you're feeling sad. That sounds really difficult. What is this sadness like for you? I can imagine how challenging this must be. You're not alone in this. Thank you for sharing with me."
        
        score, details = checker.check_response_length("", long_response)
        
        assert score < 1.0  # Should be lower for too long
        assert details["sentence_count"] == 6
    
    def test_run_compliance_check(self):
        """Test full compliance check."""
        checker = ComplianceChecker()
        
        user_input = "I feel really anxious about my job"
        response = "I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?"
        
        metrics = checker.run_compliance_check(user_input, response, "en")
        
        assert isinstance(metrics, ComplianceMetrics)
        assert 0.0 <= metrics.overall_score <= 1.0
        assert metrics.checks_performed == 5
        assert 0 <= metrics.checks_passed <= metrics.checks_performed
        assert 0.0 <= metrics.rogerian_score <= 1.0
        assert 0.0 <= metrics.diagnostic_language_score <= 1.0
        assert 0.0 <= metrics.empathy_score <= 1.0
        assert 0.0 <= metrics.safety_score <= 1.0
        assert 0.0 <= metrics.response_length_score <= 1.0


class TestComplianceManager:
    """Test cases for ComplianceManager."""
    
    def test_initialization(self):
        """Test compliance manager initialization."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            assert manager.storage_path.exists()
            assert manager.compliance_results == {}
            assert manager.checker is not None
    
    def test_check_compliance(self):
        """Test compliance checking."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            
            conversation_hash = "abc123def456"
            user_input = "I feel really anxious about my job"
            response = "I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?"
            
            result = manager.check_compliance(conversation_hash, user_input, response, "en")
            
            assert result is not None
            assert isinstance(result, ComplianceResult)
            assert result.conversation_hash == conversation_hash
            assert result.pass_status is not None
            assert isinstance(result.metrics, ComplianceMetrics)
            assert result.signature != ""
            assert result.compliance_hash != ""
            assert conversation_hash in manager.compliance_results
    
    def test_verify_compliance(self):
        """Test compliance verification."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            
            conversation_hash = "abc123def456"
            user_input = "I feel really anxious about my job"
            response = "I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?"
            
            # Check compliance first
            manager.check_compliance(conversation_hash, user_input, response, "en")
            
            # Verify compliance
            result = manager.verify_compliance(conversation_hash)
            
            assert result is not None
            assert isinstance(result, ComplianceResult)
            assert result.conversation_hash == conversation_hash
    
    def test_verify_compliance_nonexistent(self):
        """Test verification of nonexistent compliance."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            
            result = manager.verify_compliance("nonexistent_hash")
            assert result is None
    
    def test_get_compliance_stats(self):
        """Test compliance statistics."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            
            # Check compliance for multiple conversations
            manager.check_compliance("hash1", "I feel sad", "I understand you're feeling sad.", "en")
            manager.check_compliance("hash2", "I feel happy", "I'm glad you're feeling happy!", "en")
            manager.check_compliance("hash3", "I feel angry", "You should calm down.", "en")
            
            stats = manager.get_compliance_stats()
            
            assert stats["total"] == 3
            assert stats["passed"] >= 0
            assert stats["failed"] >= 0
            assert stats["average_score"] > 0.0
    
    def test_compliance_persistence(self):
        """Test that compliance results persist across manager instances."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create first manager and check compliance
            manager1 = ComplianceManager()
            manager1.check_compliance("hash1", "I feel sad", "I understand you're feeling sad.", "en")
            
            # Create second manager and check if result exists
            manager2 = ComplianceManager()
            result = manager2.verify_compliance("hash1")
            
            assert result is not None
            assert result.conversation_hash == "hash1"


class TestComplianceResult:
    """Test cases for ComplianceResult."""
    
    def test_compliance_result_creation(self):
        """Test ComplianceResult creation."""
        metrics = ComplianceMetrics(
            rogerian_score=0.8,
            diagnostic_language_score=1.0,
            empathy_score=0.9,
            safety_score=1.0,
            response_length_score=0.7,
            overall_score=0.88,
            checks_performed=5,
            checks_passed=4
        )
        
        result = ComplianceResult(
            conversation_hash="abc123",
            policy_check_id="check_456",
            pass_status=True,
            metrics=metrics,
            timestamp=1234567890.0,
            signature="signature123",
            compliance_hash="hash789"
        )
        
        assert result.conversation_hash == "abc123"
        assert result.policy_check_id == "check_456"
        assert result.pass_status is True
        assert result.metrics.overall_score == 0.88
        assert result.signature == "signature123"
        assert result.compliance_hash == "hash789"


class TestComplianceMetrics:
    """Test cases for ComplianceMetrics."""
    
    def test_compliance_metrics_creation(self):
        """Test ComplianceMetrics creation."""
        metrics = ComplianceMetrics(
            rogerian_score=0.8,
            diagnostic_language_score=1.0,
            empathy_score=0.9,
            safety_score=1.0,
            response_length_score=0.7,
            overall_score=0.88,
            checks_performed=5,
            checks_passed=4
        )
        
        assert metrics.rogerian_score == 0.8
        assert metrics.diagnostic_language_score == 1.0
        assert metrics.empathy_score == 0.9
        assert metrics.safety_score == 1.0
        assert metrics.response_length_score == 0.7
        assert metrics.overall_score == 0.88
        assert metrics.checks_performed == 5
        assert metrics.checks_passed == 4


class TestComplianceIntegration:
    """Integration tests for compliance system."""
    
    def test_full_compliance_workflow(self):
        """Test complete compliance workflow."""
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = ComplianceManager()
            
            # Test conversation 1 - should pass
            conv1 = "conv1"
            user1 = "I feel really anxious about my job"
            response1 = "I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?"
            
            result1 = manager.check_compliance(conv1, user1, response1, "en")
            assert result1 is not None
            assert result1.pass_status is True
            
            # Test conversation 2 - should fail
            conv2 = "conv2"
            user2 = "I feel sad"
            response2 = "You have depression and need medication. You should see a psychiatrist immediately."
            
            result2 = manager.check_compliance(conv2, user2, response2, "en")
            assert result2 is not None
            assert result2.pass_status is False
            
            # Verify both conversations
            verify1 = manager.verify_compliance(conv1)
            verify2 = manager.verify_compliance(conv2)
            
            assert verify1 is not None
            assert verify2 is not None
            assert verify1.pass_status is True
            assert verify2.pass_status is False
            
            # Check statistics
            stats = manager.get_compliance_stats()
            assert stats["total"] == 2
            assert stats["passed"] == 1
            assert stats["failed"] == 1
