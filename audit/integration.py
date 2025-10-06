"""
Integration module to connect the audit system with the chatbot.
"""

import os
import sys
import hashlib
from pathlib import Path

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

from anchor import ConversationAuditor
from policy import PolicyManager


class ChatbotAuditIntegration:
    """Integration class to automatically audit chatbot conversations."""
    
    def __init__(self):
        self.auditor = ConversationAuditor()
        self.policy_manager = PolicyManager()
    
    def log_conversation(self, user_input: str, reply: str, language: str = "en", model_id: str = None):
        """
        Log a conversation for auditing with policy compliance checking.
        
        Args:
            user_input: User's input message
            reply: AI's reply message
            language: Language code (en/ms)
            model_id: Model ID used for the response
        """
        # Add conversation to auditor
        self.auditor.add_conversation(user_input, reply, language)
        
        # Check policy compliance
        conversation_hash = self._compute_conversation_hash(user_input, reply)
        compliance_record = self.policy_manager.check_compliance(
            conversation_hash=conversation_hash,
            user_input=user_input,
            reply=reply,
            language=language,
            model_id=model_id
        )
        
        if compliance_record:
            print(f"📋 Policy compliance: {'✅ PASS' if compliance_record.compliance_pass else '❌ FAIL'} (score: {compliance_record.overall_score:.2f})")
        
        # Auto-anchor if we have enough conversations
        if len(self.auditor.pending_conversations) >= 10:
            print("🔄 Auto-anchoring conversations to blockchain...")
            self.auditor.batch_and_anchor()
    
    def _compute_conversation_hash(self, user_input: str, reply: str) -> str:
        """Compute hash for conversation."""
        conversation_data = f"User: {user_input}\nEVE: {reply}"
        return hashlib.sha256(conversation_data.encode()).hexdigest()
    
    def force_anchor(self):
        """Force anchoring of all pending conversations."""
        return self.auditor.batch_and_anchor(force=True)
    
    def register_policy(self, document_type: str, content: str, created_by: str = "system"):
        """Register a new policy document."""
        return self.policy_manager.register_policy(document_type, content, created_by)
    
    def register_model(self, provider: str, model_name: str, parameters: dict = None):
        """Register a new model configuration."""
        return self.policy_manager.register_model(provider, model_name, parameters)
    
    def get_compliance_record(self, conversation_hash: str):
        """Get compliance record for a conversation."""
        return self.policy_manager.get_compliance_record(conversation_hash)


# Global instance for easy import
audit_integration = ChatbotAuditIntegration()
