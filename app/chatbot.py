"""
Mental Health Chatbot using Rogerian therapy approach.
"""

import os
from pathlib import Path


class MentalHealthChatbot:
    """
    A chatbot that provides mental health support using Rogerian therapy techniques.
    """
    
    def __init__(self):
        """Initialize the chatbot with the Rogerian prompt."""
        self.conversation_history = []
        self.rogerian_prompt = self._load_prompt()
    
    def _load_prompt(self):
        """Load the Rogerian therapy prompt from file."""
        prompt_path = Path(__file__).parent / "prompts" / "rogerian_prompt.txt"
        try:
            with open(prompt_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return "You are a supportive mental health chatbot using Rogerian therapy principles."
    
    def get_response(self, user_input, sentiment=None):
        """
        Generate a response to user input.
        
        Args:
            user_input (str): The user's message
            sentiment (str): The detected sentiment of the user's message
            
        Returns:
            str: The chatbot's response
        """
        self.conversation_history.append({
            'role': 'user',
            'content': user_input,
            'sentiment': sentiment
        })
        
        # Simple response logic (to be enhanced with LLM integration)
        response = self._generate_response(user_input, sentiment)
        
        self.conversation_history.append({
            'role': 'assistant',
            'content': response
        })
        
        return response
    
    def _generate_response(self, user_input, sentiment):
        """
        Generate a response based on user input and sentiment.
        
        This is a placeholder implementation. In production, this would
        integrate with an LLM API (OpenAI, Anthropic, etc.)
        """
        # Placeholder responses based on sentiment
        if sentiment == "negative":
            return "I hear that you're going through a difficult time. Can you tell me more about what's troubling you?"
        elif sentiment == "positive":
            return "It's wonderful to hear that you're feeling good. What's been going well for you?"
        else:
            return "I'm here to listen. Could you share more about what's on your mind?"
    
    def get_conversation_history(self):
        """Return the conversation history."""
        return self.conversation_history
    
    def clear_history(self):
        """Clear the conversation history."""
        self.conversation_history = []
