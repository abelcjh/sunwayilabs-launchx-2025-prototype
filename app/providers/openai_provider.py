import os
from typing import List, Dict
from openai import OpenAI
from .base import ModelProvider


class OpenAIProvider(ModelProvider):
    """OpenAI API provider implementation."""
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    
    def generate(self, messages: List[Dict[str, str]]) -> str:
        """Generate response using OpenAI API."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.8,
                max_tokens=220,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            raise RuntimeError(f"OpenAI API error: {str(e)}")
    
    def is_available(self) -> bool:
        """Check if OpenAI provider is available."""
        return bool(os.getenv("OPENAI_API_KEY"))
