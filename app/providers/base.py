from abc import ABC, abstractmethod
from typing import List, Dict, Any


class ModelProvider(ABC):
    """Abstract base class for model providers."""
    
    @abstractmethod
    def generate(self, messages: List[Dict[str, str]]) -> str:
        """
        Generate a response from the model.
        
        Args:
            messages: List of message dictionaries with 'role' and 'content' keys
            
        Returns:
            Generated response as a string
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if this provider is available and properly configured.
        
        Returns:
            True if provider is available, False otherwise
        """
        pass
