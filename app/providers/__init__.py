from .base import ModelProvider
from .openai_provider import OpenAIProvider
from .ilmu_stub import ILMUProvider


def get_provider() -> ModelProvider:
    """
    Factory function to get the best available provider.
    
    Priority order:
    1. ILMU (if configured)
    2. OpenAI (if configured)
    3. Fallback to OpenAI with error handling
    
    Returns:
        Available ModelProvider instance
        
    Raises:
        RuntimeError: If no providers are available
    """
    # Try ILMU first if configured
    ilmu_provider = ILMUProvider()
    if ilmu_provider.is_available():
        return ilmu_provider
    
    # Fallback to OpenAI
    openai_provider = OpenAIProvider()
    if openai_provider.is_available():
        return openai_provider
    
    raise RuntimeError(
        "No model providers are available. Please configure either "
        "ILMU_API_URL or OPENAI_API_KEY in your .env file."
    )
