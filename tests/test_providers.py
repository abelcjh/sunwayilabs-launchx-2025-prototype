import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add app directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from providers import get_provider, OpenAIProvider, ILMUProvider


class TestProviders:
    """Test cases for the provider system."""
    
    def test_openai_provider_availability(self):
        """Test OpenAI provider availability check."""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test_key'}):
            provider = OpenAIProvider()
            assert provider.is_available() is True
        
        with patch.dict(os.environ, {}, clear=True):
            provider = OpenAIProvider()
            assert provider.is_available() is False
    
    def test_ilmu_provider_availability(self):
        """Test ILMU provider availability check."""
        with patch.dict(os.environ, {'ILMU_API_URL': 'http://test.api'}):
            provider = ILMUProvider()
            assert provider.is_available() is True
        
        with patch.dict(os.environ, {}, clear=True):
            provider = ILMUProvider()
            assert provider.is_available() is False
    
    def test_ilmu_provider_not_implemented(self):
        """Test ILMU provider raises NotImplementedError when not configured."""
        with patch.dict(os.environ, {}, clear=True):
            provider = ILMUProvider()
            with pytest.raises(NotImplementedError):
                provider.generate([{"role": "user", "content": "test"}])
    
    def test_provider_factory_priority(self):
        """Test that provider factory returns ILMU when both are available."""
        with patch.dict(os.environ, {
            'OPENAI_API_KEY': 'test_key',
            'ILMU_API_URL': 'http://test.api'
        }):
            provider = get_provider()
            assert isinstance(provider, ILMUProvider)
    
    def test_provider_factory_openai_fallback(self):
        """Test that provider factory falls back to OpenAI when ILMU not available."""
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test_key'}):
            provider = get_provider()
            assert isinstance(provider, OpenAIProvider)
    
    def test_provider_factory_no_providers(self):
        """Test that provider factory raises error when no providers available."""
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="No model providers are available"):
                get_provider()
