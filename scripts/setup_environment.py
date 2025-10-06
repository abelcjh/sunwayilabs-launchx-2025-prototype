#!/usr/bin/env python3
"""
Setup script for environment variables and configuration.
"""

import os
import sys
from pathlib import Path

def create_env_file():
    """Create .env file from .env.example if it doesn't exist."""
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print("✅ .env file already exists")
        return True
    
    if not env_example.exists():
        print("❌ .env.example file not found")
        return False
    
    # Copy .env.example to .env
    with open(env_example, 'r') as f:
        content = f.read()
    
    with open(env_file, 'w') as f:
        f.write(content)
    
    print("✅ Created .env file from .env.example")
    print("⚠️  Please update .env with your actual API keys and configuration")
    return True

def validate_environment():
    """Validate that required environment variables are set."""
    
    required_vars = [
        "OPENAI_API_KEY"
    ]
    
    optional_vars = [
        "ILMU_API_URL",
        "BLOCKCHAIN_RPC_URL",
        "PRIVATE_KEY",
        "CONSENT_REGISTRY_ADDRESS",
        "STORAGE_PROOF_ADDRESS",
        "POLICY_REGISTRY_ADDRESS",
        "COMPLIANCE_CONTRACT_ADDRESS"
    ]
    
    missing_required = []
    missing_optional = []
    
    for var in required_vars:
        if not os.getenv(var):
            missing_required.append(var)
    
    for var in optional_vars:
        if not os.getenv(var):
            missing_optional.append(var)
    
    if missing_required:
        print("❌ Missing required environment variables:")
        for var in missing_required:
            print(f"   - {var}")
        return False
    
    if missing_optional:
        print("⚠️  Missing optional environment variables:")
        for var in missing_optional:
            print(f"   - {var}")
        print("   (These are optional but recommended for full functionality)")
    
    print("✅ Environment validation passed")
    return True

def setup_directories():
    """Create necessary directories."""
    
    directories = [
        "privacy/storage",
        "privacy/encrypted_blobs",
        "audit/compliance_storage",
        "audit/policy_storage",
        "logs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"📁 Created directory: {directory}")
    
    return True

def main():
    """Main setup function."""
    
    print("🚀 Setting up EVE Mental Health AI Companion...")
    
    # Create .env file
    if not create_env_file():
        sys.exit(1)
    
    # Setup directories
    if not setup_directories():
        sys.exit(1)
    
    # Validate environment
    if not validate_environment():
        print("\n❌ Setup incomplete. Please configure your environment variables.")
        print("📝 Edit .env file with your API keys and configuration")
        sys.exit(1)
    
    print("\n✅ Setup completed successfully!")
    print("🎉 You can now run the application with: streamlit run app/main.py")

if __name__ == "__main__":
    main()
