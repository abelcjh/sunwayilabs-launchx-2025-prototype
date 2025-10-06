#!/usr/bin/env python3
"""
Deploy EVE Mental Health AI Companion to Hugging Face Spaces.
"""

import os
import json
import shutil
from pathlib import Path
from huggingface_hub import HfApi, Repository

def create_hf_space_config():
    """Create Hugging Face Space configuration files."""
    
    # Create README.md for HF Space
    hf_readme = """---
title: EVE Mental Health AI Companion
emoji: 🧠
colorFrom: blue
colorTo: purple
sdk: streamlit
sdk_version: 1.36.0
app_file: app/main.py
pinned: false
license: mit
short_description: Privacy-first mental health AI companion with blockchain transparency
---

# 🧠 EVE - Mental Health AI Companion

A privacy-first, blockchain-anchored mental health chatbot that combines Rogerian therapy principles with advanced AI, comprehensive data protection, and transparent compliance monitoring.

## Features

- **🤖 AI-Powered Therapy**: Rogerian therapy principles with multilingual support
- **🔒 Privacy-First Design**: End-to-end encryption with consent management
- **⛓️ Blockchain Transparency**: Immutable audit trails and compliance verification
- **📊 Real-time Monitoring**: Policy compliance and safety protocol enforcement

## Usage

1. Enter your message in the chat interface
2. EVE will respond with empathetic, non-directive therapy
3. All conversations are encrypted and consent-managed
4. Compliance is automatically checked and recorded

## Privacy Notice

This is a prototype system for educational purposes. All data is encrypted and consent-managed. For production mental health applications, ensure compliance with local healthcare regulations.

## Crisis Resources

- **Malaysia**: 03-79568145 (Befrienders)
- **International**: +1-800-273-8255 (National Suicide Prevention Lifeline)
- **Emergency**: 999 (Malaysia) / 911 (US)
"""
    
    # Create requirements.txt for HF Space
    hf_requirements = """streamlit>=1.36.0
openai>=1.30.0
python-dotenv>=1.0.1
transformers>=4.43.0
torch>=2.2.0
sentencepiece>=0.2.0
langdetect>=1.0.9
web3>=6.0.0
cryptography>=41.0.0
boto3>=1.26.0
requests>=2.31.0
"""
    
    # Create .env.example for HF Space
    hf_env_example = """# OpenAI API Key (Required)
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4o-mini

# ILMU API (Optional)
ILMU_API_URL=your_ilmu_api_url_here
ILMU_MODEL=ilmu-mini

# Blockchain Configuration (Optional)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here

# Contract Addresses (Optional)
CONSENT_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890
STORAGE_PROOF_ADDRESS=0x1234567890123456789012345678901234567890
POLICY_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890
COMPLIANCE_CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890

# Privacy Configuration (Optional)
SIGNING_KEY_PATH=privacy/signing_key.pem
ENCRYPTION_KEY=your_encryption_key_here

# Storage Configuration (Optional)
STORAGE_TYPE=local
S3_BUCKET=your-s3-bucket-name
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
"""
    
    return hf_readme, hf_requirements, hf_env_example

def deploy_to_huggingface():
    """Deploy the application to Hugging Face Spaces."""
    
    # Get HF token from environment
    hf_token = os.getenv("HF_TOKEN")
    if not hf_token:
        print("❌ HF_TOKEN not found in environment variables")
        return False
    
    # Configuration
    repo_id = "sunwayilabs/eve-mental-health-ai"
    local_dir = "hf_space"
    
    try:
        # Create local directory for HF Space
        Path(local_dir).mkdir(exist_ok=True)
        
        # Copy application files
        print("📁 Copying application files...")
        shutil.copytree("app", f"{local_dir}/app", dirs_exist_ok=True)
        shutil.copytree("audit", f"{local_dir}/audit", dirs_exist_ok=True)
        shutil.copytree("privacy", f"{local_dir}/privacy", dirs_exist_ok=True)
        shutil.copytree("contracts", f"{local_dir}/contracts", dirs_exist_ok=True)
        shutil.copytree("tests", f"{local_dir}/tests", dirs_exist_ok=True)
        
        # Copy configuration files
        shutil.copy("requirements.txt", f"{local_dir}/requirements.txt")
        shutil.copy(".env.example", f"{local_dir}/.env.example")
        
        # Create HF Space specific files
        hf_readme, hf_requirements, hf_env_example = create_hf_space_config()
        
        with open(f"{local_dir}/README.md", "w", encoding="utf-8") as f:
            f.write(hf_readme)
        
        with open(f"{local_dir}/requirements.txt", "w", encoding="utf-8") as f:
            f.write(hf_requirements)
        
        with open(f"{local_dir}/.env.example", "w", encoding="utf-8") as f:
            f.write(hf_env_example)
        
        # Initialize HF API
        api = HfApi(token=hf_token)
        
        # Create or get repository
        try:
            api.create_repo(repo_id=repo_id, repo_type="space", exist_ok=True)
            print(f"✅ Repository {repo_id} ready")
        except Exception as e:
            print(f"⚠️ Repository creation: {e}")
        
        # Upload files
        print("📤 Uploading files to Hugging Face Space...")
        api.upload_folder(
            folder_path=local_dir,
            repo_id=repo_id,
            repo_type="space",
            commit_message="Deploy EVE Mental Health AI Companion"
        )
        
        print(f"✅ Successfully deployed to https://huggingface.co/spaces/{repo_id}")
        return True
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        return False
    
    finally:
        # Cleanup
        if Path(local_dir).exists():
            shutil.rmtree(local_dir)

if __name__ == "__main__":
    success = deploy_to_huggingface()
    exit(0 if success else 1)
