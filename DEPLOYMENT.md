# 🚀 Deployment Guide

This guide covers deploying the EVE Mental Health AI Companion to various platforms with automated CI/CD.

## 📋 Prerequisites

### Required Accounts
- **GitHub**: For repository and CI/CD
- **Vercel**: For web deployment (optional)
- **Hugging Face**: For AI model hosting (optional)
- **Polygon**: For blockchain deployment (optional)

### Required API Keys
- **OpenAI API Key**: For AI model access
- **ILMU API Key**: For Malaysian AI model (optional)
- **Blockchain RPC**: For smart contract interaction (optional)

## 🔧 Environment Variables

### Required Variables

```bash
# OpenAI API Key (Required)
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4o-mini
```

### Optional Variables

```bash
# ILMU API (Optional - for Malaysian AI model)
ILMU_API_URL=your_ilmu_api_url_here
ILMU_MODEL=ilmu-mini

# Blockchain Configuration (Optional - for full features)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here

# Contract Addresses (Optional - for blockchain features)
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
```

## 🏠 Local Deployment

### Quick Start

1. **Clone Repository**:
```bash
git clone https://github.com/your-username/sunwayilabs-launchx-2025-prototype.git
cd sunwayilabs-launchx-2025-prototype
```

2. **Setup Environment**:
```bash
python scripts/setup_environment.py
```

3. **Install Dependencies**:
```bash
pip install -r requirements.txt
```

4. **Run Application**:
```bash
streamlit run app/main.py
```

### Development Mode

```bash
# Run with auto-reload
streamlit run app/main.py --server.runOnSave true

# Run tests
pytest tests/ -v

# Run linting
flake8 app/ audit/ privacy/
black --check app/ audit/ privacy/
```

## 🌐 Vercel Deployment

### Automatic Deployment (Recommended)

1. **Connect Repository**:
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your GitHub repository

2. **Configure Environment Variables**:
   - Add all required environment variables in Vercel dashboard
   - Ensure sensitive keys are properly secured

3. **Deploy**:
   - Vercel will automatically deploy on push to main branch
   - Monitor deployment in Vercel dashboard

### Manual Deployment

1. **Install Vercel CLI**:
```bash
npm install -g vercel
```

2. **Login to Vercel**:
```bash
vercel login
```

3. **Deploy**:
```bash
vercel --prod
```

### Vercel Configuration

The `vercel.json` file is already configured for Streamlit deployment:

```json
{
  "version": 2,
  "builds": [
    {
      "src": "app/main.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "app/main.py"
    }
  ],
  "env": {
    "PYTHON_VERSION": "3.9"
  },
  "functions": {
    "app/main.py": {
      "maxDuration": 30
    }
  },
  "regions": ["sin1"],
  "framework": "streamlit"
}
```

## 🤗 Hugging Face Spaces Deployment

### Automatic Deployment

The GitHub Actions workflow automatically deploys to Hugging Face Spaces on push to main branch.

### Manual Deployment

1. **Install Dependencies**:
```bash
pip install huggingface_hub
```

2. **Set Environment Variables**:
```bash
export HF_TOKEN=your_huggingface_token
```

3. **Deploy**:
```bash
python scripts/deploy_to_hf.py
```

### Hugging Face Space Configuration

The deployment script creates a Hugging Face Space with:
- **Title**: EVE Mental Health AI Companion
- **SDK**: Streamlit
- **Python Version**: 3.9
- **License**: MIT

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

The CI/CD pipeline includes:

1. **Testing**:
   - Python 3.8, 3.9, 3.10 compatibility
   - Unit tests with pytest
   - Coverage reporting
   - Linting with flake8, black, isort, mypy

2. **Security Scanning**:
   - Bandit security scan
   - Safety dependency check
   - Semgrep security analysis

3. **Deployment**:
   - Automatic Vercel deployment on main branch
   - Automatic Hugging Face Spaces deployment
   - Slack notifications (optional)

### Workflow Triggers

- **Push to main/develop**: Full CI/CD pipeline
- **Pull Request**: Testing and security scanning only
- **Manual**: Workflow dispatch for manual deployment

### Required Secrets

Add these secrets to your GitHub repository:

```bash
# Vercel Deployment
VERCEL_TOKEN=your_vercel_token
VERCEL_ORG_ID=your_vercel_org_id
VERCEL_PROJECT_ID=your_vercel_project_id

# Hugging Face Deployment
HF_TOKEN=your_huggingface_token

# Optional: Slack Notifications
SLACK_WEBHOOK=your_slack_webhook_url
```

## ⛓️ Blockchain Deployment

### Smart Contract Deployment

1. **Install Dependencies**:
```bash
npm install
```

2. **Configure Hardhat**:
```bash
# Update hardhat.config.js with your network configuration
```

3. **Deploy Contracts**:
```bash
npx hardhat run scripts/deploy.js --network amoy
```

4. **Verify Contracts**:
```bash
npx hardhat verify --network amoy <CONTRACT_ADDRESS>
```

### Contract Addresses

After deployment, update your environment variables with the deployed contract addresses:

```bash
CONSENT_REGISTRY_ADDRESS=0x...
STORAGE_PROOF_ADDRESS=0x...
POLICY_REGISTRY_ADDRESS=0x...
COMPLIANCE_CONTRACT_ADDRESS=0x...
```

## 🔍 Monitoring and Debugging

### Application Logs

```bash
# View application logs
tail -f logs/app.log

# View error logs
tail -f logs/error.log
```

### Health Checks

```bash
# Check application health
curl http://localhost:8501/health

# Check API endpoints
curl http://localhost:8501/api/status
```

### Performance Monitoring

- **Vercel**: Built-in analytics and performance monitoring
- **Hugging Face**: Space metrics and usage statistics
- **Custom**: Application-specific metrics in logs

## 🚨 Troubleshooting

### Common Issues

1. **Environment Variables Not Loaded**:
   - Check `.env` file exists and is properly formatted
   - Restart the application after changing environment variables

2. **Import Errors**:
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Check Python path and virtual environment

3. **Blockchain Connection Issues**:
   - Verify RPC URL and network connectivity
   - Check private key format and wallet balance

4. **Deployment Failures**:
   - Check GitHub Actions logs for detailed error messages
   - Verify all required secrets are set
   - Ensure repository permissions are correct

### Debug Mode

```bash
# Run with debug logging
export DEBUG=1
streamlit run app/main.py

# Run with verbose output
streamlit run app/main.py --logger.level debug
```

## 📊 Production Considerations

### Security

- **API Key Management**: Use environment variables, never hardcode
- **HTTPS Only**: Ensure all communications are encrypted
- **Rate Limiting**: Implement rate limiting for API endpoints
- **Input Validation**: Validate all user inputs

### Performance

- **Caching**: Implement caching for frequently accessed data
- **CDN**: Use CDN for static assets
- **Database**: Consider database for production data storage
- **Monitoring**: Set up application performance monitoring

### Scalability

- **Horizontal Scaling**: Design for multiple instances
- **Load Balancing**: Implement load balancing for high traffic
- **Database Scaling**: Plan for database scaling
- **Caching Strategy**: Implement distributed caching

## 📚 Additional Resources

- [Streamlit Documentation](https://docs.streamlit.io/)
- [Vercel Documentation](https://vercel.com/docs)
- [Hugging Face Spaces](https://huggingface.co/docs/hub/spaces)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Polygon Documentation](https://docs.polygon.technology/)

## 🆘 Support

- **GitHub Issues**: [Report issues](https://github.com/your-username/sunwayilabs-launchx-2025-prototype/issues)
- **Discussions**: [Community discussions](https://github.com/your-username/sunwayilabs-launchx-2025-prototype/discussions)
- **Email**: support@eve-mental-health.com
