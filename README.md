# 🧠 EVE - Mental Health AI Companion

A privacy-first, blockchain-anchored mental health chatbot that combines Rogerian therapy principles with advanced AI, comprehensive data protection, and transparent compliance monitoring.

## 🌟 System Overview

EVE (Empathetic Virtual Entity) is a sophisticated mental health support system that provides:

- **🤖 AI-Powered Therapy**: Rogerian therapy principles with multilingual support (English/Bahasa Malaysia)
- **🔒 Privacy-First Design**: End-to-end encryption with consent management
- **⛓️ Blockchain Transparency**: Immutable audit trails and compliance verification
- **📊 Real-time Monitoring**: Policy compliance and safety protocol enforcement
- **🌐 Multi-Platform Deployment**: Local development and cloud deployment options

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        EVE Mental Health System                │
├─────────────────────────────────────────────────────────────────┤
│  Frontend Layer (Streamlit)                                    │
│  ├─ User Interface                                             │
│  ├─ Conversation Management                                    │
│  └─ Real-time Feedback                                         │
├─────────────────────────────────────────────────────────────────┤
│  AI Processing Layer                                           │
│  ├─ Rogerian Chatbot (OpenAI/ILMU)                            │
│  ├─ Sentiment Analysis (Multilingual)                         │
│  ├─ Crisis Detection & Safety Protocols                       │
│  └─ Language Detection (EN/MS)                                │
├─────────────────────────────────────────────────────────────────┤
│  Privacy & Security Layer                                      │
│  ├─ Consent Management (Verifiable Credentials)               │
│  ├─ Key Broker (AES-256-GCM Encryption)                       │
│  ├─ Storage Proof (Blockchain Anchoring)                      │
│  └─ Threshold Encryption (DEK Management)                     │
├─────────────────────────────────────────────────────────────────┤
│  Compliance & Audit Layer                                      │
│  ├─ Policy Management (Therapy Guidelines)                    │
│  ├─ Compliance Checking (Real-time Validation)                │
│  ├─ Digital Signing (RSA-2048)                                │
│  └─ Merkle Tree Logging (Conversation Integrity)              │
├─────────────────────────────────────────────────────────────────┤
│  Blockchain Infrastructure                                     │
│  ├─ ConsentRegistry.sol (Consent Management)                  │
│  ├─ StorageProof.sol (Data Storage Verification)              │
│  ├─ PolicyRegistry.sol (Policy Versioning)                    │
│  └─ ComplianceRegistry.sol (Compliance Tracking)              │
└─────────────────────────────────────────────────────────────────┘
```

## 🤖 AI Features

### Rogerian Therapy Chatbot

**Core Principles**:
- **Empathetic Responses**: "I hear that you're feeling..." 
- **Non-directive Approach**: Avoids giving advice or solutions
- **Unconditional Positive Regard**: Accepts user's feelings without judgment
- **Reflective Listening**: Mirrors and validates user's emotions
- **Open-ended Questions**: Encourages deeper exploration

**Example Interaction**:
```
User: "I feel really anxious about my job interview tomorrow."
EVE: "I hear that you're feeling anxious about your job interview tomorrow. That sounds really challenging. What is this anxiety like for you? How does it feel in your body?"
```

### Multilingual Support

**English (EN)**:
- Natural conversation flow
- Cultural sensitivity
- Professional therapy language

**Bahasa Malaysia (MS)**:
- Localized responses
- Cultural context awareness
- Accessible mental health support

**Language Detection**:
```python
def detect_lang(text: str) -> str:
    """Detects language and returns 'en' or 'ms'"""
    detected = detect(text)
    return "ms" if detected == "ms" else "en"
```

### Sentiment Analysis

**Multilingual Transformer Model**:
- Model: `cardiffnlp/twitter-xlm-roberta-base-sentiment`
- Supports: English, Bahasa Malaysia, and 100+ languages
- Real-time emotion detection
- Crisis keyword monitoring

**Sentiment Categories**:
- **Positive**: Joy, optimism, contentment
- **Negative**: Sadness, anger, fear, anxiety
- **Neutral**: Calm, balanced, factual

### Crisis Detection & Safety Protocols

**Crisis Keywords**:
- English: "suicide", "kill myself", "end it"
- Bahasa Malaysia: "bunuh diri", "mati", "akhiri"

**Safety Response Protocol**:
1. **Acknowledge**: "I hear that you're having thoughts of suicide"
2. **Validate**: "This is a crisis situation and you need immediate help"
3. **Resource**: "Please call emergency services or a crisis hotline right now"
4. **Support**: "You are not alone, and people care about you"

## ⛓️ Blockchain Components

### ConsentRegistry.sol

**Purpose**: Manage user consent for data processing

**Key Functions**:
```solidity
function setConsent(
    bytes32 consentId,
    address subjectDid,
    address controllerDid,
    bytes32 consentHash,
    uint256 expiresAt
) public;

function revokeConsent(bytes32 consentId) public;
function isActive(bytes32 consentId) public view returns (bool);
```

**Features**:
- Verifiable Credentials (JSON-LD format)
- Consent expiration management
- Subject and controller DID tracking
- Immutable consent history

### StorageProof.sol

**Purpose**: Verify encrypted data storage and accessibility

**Key Functions**:
```solidity
function recordStorage(
    bytes32 blobHash,
    string storageUri,
    string providerId,
    string region,
    bytes32 conversationHash
) external;

function verifyStorage(bytes32 blobHash) external view returns (bool);
function createTombstone(bytes32 blobHash, string reason) external;
```

**Features**:
- Multi-provider support (Local, S3, HTTP)
- Storage accessibility verification
- Tombstone management for data deletion
- Geographic region tracking

### PolicyRegistry.sol

**Purpose**: Version and anchor therapy guidelines and policies

**Key Functions**:
```solidity
function registerPolicy(
    bytes32 policyId,
    string documentType,
    bytes32 policyHash,
    uint256 version,
    string createdBy
) public;

function registerModel(
    bytes32 modelId,
    string provider,
    string modelName,
    bytes32 modelHash,
    string parametersJson
) public;
```

**Features**:
- Policy version control
- Model configuration tracking
- Content integrity verification
- Creator attribution

### ComplianceRegistry.sol

**Purpose**: Store and verify compliance check results

**Key Functions**:
```solidity
function storeCompliance(
    bytes32 conversationHash,
    bytes32 policyCheckId,
    bool passStatus,
    bytes32 complianceHash,
    bytes signature
) external;

function verifyCompliance(
    bytes32 conversationHash,
    bytes32 expectedComplianceHash
) external view returns (bool);
```

**Features**:
- Digital signature verification
- Compliance scoring and tracking
- Policy check linking
- Immutable audit trail

## 🔒 Data Privacy & Compliance Philosophy

### Privacy-First Design

**Core Principles**:
- **Data Minimization**: Only collect necessary data
- **Purpose Limitation**: Use data only for stated purposes
- **Consent Management**: Explicit, informed consent required
- **Right to Erasure**: Users can revoke consent and delete data
- **Transparency**: Clear data usage policies

### Encryption Architecture

**End-to-End Encryption**:
- **AES-256-GCM**: Military-grade symmetric encryption
- **Per-Session DEKs**: Unique keys for each conversation
- **Threshold Encryption**: Secure key sharing mechanisms
- **Key Rotation**: Automatic key expiration and renewal

**Data Flow**:
```
User Input → Consent Check → Encryption → Storage → Blockchain Proof
     ↓              ↓            ↓          ↓           ↓
Plain Text    Active Consent  Ciphertext  Encrypted   Immutable
Message       Verification    + Metadata   Blob       Hash
```

### Compliance Framework

**Real-time Policy Checking**:
- **Rogerian Principles**: Empathetic, non-directive responses
- **Diagnostic Language**: Avoids clinical terminology
- **Safety Protocols**: Appropriate crisis response
- **Response Quality**: Length and structure validation
- **Empathy Indicators**: Presence of understanding expressions

**Compliance Scoring**:
- **Overall Score**: 0.0 to 1.0 (70% pass threshold)
- **Individual Rules**: 5 compliance categories
- **Digital Signing**: RSA-2048 cryptographic proof
- **Blockchain Storage**: Immutable compliance records

### Audit Trail

**Merkle Tree Logging**:
- **Conversation Hashing**: SHA-256 salted hashes
- **Batch Processing**: Hourly Merkle tree construction
- **Blockchain Anchoring**: Immutable root storage
- **Integrity Verification**: Cryptographic proof of data integrity

**Complete Traceability**:
- **Conversation → Policy → Model → Compliance**
- **User Consent → Data Encryption → Storage Proof**
- **Real-time Monitoring → Compliance Checking → Blockchain Storage**

## 🚀 Local Deployment (Streamlit)

### Prerequisites

```bash
# Python 3.8+
python --version

# Node.js 16+ (for blockchain development)
node --version

# Git
git --version
```

### Installation

1. **Clone Repository**:
```bash
git clone https://github.com/your-username/sunwayilabs-launchx-2025-prototype.git
cd sunwayilabs-launchx-2025-prototype
```

2. **Install Python Dependencies**:
```bash
pip install -r requirements.txt
```

3. **Environment Configuration**:
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

4. **Run Streamlit Application**:
```bash
streamlit run app/main.py
```

### Configuration

**Required Environment Variables**:
```bash
# OpenAI API Key
OPENAI_API_KEY=your_openai_api_key_here
OPENAI_MODEL=gpt-4o-mini

# Optional: ILMU API
ILMU_API_URL=your_ilmu_api_url_here

# Blockchain Configuration (Optional)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here

# Contract Addresses (Optional)
CONSENT_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890
STORAGE_PROOF_ADDRESS=0x1234567890123456789012345678901234567890
POLICY_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890
COMPLIANCE_CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890
```

### Local Development Features

**Available Modes**:
- **Full Blockchain**: Complete privacy and compliance features
- **Local Only**: Privacy features without blockchain
- **Basic Mode**: Core chatbot functionality only

**Testing**:
```bash
# Run all tests
pytest

# Run specific test suites
pytest tests/test_chatbot.py
pytest tests/test_privacy.py
pytest tests/test_audit.py
pytest tests/test_compliance.py
```

## 🌐 Vercel Deployment

### Prerequisites

- Vercel account
- GitHub repository
- Environment variables configured

### Deployment Steps

1. **Connect Repository**:
   - Go to [Vercel Dashboard](https://vercel.com/dashboard)
   - Click "New Project"
   - Import your GitHub repository

2. **Configure Build Settings**:
   ```json
   {
     "buildCommand": "pip install -r requirements.txt",
     "outputDirectory": ".",
     "installCommand": "pip install -r requirements.txt"
   }
   ```

3. **Environment Variables**:
   - Add all required environment variables in Vercel dashboard
   - Ensure sensitive keys are properly secured

4. **Deploy**:
   - Click "Deploy"
   - Vercel will automatically build and deploy your application

### Vercel Configuration

**vercel.json**:
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
  ]
}
```

### Production Considerations

**Security**:
- Use Vercel's environment variable encryption
- Enable HTTPS only
- Configure proper CORS settings
- Implement rate limiting

**Performance**:
- Enable Vercel's edge caching
- Optimize Python dependencies
- Use CDN for static assets
- Monitor performance metrics

## ⛓️ Smart Contract Deployment (Hardhat + Polygon Amoy)

### Prerequisites

```bash
# Node.js 16+
npm install -g hardhat

# Install dependencies
npm install
```

### Hardhat Configuration

**hardhat.config.js**:
```javascript
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.19",
  networks: {
    amoy: {
      url: "https://rpc-amoy.polygon.technology",
      accounts: [process.env.PRIVATE_KEY],
      chainId: 80002
    }
  }
};
```

### Contract Deployment

1. **Compile Contracts**:
```bash
npx hardhat compile
```

2. **Deploy to Polygon Amoy**:
```bash
npx hardhat run scripts/deploy.js --network amoy
```

3. **Verify Contracts**:
```bash
npx hardhat verify --network amoy <CONTRACT_ADDRESS>
```

### Deployment Script

**scripts/deploy.js**:
```javascript
const hre = require("hardhat");

async function main() {
  // Deploy ConsentRegistry
  const ConsentRegistry = await hre.ethers.getContractFactory("ConsentRegistry");
  const consentRegistry = await ConsentRegistry.deploy();
  await consentRegistry.deployed();
  console.log("ConsentRegistry deployed to:", consentRegistry.address);

  // Deploy StorageProof
  const StorageProof = await hre.ethers.getContractFactory("StorageProof");
  const storageProof = await StorageProof.deploy();
  await storageProof.deployed();
  console.log("StorageProof deployed to:", storageProof.address);

  // Deploy PolicyRegistry
  const PolicyRegistry = await hre.ethers.getContractFactory("PolicyRegistry");
  const policyRegistry = await PolicyRegistry.deploy();
  await policyRegistry.deployed();
  console.log("PolicyRegistry deployed to:", policyRegistry.address);

  // Deploy ComplianceRegistry
  const ComplianceRegistry = await hre.ethers.getContractFactory("ComplianceRegistry");
  const complianceRegistry = await ComplianceRegistry.deploy();
  await complianceRegistry.deployed();
  console.log("ComplianceRegistry deployed to:", complianceRegistry.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
```

### Post-Deployment

1. **Update Environment Variables**:
```bash
# Update .env with deployed contract addresses
CONSENT_REGISTRY_ADDRESS=0x...
STORAGE_PROOF_ADDRESS=0x...
POLICY_REGISTRY_ADDRESS=0x...
COMPLIANCE_CONTRACT_ADDRESS=0x...
```

2. **Initialize Contracts**:
```bash
# Register initial policies
python -m audit.policy --register-policy "system_prompt" "prompts/rogerian_prompt.txt" "system"

# Register models
python -m audit.policy --register-model "openai" "gpt-4o-mini" '{"temperature": 0.8}'
```

## 🗺️ Future Roadmap

### Phase 1: ZKML Proofs (2026)

**Zero-Knowledge Machine Learning**:
- **Privacy-Preserving Inference**: Prove AI responses without revealing inputs
- **Compliance Verification**: Cryptographic proof of policy adherence
- **User Privacy**: No conversation data leaves user's device
- **Audit Transparency**: Verifiable compliance without data exposure

**Technical Implementation**:
```python
# ZKML Proof Generation
def generate_zkml_proof(conversation, model_output):
    # Generate zero-knowledge proof
    proof = zkml_prover.prove(
        input_data=conversation,
        model_output=model_output,
        compliance_rules=policy_rules
    )
    return proof

# Proof Verification
def verify_zkml_proof(proof, public_inputs):
    return zkml_verifier.verify(proof, public_inputs)
```

### Phase 2: ILMU Integration (2026)

**Malaysian AI Model Integration**:
- **Local Language Support**: Enhanced Bahasa Malaysia capabilities
- **Cultural Context**: Malaysia-specific mental health understanding
- **Regulatory Compliance**: Malaysian data protection laws
- **Performance Optimization**: Reduced latency for local users

**Integration Features**:
```python
class ILMUProvider(ModelProvider):
    def __init__(self):
        self.api_url = os.getenv("ILMU_API_URL")
        self.model_id = os.getenv("ILMU_MODEL", "ilmu-mental-health-v1")
    
    def generate(self, messages: List[Dict[str, str]]) -> str:
        # ILMU API integration
        response = self.ilmu_client.generate(
            messages=messages,
            model=self.model_id,
            temperature=0.8,
            max_tokens=220
        )
        return response.text
```

### Phase 3: Clinician Review Portal (2026)

**Professional Oversight System**:
- **Clinician Dashboard**: Real-time conversation monitoring
- **Risk Assessment**: Automated flagging of concerning conversations
- **Intervention Alerts**: Immediate notification for crisis situations
- **Quality Assurance**: Compliance monitoring and improvement

**Portal Features**:
```python
class ClinicianPortal:
    def __init__(self):
        self.dashboard = Dashboard()
        self.alert_system = AlertSystem()
        self.analytics = Analytics()
    
    def monitor_conversation(self, conversation_id):
        # Real-time monitoring
        conversation = self.get_conversation(conversation_id)
        risk_score = self.assess_risk(conversation)
        
        if risk_score > 0.8:
            self.alert_system.send_alert(conversation_id, risk_score)
    
    def generate_report(self, time_period):
        # Generate compliance and quality reports
        return self.analytics.generate_report(time_period)
```

### Phase 4: Advanced Features (2026)

**Enhanced AI Capabilities**:
- **Multi-modal Support**: Voice, text, and image input
- **Emotion Recognition**: Advanced emotional state detection
- **Personalization**: Adaptive responses based on user history
- **Group Therapy**: Multi-user conversation support

**Blockchain Enhancements**:
- **Cross-chain Compatibility**: Multi-blockchain support
- **NFT Integration**: Unique therapy session tokens
- **DAO Governance**: Community-driven policy updates
- **Token Economics**: Incentive mechanisms for compliance

**Privacy Innovations**:
- **Homomorphic Encryption**: Computation on encrypted data
- **Federated Learning**: Distributed model training
- **Differential Privacy**: Mathematical privacy guarantees
- **Secure Multi-party Computation**: Collaborative analysis

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Code Standards

- **Python**: Follow PEP 8
- **Solidity**: Follow Solidity Style Guide
- **Documentation**: Comprehensive docstrings
- **Testing**: 90%+ code coverage

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Sunway University**: Academic support and research collaboration
- **LaunchX 2025**: Innovation program and mentorship
- **OpenAI**: AI model capabilities
- **Polygon**: Blockchain infrastructure
- **Mental Health Community**: Feedback and validation

## 📞 Support

- **Documentation**: [Wiki](https://github.com/abelcjh/sunwayilabs-launchx-2025-prototype/wiki)
- **Issues**: [GitHub Issues](https://github.com/abelcjh/sunwayilabs-launchx-2025-prototype/issues)
- **Discussions**: [GitHub Discussions](https://github.com/abelcjh/sunwayilabs-launchx-2025-prototype/discussions)

---

**⚠️ Important Notice**: This is a prototype system for educational and research purposes. For production mental health applications, ensure compliance with local healthcare regulations and obtain appropriate professional oversight.

**🆘 Crisis Resources**:
- **Malaysia**: 03-79568145 (Befrienders)
- **International**: +1-800-273-8255 (National Suicide Prevention Lifeline)
- **Emergency**: 999 (Malaysia) / 911 (US)
