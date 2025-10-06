# ✅ Compliance Module

Lightweight policy compliance checking with digital signing and blockchain verification for mental health conversations.

## 🌟 Features

- **Lightweight Policy Checks**: Fast, efficient compliance validation
- **Digital Signing**: Cryptographic signing of compliance results
- **Blockchain Storage**: Immutable compliance hash storage
- **Real-time Verification**: Cross-check against blockchain data
- **Comprehensive Metrics**: Detailed scoring and analysis
- **Multi-language Support**: English and Bahasa Malaysia

## 🏗️ Architecture

```
Conversation → Compliance Check → Digital Sign → Blockchain Storage
     ↓              ↓                ↓              ↓
User Input    Policy Rules      RSA Signature   Immutable Hash
AI Response   Rogerian Check    Compliance Hash  Verification
Language     Safety Protocol   Timestamp       Cross-check
```

## 🔧 Core Components

### ComplianceChecker

**Lightweight Policy Checks**:
- **Rogerian Principles**: Empathetic, non-directive language
- **Diagnostic Language**: Avoids clinical terminology
- **Empathy Indicators**: Presence of understanding expressions
- **Safety Protocols**: Crisis response appropriateness
- **Response Length**: Appropriate conversation length

### ComplianceManager

**Main Management System**:
- Compliance checking and scoring
- Digital signing with RSA keys
- Blockchain storage and verification
- Local storage and persistence
- Statistics and analytics

### ComplianceRegistry.sol

**Smart Contract Features**:
- `storeCompliance()` - Store compliance results
- `verifyCompliance()` - Verify against stored data
- `getCompliance()` - Retrieve compliance records
- `getComplianceStats()` - Get compliance statistics

## 🚀 Usage Examples

### Basic Compliance Checking

```python
from audit import ComplianceManager

# Initialize compliance manager
manager = ComplianceManager()

# Check compliance for a conversation
result = manager.check_compliance(
    conversation_hash="abc123def456...",
    user_input="I feel really anxious about my job",
    response="I hear that you're feeling anxious about your job. That sounds really difficult. What is this anxiety like for you?",
    language="en"
)

print(f"Compliance: {'PASS' if result.pass_status else 'FAIL'}")
print(f"Overall Score: {result.metrics.overall_score:.2f}")
print(f"Checks Passed: {result.metrics.checks_passed}/{result.metrics.checks_performed}")
```

### Compliance Verification

```python
# Verify compliance against blockchain
verified_result = manager.verify_compliance("abc123def456...")

if verified_result:
    print(f"✅ Compliance verified: {'PASS' if verified_result.pass_status else 'FAIL'}")
    print(f"📊 Score: {verified_result.metrics.overall_score:.2f}")
    print(f"🔐 Signature: {verified_result.signature[:16]}...")
else:
    print("❌ Compliance verification failed")
```

### Detailed Metrics Analysis

```python
# Analyze individual compliance metrics
metrics = result.metrics

print(f"Rogerian Score: {metrics.rogerian_score:.2f}")
print(f"Diagnostic Language: {metrics.diagnostic_language_score:.2f}")
print(f"Empathy Score: {metrics.empathy_score:.2f}")
print(f"Safety Score: {metrics.safety_score:.2f}")
print(f"Response Length: {metrics.response_length_score:.2f}")
```

## 📊 Compliance Rules

### 1. Rogerian Principles (0.0 - 1.0)
**Purpose**: Ensure empathetic, non-directive responses

**Positive Indicators**:
- "I hear", "I understand", "I can see"
- "How does that feel?", "What is that like?"
- "Would you like to share?", "Tell me more"
- "It sounds like", "I can sense"
- "That must be", "That would be"

**Negative Indicators**:
- "You should", "You must", "You need to"
- "Try this", "Do this", "Follow this"
- "I recommend", "I suggest", "I advise"
- "Here's what you do", "The solution is"

### 2. Diagnostic Language Avoidance (0.0 - 1.0)
**Purpose**: Prevent inappropriate clinical terminology

**Avoided Patterns**:
- "You have depression/anxiety/bipolar"
- "Diagnosis", "symptoms", "disorder", "condition"
- "You need therapy/medication/treatment"
- "Clinical", "pathological", "abnormal"

### 3. Empathy Indicators (0.0 - 1.0)
**Purpose**: Ensure empathetic responses

**Empathy Patterns**:
- "I understand", "I hear you", "I can see"
- "That sounds", "it sounds like", "I can imagine"
- "That must be", "that would be", "I can sense"
- "Thank you for sharing", "I appreciate you telling me"
- "I'm here for you", "you're not alone"

### 4. Safety Protocols (0.0 - 1.0)
**Purpose**: Ensure appropriate crisis response

**Crisis Keywords**:
- "suicide", "kill myself", "end it", "bunuh diri"
- "harm myself", "hurt myself", "self harm"
- "die", "death", "not worth living"

**Appropriate Response Patterns**:
- "emergency", "crisis", "immediate help"
- "hotline", "helpline", "support line"
- "trusted person", "professional help"
- "you are not alone", "people care"

**Inappropriate Response Patterns**:
- "it's not that bad", "you'll get over it"
- "think positive", "just be happy"
- "other people have it worse"

### 5. Response Length (0.0 - 1.0)
**Purpose**: Maintain appropriate conversation length

**Target**: 2-4 sentences
- 1 sentence: 0.7 score
- 2-4 sentences: 1.0 score
- 5 sentences: 0.8 score
- 6+ sentences: 0.5 score

## 🔐 Digital Signing

### RSA Key Generation

```python
# Generate signing key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save key
with open("signing_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
```

### Signature Verification

```python
# Verify signature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

public_key = key.public_key()
try:
    public_key.verify(
        bytes.fromhex(signature),
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Signature verified")
except:
    print("❌ Signature verification failed")
```

## 🔗 Blockchain Integration

### ComplianceRegistry.sol

```solidity
// Store compliance result
function storeCompliance(
    bytes32 _conversationHash,
    bytes32 _policyCheckId,
    bool _passStatus,
    bytes32 _complianceHash,
    bytes memory _signature
) external;

// Verify compliance
function verifyCompliance(
    bytes32 _conversationHash,
    bytes32 _expectedComplianceHash
) external view returns (bool);

// Get compliance record
function getCompliance(bytes32 _conversationHash) 
    external view returns (ComplianceRecord memory);
```

### On-Chain Storage

- **Compliance Records**: Immutable compliance results
- **Digital Signatures**: Cryptographic proof of authenticity
- **Timestamps**: When compliance was checked
- **Policy Check IDs**: Link to specific policy versions
- **Pass/Fail Status**: Binary compliance result

## 🛠️ CLI Usage

```bash
# Check compliance
python -m audit.compliance --check-compliance "conv123" "I feel sad" "I understand you're feeling sad." "en"

# Verify compliance
python -m audit.compliance --verify-compliance "conv123"

# Get compliance statistics
python -m audit.compliance --get-stats
```

## ⚙️ Configuration

### Environment Variables

```bash
# Compliance Configuration
COMPLIANCE_CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890
SIGNING_KEY_PATH=privacy/signing_key.pem

# Blockchain (shared with other systems)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here
```

### Storage Structure

```
audit/compliance_storage/
└─ compliance_results.json    # Local compliance storage
```

## 🧪 Testing

```bash
# Run compliance tests
pytest tests/test_compliance.py -v

# Test specific functionality
pytest tests/test_compliance.py::TestComplianceChecker::test_check_rogerian_principles -v
```

## 📈 Compliance Analytics

### Scoring System

- **Overall Score**: Weighted average of all rule scores
- **Pass Threshold**: 70% (0.7) for compliance
- **Individual Scores**: 0.0 to 1.0 for each rule
- **Checks Passed**: Number of rules that passed (≥0.7)

### Statistics

```python
# Get compliance statistics
stats = manager.get_compliance_stats()

print(f"Total checks: {stats['total']}")
print(f"Passed: {stats['passed']}")
print(f"Failed: {stats['failed']}")
print(f"Average score: {stats['average_score']:.2f}")
```

### Real-time Monitoring

- **Compliance Rate**: Percentage of conversations that pass
- **Rule Performance**: Individual rule success rates
- **Trend Analysis**: Compliance over time
- **Alert System**: Immediate feedback on failures

## 🔒 Security Features

### Immutable Records

- **Blockchain Anchoring**: Tamper-proof compliance storage
- **Digital Signatures**: Cryptographic authenticity proof
- **Content Hashing**: SHA-256 integrity verification
- **Timestamp Verification**: When compliance was checked

### Access Control

- **Owner-only Storage**: Controlled compliance recording
- **Public Verification**: Anyone can verify compliance
- **Signature Validation**: Cryptographic proof of authenticity
- **Transparent Scoring**: Open compliance assessment

## 🚨 Error Handling

The system gracefully handles:

- **Missing Signing Keys**: Automatic key generation
- **Blockchain Issues**: Local storage fallback
- **Invalid Signatures**: Clear error messages
- **Network Problems**: Offline compliance checking
- **Malformed Data**: Graceful degradation

## 📊 Integration Points

### Policy System Integration

- **Rule Engine**: Uses PolicyRuleEngine for advanced checks
- **Policy Linking**: Links to specific policy versions
- **Compliance Records**: Part of policy compliance system
- **Shared Metrics**: Consistent scoring across systems

### Audit System Integration

- **Conversation Hashing**: Links to audit system
- **Merkle Tree Integration**: Compliance hashes in audit trees
- **Blockchain Anchoring**: Shared blockchain infrastructure
- **Audit Trail**: Part of complete audit trail

## 🔮 Future Enhancements

- [ ] Machine learning-based compliance scoring
- [ ] Custom rule definition interface
- [ ] Multi-language rule support
- [ ] Advanced compliance analytics
- [ ] Real-time compliance dashboards
- [ ] Automated compliance reporting
- [ ] Cross-model compliance comparison
- [ ] Compliance recommendation engine

## 📚 References

- [Rogerian Therapy Principles](https://en.wikipedia.org/wiki/Person-centered_therapy)
- [Mental Health Safety Protocols](https://www.samhsa.gov/find-help/national-helpline)
- [Digital Signatures](https://en.wikipedia.org/wiki/Digital_signature)
- [Blockchain Compliance](https://ethereum.org/en/developers/docs/storage/)
