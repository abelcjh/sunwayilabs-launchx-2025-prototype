# 📋 Policy Management and Compliance System

Comprehensive policy tracking, compliance checking, and blockchain anchoring for therapy guidelines and system prompts.

## 🌟 Features

- **Policy Versioning**: Track system prompts, therapy guidelines, and safety checklists
- **Model Configuration Tracking**: Monitor AI model versions and parameters
- **Automated Compliance Checking**: Real-time policy validation with 8 rule types
- **Blockchain Anchoring**: Immutable policy and compliance records
- **Compliance Scoring**: Quantitative assessment of therapy quality
- **Audit Trail**: Complete conversation-to-policy linking

## 🏗️ Architecture

```
Policy Documents → Content Hashing → Blockchain Registry
       ↓                ↓                    ↓
System Prompts    Version Control      Immutable Proof
Therapy Guidelines  Model Tracking     Compliance Records
Safety Checklists   Rule Engine        Audit Trail
```

## 🔧 Core Components

### PolicyDocument
- **Version Control**: Semantic versioning for policy updates
- **Content Hashing**: SHA-256 integrity verification
- **Type Classification**: System prompts, therapy guidelines, safety checklists
- **Metadata Storage**: Creator, timestamps, activation status

### ModelConfiguration
- **Provider Tracking**: OpenAI, ILMU, custom models
- **Parameter Monitoring**: Temperature, tokens, model settings
- **Configuration Hashing**: Immutable model state verification
- **Version Management**: Model update tracking

### PolicyRuleEngine
- **8 Compliance Rules**: Comprehensive therapy quality assessment
- **Automated Checking**: Real-time conversation validation
- **Scoring System**: 0.0 to 1.0 compliance scores
- **Detailed Reporting**: Rule-specific pass/fail analysis

### ComplianceRecord
- **Conversation Linking**: Hash-based conversation identification
- **Policy Association**: Links to specific policy versions
- **Model Association**: Links to specific model configurations
- **Overall Assessment**: Pass/fail with detailed scoring

## 🚀 Usage Examples

### Policy Registration

```python
from audit import PolicyManager

# Initialize policy manager
manager = PolicyManager()

# Register system prompt
prompt_id = manager.register_policy(
    document_type="system_prompt",
    content="You are EVE, an empathetic AI mental health companion...",
    created_by="system"
)

# Register therapy guideline
guideline_id = manager.register_policy(
    document_type="therapy_guideline",
    content="Rogerian therapy principles: empathy, authenticity, unconditional positive regard...",
    created_by="therapist"
)

# Register safety checklist
safety_id = manager.register_policy(
    document_type="safety_checklist",
    content="Crisis response protocol: 1. Acknowledge feelings 2. Provide resources 3. Encourage help-seeking...",
    created_by="safety_team"
)
```

### Model Registration

```python
# Register OpenAI model
openai_model_id = manager.register_model(
    provider="openai",
    model_name="gpt-4o-mini",
    parameters={
        "temperature": 0.8,
        "max_tokens": 220,
        "top_p": 0.9
    }
)

# Register ILMU model
ilmu_model_id = manager.register_model(
    provider="ilmu",
    model_name="ilmu-mental-health-v1",
    parameters={
        "temperature": 0.7,
        "max_tokens": 200
    }
)
```

### Compliance Checking

```python
# Check conversation compliance
compliance = manager.check_compliance(
    conversation_hash="abc123...",
    user_input="I feel really depressed and hopeless",
    response="I hear that you're feeling depressed and hopeless. That sounds incredibly difficult. What is this feeling like for you?",
    language="en",
    model_id=openai_model_id
)

print(f"Compliance: {compliance.compliance_pass}")
print(f"Overall Score: {compliance.overall_score:.2f}")

# Check individual rule results
for check in compliance.policy_checks:
    print(f"{check.rule_name}: {check.status} (score: {check.score:.2f})")
```

## 📊 Compliance Rules

### 1. Response Length
- **Target**: 2-4 sentences
- **Purpose**: Maintain concise, focused responses
- **Scoring**: Pass (1.0), Warning (0.7), Fail (0.3)

### 2. Non-Directive Language
- **Target**: Avoid directive phrases
- **Purpose**: Maintain Rogerian non-directive approach
- **Patterns**: "you should", "you must", "I recommend"

### 3. Empathy Indicators
- **Target**: Include empathy expressions
- **Purpose**: Ensure empathetic responses
- **Patterns**: "I understand", "I hear you", "that sounds"

### 4. Safety Keywords
- **Target**: Appropriate crisis response
- **Purpose**: Ensure safety protocol compliance
- **Triggers**: Suicide, self-harm, crisis keywords

### 5. Crisis Response
- **Target**: Appropriate crisis handling
- **Purpose**: Prevent harmful crisis responses
- **Checks**: Avoid minimizing, provide resources

### 6. Language Consistency
- **Target**: Match user's language
- **Purpose**: Maintain language consistency
- **Supports**: English, Bahasa Malaysia

### 7. Rogerian Principles
- **Target**: Reflect Rogerian therapy principles
- **Purpose**: Ensure therapeutic approach compliance
- **Patterns**: Reflective listening, open questions

### 8. CBT Techniques
- **Target**: Appropriate CBT usage when relevant
- **Purpose**: Support evidence-based techniques
- **Patterns**: Thought challenging, perspective taking

## 🔗 Blockchain Integration

### PolicyRegistry.sol

Smart contract for policy and compliance management:

```solidity
// Register policy
function registerPolicy(
    bytes32 policyId,
    string version,
    bytes32 policyHash,
    string documentType
) external;

// Register model
function registerModel(
    bytes32 modelId,
    string version,
    bytes32 modelHash,
    string provider
) external;

// Register compliance
function registerCompliance(
    bytes32 conversationHash,
    bytes32 modelHash,
    bytes32 policyHash,
    bool compliancePass
) external;
```

### On-Chain Storage

- **Policy Hashes**: Immutable policy content verification
- **Model Hashes**: Immutable model configuration verification
- **Compliance Records**: Immutable conversation compliance tracking
- **Version History**: Complete policy and model evolution

## 🛠️ CLI Usage

```bash
# Register a policy
python -m audit.policy --register-policy "system_prompt" "prompt.txt" "system"

# Register a model
python -m audit.policy --register-model "openai" "gpt-4o-mini" '{"temperature": 0.8}'

# Check compliance
python -m audit.policy --check-compliance "conv_hash" "I feel sad" "I understand you're feeling sad" "en"

# List policies
python -m audit.policy --list-policies

# List models
python -m audit.policy --list-models
```

## ⚙️ Configuration

### Environment Variables

```bash
# Policy Registry Configuration
POLICY_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890

# Blockchain (shared with other systems)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here
```

### Storage Structure

```
audit/policy_storage/
├─ policies.json          # Policy documents
├─ models.json           # Model configurations
└─ compliance.json       # Compliance records
```

## 🧪 Testing

```bash
# Run policy system tests
pytest tests/test_policy.py -v

# Test specific functionality
pytest tests/test_policy.py::TestPolicyRuleEngine::test_response_length_check -v
```

## 📈 Compliance Analytics

### Scoring System

- **Overall Score**: Weighted average of all rule scores
- **Pass Threshold**: 70% (0.7) for compliance
- **Rule Weights**: Equal weighting for all rules
- **Trend Analysis**: Track compliance over time

### Reporting

- **Real-time Alerts**: Immediate compliance feedback
- **Historical Analysis**: Compliance trend tracking
- **Rule-specific Reports**: Individual rule performance
- **Model Comparison**: Compliance across different models

## 🔒 Security Features

### Immutable Records

- **Blockchain Anchoring**: Tamper-proof policy storage
- **Content Hashing**: SHA-256 integrity verification
- **Version Control**: Complete policy evolution tracking
- **Audit Trail**: Full conversation-to-policy linking

### Access Control

- **Owner-only Registration**: Controlled policy updates
- **Immutable History**: Cannot modify past records
- **Public Verification**: Anyone can verify compliance
- **Transparent Scoring**: Open compliance assessment

## 🚨 Error Handling

The system gracefully handles:

- **Missing Policies**: Graceful degradation
- **Invalid Models**: Fallback to default checks
- **Rule Failures**: Individual rule error isolation
- **Blockchain Issues**: Local storage fallback
- **Network Problems**: Offline compliance checking

## 📊 Integration Points

### Chatbot Integration

- **Automatic Checking**: Every conversation validated
- **Real-time Feedback**: Immediate compliance scoring
- **Model Tracking**: Links responses to model versions
- **Policy Linking**: Associates conversations with policies

### Audit System Integration

- **Conversation Hashing**: Links to audit system
- **Merkle Tree Integration**: Policy hashes in audit trees
- **Blockchain Anchoring**: Shared blockchain infrastructure
- **Compliance Records**: Part of audit trail

## 🔮 Future Enhancements

- [ ] Machine learning-based rule generation
- [ ] Custom rule definition interface
- [ ] Multi-language rule support
- [ ] Advanced compliance analytics
- [ ] Policy recommendation engine
- [ ] Automated policy updates
- [ ] Cross-model compliance comparison
- [ ] Real-time compliance dashboards

## 📚 References

- [Rogerian Therapy Principles](https://en.wikipedia.org/wiki/Person-centered_therapy)
- [CBT Techniques](https://en.wikipedia.org/wiki/Cognitive_behavioral_therapy)
- [Mental Health Safety Protocols](https://www.samhsa.gov/find-help/national-helpline)
- [Blockchain Audit Trails](https://en.wikipedia.org/wiki/Audit_trail)
