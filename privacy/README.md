# 🔐 Privacy and Consent Management System

This module provides comprehensive privacy protection and consent management for the mental health chatbot, ensuring GDPR compliance and user data protection.

## 🌟 Features

- **Verifiable Credentials**: JSON-LD based consent receipts
- **Blockchain Integration**: Immutable consent registry on Polygon/Base
- **Data Encryption**: End-to-end encryption with consent validation
- **Consent Lifecycle**: Create, validate, revoke, and expire consents
- **GDPR Compliance**: Full consent management for data processing
- **DID Integration**: Decentralized Identifier support

## 🏗️ Architecture

```
User Consent → Verifiable Credential → Blockchain Registry → Data Encryption
     ↓              ↓                      ↓                    ↓
  User DID      JSON-LD VC            Smart Contract        Encrypted Data
  Purpose       Digital Signature     Merkle Root          Consent Validation
  Categories    Timestamp            Immutable Proof       Access Control
```

## 📋 Smart Contract

### ConsentRegistry.sol

The smart contract provides:

- `setConsent(consentId, subjectDid, controllerDid, consentHash, expiresAt)`
- `revokeConsent(consentId)`
- `isActive(consentId)` - Check if consent is active
- `getConsent(consentId)` - Get full consent details
- `ConsentSet` and `ConsentRevoked` events

### Key Features

- **Immutable Storage**: Consent hashes stored on blockchain
- **Expiration Handling**: Automatic expiration checking
- **Access Control**: Only subject, controller, or owner can revoke
- **Event Logging**: All consent changes are logged
- **DID Support**: Decentralized Identifier integration

## 🐍 Python Integration

### ConsentManager Class

Main class for consent management:

```python
from privacy import ConsentManager

# Initialize manager
manager = ConsentManager()

# Create consent
receipt = manager.create_consent_receipt(
    subject_did="did:example:user123",
    controller_did="did:example:mentalhealthbot",
    purpose="Mental health support",
    data_categories=["health_data", "conversation_data"],
    processing_activities=["analysis", "storage"]
)

# Register on blockchain
manager.register_consent_on_blockchain(receipt)

# Check consent
is_active = manager.check_consent_active(receipt.consent_id)

# Encrypt data with consent
encrypted = manager.encrypt_data("sensitive data", receipt.consent_id)
```

### Verifiable Credentials

JSON-LD based consent receipts:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/consent/v1"
  ],
  "type": ["VerifiableCredential", "ConsentCredential"],
  "id": "did:example:consent:123",
  "issuer": "did:example:mentalhealthbot",
  "credentialSubject": {
    "id": "did:example:user123",
    "consentId": "consent_123",
    "purpose": "Mental health support",
    "dataCategories": ["health_data", "conversation_data"],
    "processingActivities": ["analysis", "storage"],
    "legalBasis": "consent",
    "expiresAt": 1234567890
  }
}
```

## 🔒 Data Protection

### Encryption Flow

1. **Consent Check**: Validate active consent before processing
2. **Data Encryption**: Encrypt sensitive data with consent validation
3. **Access Control**: Only decrypt with valid consent
4. **Audit Trail**: All operations logged for compliance

### Supported Data Types

- **Health Data**: Mental health conversations and assessments
- **Conversation Data**: Chat history and context
- **Sentiment Data**: Emotional analysis results
- **Personal Data**: User preferences and settings

## 🚀 Usage Examples

### Basic Consent Creation

```python
# Create consent for new user
consent_id = create_consent_for_user("did:example:user123")

# Check if user has consent
active_consent = check_user_consent("did:example:user123")
```

### Data Encryption

```python
# Encrypt conversation data
encrypted_data, consent_id = encrypt_conversation_data(
    "User: I feel anxious\nEVE: I understand...", 
    "did:example:user123"
)

# Decrypt with consent validation
decrypted_data = decrypt_conversation_data(encrypted_data, consent_id)
```

### Chatbot Integration

```python
# Chatbot automatically handles consent
response = rogerian_reply(
    "I'm feeling depressed", 
    user_did="did:example:user123"
)

# Response includes consent info
print(f"Reply: {response['reply']}")
print(f"Encrypted: {response['encrypted']}")
print(f"Consent ID: {response['consent_id']}")
```

## 🛠️ CLI Usage

```bash
# Create a new consent
python -m privacy.consent --create-consent

# Check consent status
python -m privacy.consent --check-consent consent_123

# Revoke consent
python -m privacy.consent --revoke-consent consent_123

# List all consents
python -m privacy.consent --list-consents
```

## ⚙️ Configuration

### Environment Variables

```bash
# Consent Registry Configuration
CONSENT_REGISTRY_ADDRESS=0x1234567890123456789012345678901234567890

# Encryption
ENCRYPTION_KEY=your_encryption_key_here

# Blockchain (same as audit system)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here
```

### Smart Contract Deployment

1. Deploy `ConsentRegistry.sol` to Polygon Mumbai or Base Sepolia
2. Update `CONSENT_REGISTRY_ADDRESS` in environment
3. Ensure contract owner has proper permissions

## 🧪 Testing

```bash
# Run consent system tests
pytest tests/test_consent.py -v

# Test specific functionality
pytest tests/test_consent.py::TestConsentManager::test_consent_receipt_creation -v
```

## 🔐 Security Features

### Cryptographic Protection

- **SHA-256 Hashing**: Consent document integrity
- **Fernet Encryption**: AES-128 symmetric encryption
- **Digital Signatures**: Verifiable Credential authenticity
- **Salt-based Hashing**: Protection against rainbow tables

### Access Control

- **Consent Validation**: All data access requires active consent
- **DID Authentication**: Decentralized identity verification
- **Expiration Handling**: Automatic consent expiration
- **Revocation Support**: Immediate consent withdrawal

### Compliance

- **GDPR Compliance**: Full consent management lifecycle
- **Data Minimization**: Only process necessary data
- **Purpose Limitation**: Data used only for stated purposes
- **Retention Limits**: Automatic data deletion after consent expires

## 📊 Monitoring

### Consent Analytics

- Active consents by user
- Consent expiration tracking
- Revocation patterns
- Data access logs

### Audit Trail

- All consent operations logged
- Blockchain immutability
- Encryption/decryption events
- Access attempt monitoring

## 🚨 Error Handling

The system gracefully handles:

- Missing or invalid consents
- Expired consents
- Blockchain connection failures
- Encryption/decryption errors
- Invalid user DIDs

## 🔮 Future Enhancements

- [ ] Zero-knowledge proof integration
- [ ] Multi-signature consent requirements
- [ ] Consent delegation and proxies
- [ ] Automated consent renewal
- [ ] Privacy-preserving analytics
- [ ] Cross-chain consent portability

## 📚 References

- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [GDPR Consent Guidelines](https://gdpr.eu/consent/)
- [DID Specification](https://www.w3.org/TR/did-core/)
- [JSON-LD Context](https://json-ld.org/)
