# 🔐 Key Broker System

Advanced encryption and key management system for secure data storage with consent-based access control.

## 🌟 Features

- **AES-256-GCM Encryption**: Military-grade symmetric encryption
- **Per-Session DEKs**: Unique Data Encryption Keys for each session
- **Threshold Encryption**: Mock proxy-re-encryption for key sharing
- **Consent Integration**: On-chain consent validation before access
- **Multi-Storage**: Local filesystem and S3 cloud storage
- **Access Control**: Granular permission management
- **Key Lifecycle**: Automatic key rotation and cleanup

## 🏗️ Architecture

```
User Data → Consent Check → DEK Generation → AES-256-GCM → Storage
    ↓            ↓              ↓              ↓           ↓
Plaintext   Blockchain      Per-Session    Encrypted   CID/Path
Request     Validation      Key Material   Blob        Return
```

## 🔧 Core Components

### DataEncryptionKey (DEK)
- **Per-session keys**: Unique 256-bit keys for each data scope
- **Expiration handling**: Automatic key rotation
- **Wrapped keys**: Threshold encryption for sharing
- **Owner tracking**: DID-based ownership

### ThresholdEncryption
- **Mock implementation**: Simplified proxy-re-encryption
- **Key sharing**: Secure key distribution
- **Access control**: Viewer-specific key wrapping
- **Reconstruction**: Threshold-based key recovery

### EncryptedBlob
- **Metadata storage**: Record ID, scope, timestamps
- **Encrypted data**: AES-256-GCM encrypted content
- **Nonce storage**: Unique nonce for each encryption
- **Size tracking**: Content size and type information

## 🚀 Usage Examples

### Basic Storage and Retrieval

```python
from privacy import KeyBroker

# Initialize key broker
broker = KeyBroker(storage_type="local")

# Store encrypted data
record_id = broker.store_blob(
    user_did="did:example:user123",
    plaintext="sensitive mental health data",
    scope="health_data"
)

# Retrieve and decrypt data
decrypted_data = broker.fetch_blob(
    viewer_did="did:example:user123",
    record_id=record_id,
    scope="health_data"
)
```

### Key Sharing

```python
# Share access with another user
broker.share_access(
    owner_did="did:example:user123",
    viewer_did="did:example:therapist",
    scope="health_data"
)

# Viewer can now access the data
therapist_data = broker.fetch_blob(
    viewer_did="did:example:therapist",
    record_id=record_id,
    scope="health_data"
)
```

### S3 Cloud Storage

```python
# Initialize with S3 storage
broker = KeyBroker(
    storage_type="s3",
    s3_bucket="my-encrypted-bucket",
    aws_access_key="your_access_key",
    aws_secret_key="your_secret_key"
)

# Store in S3
record_id = broker.store_blob(
    user_did="did:example:user123",
    plaintext="cloud-stored data",
    scope="conversation_data"
)
```

## 🔐 Security Features

### Encryption
- **AES-256-GCM**: Authenticated encryption with Galois/Counter Mode
- **Unique nonces**: 96-bit nonces for each encryption
- **Key derivation**: PBKDF2-based key generation
- **Perfect forward secrecy**: New keys for each session

### Access Control
- **Consent validation**: On-chain consent checking
- **DID-based identity**: Decentralized Identifier authentication
- **Scope-based permissions**: Granular data category access
- **Time-based expiration**: Automatic access revocation

### Key Management
- **Per-session DEKs**: Unique keys for each data scope
- **Threshold encryption**: Secure key sharing mechanism
- **Automatic cleanup**: Expired key removal
- **Wrapped keys**: Viewer-specific key access

## 📊 API Reference

### KeyBroker Class

#### Constructor
```python
KeyBroker(
    storage_type="local",           # "local" or "s3"
    s3_bucket=None,                # S3 bucket name
    aws_access_key=None,           # AWS access key
    aws_secret_key=None,           # AWS secret key
    storage_path="privacy/storage" # Local storage path
)
```

#### Core Methods

**store_blob(user_did, plaintext, scope)**
- Store encrypted data with consent validation
- Returns: Record ID or None

**fetch_blob(viewer_did, record_id, scope)**
- Retrieve and decrypt data with access control
- Returns: Decrypted plaintext or None

**share_access(owner_did, viewer_did, scope)**
- Share data access with another user
- Returns: Success boolean

**revoke_access(owner_did, viewer_did, scope)**
- Revoke data access from user
- Returns: Success boolean

**list_user_blobs(user_did, scope=None)**
- List all blobs for a user
- Returns: List of blob metadata

**cleanup_expired_keys()**
- Remove expired DEKs
- Returns: None

## 🛠️ CLI Usage

```bash
# Store encrypted data
python -m privacy.keybroker --store "did:example:user123" "sensitive data" "health_data"

# Fetch and decrypt data
python -m privacy.keybroker --fetch "did:example:user123" "blob_abc123" "health_data"

# Share access
python -m privacy.keybroker --share "did:example:user123" "did:example:therapist" "health_data"

# List user's blobs
python -m privacy.keybroker --list "did:example:user123" "health_data"
```

## ⚙️ Configuration

### Environment Variables

```bash
# Storage Configuration
STORAGE_TYPE=local                    # or "s3"
S3_BUCKET=your-s3-bucket-name
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Consent Integration (shared with consent system)
CONSENT_REGISTRY_ADDRESS=0x1234...
BLOCKCHAIN_RPC_URL=https://...
PRIVATE_KEY=your_private_key
```

### Storage Options

**Local Storage**
- Files stored in `privacy/storage/blobs/`
- Metadata in `privacy/storage/metadata.json`
- Fast access, no external dependencies

**S3 Storage**
- Encrypted blobs in S3 bucket
- Metadata includes S3 keys
- Scalable, cloud-based storage
- Requires AWS credentials

## 🧪 Testing

```bash
# Run key broker tests
pytest tests/test_keybroker.py -v

# Test specific functionality
pytest tests/test_keybroker.py::TestKeyBroker::test_store_blob -v
```

## 🔒 Security Considerations

### Encryption Strength
- **AES-256**: 256-bit key length
- **GCM Mode**: Authenticated encryption
- **Unique Nonces**: Prevent replay attacks
- **Key Rotation**: Regular key updates

### Access Control
- **Consent Validation**: Blockchain-based verification
- **DID Authentication**: Decentralized identity
- **Scope Restrictions**: Category-based access
- **Time Expiration**: Automatic access revocation

### Key Management
- **Secure Generation**: Cryptographically secure random keys
- **Threshold Sharing**: Distributed key access
- **Automatic Cleanup**: Expired key removal
- **No Key Reuse**: Fresh keys for each session

## 📈 Performance

### Storage Efficiency
- **Compressed Metadata**: JSON-based storage
- **Efficient Encryption**: AES-GCM performance
- **Batch Operations**: Multiple blob handling
- **Lazy Loading**: On-demand data retrieval

### Scalability
- **S3 Integration**: Cloud storage scaling
- **Key Pooling**: Reuse of valid DEKs
- **Parallel Processing**: Concurrent operations
- **Memory Management**: Efficient resource usage

## 🚨 Error Handling

The system gracefully handles:
- **Missing Consents**: Automatic consent creation
- **Expired Keys**: Automatic key regeneration
- **Storage Failures**: Fallback mechanisms
- **Access Denied**: Clear error messages
- **Network Issues**: Retry mechanisms

## 🔮 Future Enhancements

- [ ] Real Shamir's Secret Sharing implementation
- [ ] Proxy re-encryption integration
- [ ] Zero-knowledge proof access control
- [ ] Multi-party computation for key sharing
- [ ] Hardware security module integration
- [ ] Quantum-resistant encryption algorithms

## 📚 References

- [AES-GCM Specification](https://tools.ietf.org/html/rfc5288)
- [Threshold Cryptography](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
- [Proxy Re-encryption](https://en.wikipedia.org/wiki/Proxy_re-encryption)
- [AWS S3 Security](https://docs.aws.amazon.com/s3/latest/userguide/security.html)
