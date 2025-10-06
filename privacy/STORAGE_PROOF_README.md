# 🔗 Storage Proof System

Comprehensive storage verification and blockchain anchoring system for encrypted blob storage metadata.

## 🌟 Features

- **Blockchain Anchoring**: Immutable storage metadata on-chain
- **Storage Verification**: Verify blob existence at known endpoints
- **Tombstone Management**: Track data deletion and consent revocation
- **Multi-Provider Support**: Local files, S3, HTTP/HTTPS endpoints
- **Conversation Linking**: Link storage proofs to conversation hashes
- **Accessibility Checking**: Real-time verification of storage accessibility

## 🏗️ Architecture

```
Encrypted Blob → Storage Metadata → Blockchain Registry
      ↓              ↓                    ↓
  Blob Hash      Storage URI         Immutable Proof
  Provider ID    Region Info         Tombstone Events
  Timestamp      Conversation Link   Verification Status
```

## 🔧 Core Components

### StorageProof.sol Smart Contract

**Storage Management**:
- `recordStorage()` - Anchor storage metadata
- `createTombstone()` - Mark data as deleted/revoked
- `verifyStorage()` - Check if blob exists and is active
- `getBlobsForConversation()` - Get all blobs for a conversation

**Events**:
- `StorageRecorded` - Emitted when new data is stored
- `StorageTombstoned` - Emitted when data is deleted
- `StorageVerified` - Emitted during verification

### StorageProofClient Python Client

**Storage Operations**:
- `record_storage()` - Record blob storage metadata
- `create_tombstone()` - Create tombstone for deleted data
- `verify_storage()` - Verify blob accessibility
- `get_blobs_for_conversation()` - Get conversation blobs

**Verification**:
- Local file existence checking
- HTTP/HTTPS endpoint verification
- S3 object accessibility (with boto3)
- Tombstone status validation

## 🚀 Usage Examples

### Basic Storage Recording

```python
from privacy import StorageProofClient

# Initialize client
client = StorageProofClient()

# Record storage of encrypted blob
success = client.record_storage(
    blob_hash="abc123def456...",
    storage_uri="s3://my-bucket/encrypted-blob.enc",
    provider_id="aws-s3",
    region="us-east-1",
    conversation_hash="conv_123456..."
)

print(f"Storage recorded: {success}")
```

### Storage Verification

```python
# Verify blob accessibility
result = client.verify_storage("abc123def456...")

print(f"Verified: {result.verified}")
print(f"Accessible: {result.accessible}")
if result.error_message:
    print(f"Error: {result.error_message}")
```

### Tombstone Management

```python
# Create tombstone when data is deleted
client.create_tombstone(
    blob_hash="abc123def456...",
    reason="consent_revoked"
)

# Check if blob is tombstoned
tombstone = client.get_tombstone_record("abc123def456...")
if tombstone:
    print(f"Tombstoned: {tombstone.reason}")
```

### Conversation Linking

```python
# Get all blobs for a conversation
blobs = client.get_blobs_for_conversation("conv_123456...")

for blob in blobs:
    print(f"Blob: {blob.blob_hash[:16]}... at {blob.storage_uri}")
    print(f"Provider: {blob.provider_id} in {blob.region}")
    print(f"Active: {blob.is_active}")
```

## 🔗 Smart Contract Integration

### StorageProof.sol

```solidity
// Record storage metadata
function recordStorage(
    bytes32 _blobHash,
    string memory _storageUri,
    string memory _providerId,
    string memory _region,
    bytes32 _conversationHash
) external;

// Create tombstone for deleted data
function createTombstone(
    bytes32 _blobHash,
    string memory _reason
) external;

// Verify storage exists and is active
function verifyStorage(bytes32 _blobHash) external view returns (bool);

// Get all blobs for a conversation
function getBlobsForConversation(bytes32 _conversationHash) 
    external view returns (bytes32[] memory);
```

### On-Chain Storage

- **Storage Records**: Immutable blob metadata
- **Tombstone Records**: Deletion/revocation tracking
- **Conversation Mapping**: Link conversations to blobs
- **Provider Statistics**: Track storage by provider
- **Region Analytics**: Geographic storage distribution

## 🛠️ CLI Usage

```bash
# Record storage
python -m privacy.storage_proof --record-storage "abc123" "s3://bucket/blob.enc" "aws-s3" "us-east-1" "conv123"

# Create tombstone
python -m privacy.storage_proof --create-tombstone "abc123" "consent_revoked"

# Verify storage
python -m privacy.storage_proof --verify-storage "abc123"

# Get conversation blobs
python -m privacy.storage_proof --get-conversation-blobs "conv123"

# Get storage statistics
python -m privacy.storage_proof --get-stats
```

## ⚙️ Configuration

### Environment Variables

```bash
# Storage Proof Configuration
STORAGE_PROOF_ADDRESS=0x1234567890123456789012345678901234567890

# Blockchain (shared with other systems)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here
```

### Storage Providers

**Local Files**:
- Scheme: `file://`
- Verification: File existence check
- Example: `file:///tmp/encrypted-blob.enc`

**AWS S3**:
- Scheme: `s3://`
- Verification: S3 HEAD request (requires boto3)
- Example: `s3://my-bucket/path/blob.enc`

**HTTP/HTTPS**:
- Scheme: `http://` or `https://`
- Verification: HTTP HEAD request
- Example: `https://api.example.com/blob.enc`

## 🧪 Testing

```bash
# Run storage proof tests
pytest tests/test_storage_proof.py -v

# Test specific functionality
pytest tests/test_storage_proof.py::TestStorageProofClient::test_verify_storage_local_file -v
```

## 📊 Storage Analytics

### Statistics

```python
# Get storage statistics
stats = client.get_storage_stats()
print(f"Total records: {stats['total']}")
print(f"Active records: {stats['active']}")
print(f"Tombstoned records: {stats['tombstoned']}")
print(f"Inactive records: {stats['inactive']}")
```

### Provider Analysis

```python
# Get blobs by provider
s3_blobs = client.get_blobs_for_provider("aws-s3")
local_blobs = client.get_blobs_for_provider("local")

print(f"S3 blobs: {len(s3_blobs)}")
print(f"Local blobs: {len(local_blobs)}")
```

### Search and Discovery

```python
# Search by URI pattern
s3_blobs = client.search_by_uri_pattern("s3://my-bucket/")
encrypted_files = client.search_by_uri_pattern(".enc")
```

## 🔒 Security Features

### Immutable Records

- **Blockchain Anchoring**: Tamper-proof storage metadata
- **Content Hashing**: SHA-256 blob integrity verification
- **Tombstone Tracking**: Permanent deletion records
- **Version History**: Complete storage evolution

### Access Control

- **Owner-only Operations**: Controlled storage recording
- **Immutable History**: Cannot modify past records
- **Public Verification**: Anyone can verify storage
- **Transparent Deletion**: Open tombstone tracking

## 🚨 Error Handling

The system gracefully handles:

- **Missing Files**: Clear error messages for inaccessible storage
- **Network Issues**: Timeout handling for remote verification
- **Provider Failures**: Fallback mechanisms for verification
- **Blockchain Issues**: Local storage fallback
- **Invalid URIs**: Graceful handling of malformed storage URIs

## 📈 Performance

### Verification Efficiency

- **Local Files**: Instant file existence checks
- **HTTP Endpoints**: 10-second timeout with HEAD requests
- **S3 Objects**: Efficient HEAD requests with boto3
- **Batch Operations**: Multiple blob verification

### Storage Optimization

- **Metadata Compression**: Efficient JSON storage
- **Lazy Loading**: On-demand verification
- **Caching**: Local storage record caching
- **Parallel Processing**: Concurrent verification

## 🔗 Integration Points

### Key Broker Integration

- **Automatic Recording**: Storage proofs created on blob storage
- **Tombstone Creation**: Automatic tombstones on consent revocation
- **Conversation Linking**: Blobs linked to conversation hashes
- **Provider Tracking**: Storage provider and region tracking

### Audit System Integration

- **Conversation Hashing**: Links to audit system
- **Merkle Tree Integration**: Storage proofs in audit trees
- **Blockchain Anchoring**: Shared blockchain infrastructure
- **Compliance Records**: Part of audit trail

## 🔮 Future Enhancements

- [ ] IPFS storage provider support
- [ ] Decentralized storage verification
- [ ] Multi-signature storage approval
- [ ] Automated storage migration
- [ ] Cross-chain storage verification
- [ ] Storage cost optimization
- [ ] Real-time storage monitoring
- [ ] Storage analytics dashboard

## 📚 References

- [AWS S3 API](https://docs.aws.amazon.com/s3/latest/API/)
- [HTTP HEAD Method](https://tools.ietf.org/html/rfc7231#section-4.3.2)
- [Blockchain Storage Patterns](https://ethereum.org/en/developers/docs/storage/)
- [File URI Scheme](https://tools.ietf.org/html/rfc8089)
