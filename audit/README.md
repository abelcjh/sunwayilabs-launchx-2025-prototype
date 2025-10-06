# 🔐 Conversation Audit System

This module provides cryptographic proof of conversation integrity by anchoring conversation hashes to blockchain networks.

## 🌟 Features

- **Salted SHA-256 Hashing**: Each conversation is hashed with a configurable salt
- **Merkle Tree Batching**: Conversations are batched into Merkle trees for efficiency
- **Blockchain Anchoring**: Merkle roots are stored on Polygon/Base testnets
- **Local Audit Logs**: All conversations and Merkle roots are stored locally
- **Verification System**: Verify conversation integrity against Merkle roots
- **CLI Interface**: Manual anchoring and testing capabilities

## 🏗️ Architecture

```
Conversation → Salted Hash → Merkle Tree → Blockchain Root
     ↓              ↓            ↓            ↓
  User Input    SHA-256      Batch Tree   On-Chain Proof
  AI Reply      + Salt       Root Hash    Timestamp
```

## 🚀 Quick Start

### 1. Environment Setup

Add to your `.env` file:

```bash
# Audit Configuration
AUDIT_SALT=your_secure_audit_salt_here

# Blockchain Configuration (Optional)
BLOCKCHAIN_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/your_key
PRIVATE_KEY=your_wallet_private_key_here
CONTRACT_ADDRESS=0x1234567890123456789012345678901234567890
```

### 2. Basic Usage

```python
from audit import ConversationAuditor

# Initialize auditor
auditor = ConversationAuditor()

# Add conversations
auditor.add_conversation("Hello", "Hi there!", "en")
auditor.add_conversation("Saya rasa tertekan", "Kedengaran seperti anda sedang menanggung tekanan", "ms")

# Batch and anchor to blockchain
root_hash = auditor.batch_and_anchor(force=True)
print(f"Anchored Merkle root: {root_hash}")
```

### 3. CLI Usage

```bash
# Add sample conversations and anchor
python -m audit.anchor --add-sample --force

# Force anchor existing conversations
python -m audit.anchor --force

# Check help
python -m audit.anchor --help
```

## 🔧 API Reference

### ConversationAuditor

Main class for conversation auditing and blockchain anchoring.

#### Methods

- `add_conversation(user_input, reply, language)`: Add conversation to audit queue
- `batch_and_anchor(force=False)`: Batch conversations and anchor to blockchain
- `hash_conversation(conversation)`: Compute salted hash of conversation

### Helper Functions

- `verify_digest(conversation, root_hash)`: Verify conversation is part of Merkle tree
- `get_latest_root()`: Get latest Merkle root and timestamp

## 🔗 Blockchain Integration

### Supported Networks

- **Polygon Mumbai Testnet**: `https://polygon-mumbai.g.alchemy.com/v2/YOUR_KEY`
- **Base Sepolia Testnet**: `https://sepolia.base.org`

### Smart Contract

The system expects a simple smart contract with these functions:

```solidity
contract AuditContract {
    function storeRoot(bytes32 root, uint256 timestamp) external;
    function getLatestRoot() external view returns (bytes32 root, uint256 timestamp);
}
```

## 📊 Audit Log Format

Local audit logs are stored in `audit/audit_log.json`:

```json
{
  "entries": [
    {
      "timestamp": 1234567890.0,
      "merkle_root": "abc123...",
      "conversation_count": 5,
      "conversations": [
        {
          "user_input": "Hello",
          "reply": "Hi there!",
          "timestamp": 1234567890.0,
          "language": "en",
          "hash": "def456..."
        }
      ]
    }
  ]
}
```

## 🧪 Testing

Run the test suite:

```bash
pytest tests/test_audit.py -v
```

## 🔒 Security Considerations

1. **Salt Security**: Use a strong, unique salt for production
2. **Private Key Security**: Store private keys securely (use environment variables)
3. **Network Security**: Use HTTPS RPC endpoints
4. **Gas Management**: Monitor gas costs for blockchain transactions

## 🚨 Error Handling

The system gracefully handles:
- Blockchain connection failures (falls back to local storage)
- Invalid conversation data
- Missing environment variables
- Network timeouts

## 📈 Performance

- **Batching**: Conversations are batched every 10 messages or hourly
- **Gas Optimization**: Merkle trees reduce blockchain transaction costs
- **Local Storage**: Fast local verification without blockchain queries

## 🔮 Future Enhancements

- [ ] Support for additional blockchain networks
- [ ] Merkle proof generation for individual conversations
- [ ] Batch verification of multiple conversations
- [ ] Integration with IPFS for conversation storage
- [ ] Real-time monitoring dashboard
