// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title StorageProof
 * @dev Smart contract for anchoring encrypted blob storage information and enabling verification
 * @notice This contract stores storage metadata and enables verification of data existence
 */
contract StorageProof {
    
    // Structs
    struct StorageRecord {
        bytes32 blobHash;
        string storageUri;
        string providerId;
        string region;
        uint256 timestamp;
        bytes32 conversationHash;
        bool exists;
        bool isActive;
    }
    
    struct TombstoneRecord {
        bytes32 blobHash;
        string reason;
        uint256 timestamp;
        bool exists;
    }
    
    // Mappings
    mapping(bytes32 => StorageRecord) public storageRecords;
    mapping(bytes32 => TombstoneRecord) public tombstoneRecords;
    mapping(bytes32 => bytes32[]) public conversationToBlobs; // conversationHash => blobHashes[]
    mapping(string => bytes32[]) public providerToBlobs; // providerId => blobHashes[]
    
    // Arrays for enumeration
    bytes32[] public blobHashes;
    bytes32[] public conversationHashes;
    
    // Owner
    address public owner;
    
    // Events
    event StorageRecorded(
        bytes32 indexed blobHash,
        string storageUri,
        string indexed providerId,
        string region,
        uint256 timestamp,
        bytes32 indexed conversationHash
    );
    
    event StorageTombstoned(
        bytes32 indexed blobHash,
        string reason,
        uint256 timestamp,
        bytes32 indexed conversationHash
    );
    
    event StorageVerified(
        bytes32 indexed blobHash,
        bool verified,
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "StorageProof: caller is not the owner");
        _;
    }
    
    modifier storageExists(bytes32 _blobHash) {
        require(storageRecords[_blobHash].exists, "StorageProof: storage record does not exist");
        _;
    }
    
    modifier notTombstoned(bytes32 _blobHash) {
        require(!tombstoneRecords[_blobHash].exists, "StorageProof: storage record is tombstoned");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Record storage of an encrypted blob
     * @param _blobHash Hash of the encrypted blob
     * @param _storageUri URI where the blob is stored
     * @param _providerId Storage provider identifier
     * @param _region Storage region
     * @param _conversationHash Hash of the associated conversation
     */
    function recordStorage(
        bytes32 _blobHash,
        string memory _storageUri,
        string memory _providerId,
        string memory _region,
        bytes32 _conversationHash
    ) external onlyOwner {
        require(_blobHash != bytes32(0), "StorageProof: blob hash cannot be zero");
        require(bytes(_storageUri).length > 0, "StorageProof: storage URI cannot be empty");
        require(bytes(_providerId).length > 0, "StorageProof: provider ID cannot be empty");
        require(bytes(_region).length > 0, "StorageProof: region cannot be empty");
        require(_conversationHash != bytes32(0), "StorageProof: conversation hash cannot be zero");
        require(!storageRecords[_blobHash].exists, "StorageProof: storage record already exists");
        
        storageRecords[_blobHash] = StorageRecord({
            blobHash: _blobHash,
            storageUri: _storageUri,
            providerId: _providerId,
            region: _region,
            timestamp: block.timestamp,
            conversationHash: _conversationHash,
            exists: true,
            isActive: true
        });
        
        // Add to arrays
        blobHashes.push(_blobHash);
        conversationToBlobs[_conversationHash].push(_blobHash);
        providerToBlobs[_providerId].push(_blobHash);
        
        // Add conversation hash if new
        bool conversationExists = false;
        for (uint256 i = 0; i < conversationHashes.length; i++) {
            if (conversationHashes[i] == _conversationHash) {
                conversationExists = true;
                break;
            }
        }
        if (!conversationExists) {
            conversationHashes.push(_conversationHash);
        }
        
        emit StorageRecorded(
            _blobHash,
            _storageUri,
            _providerId,
            _region,
            block.timestamp,
            _conversationHash
        );
    }
    
    /**
     * @dev Create a tombstone record for deleted/revoked data
     * @param _blobHash Hash of the blob to tombstone
     * @param _reason Reason for tombstoning
     */
    function createTombstone(
        bytes32 _blobHash,
        string memory _reason
    ) external onlyOwner storageExists(_blobHash) notTombstoned(_blobHash) {
        require(bytes(_reason).length > 0, "StorageProof: reason cannot be empty");
        
        tombstoneRecords[_blobHash] = TombstoneRecord({
            blobHash: _blobHash,
            reason: _reason,
            timestamp: block.timestamp,
            exists: true
        });
        
        // Mark storage record as inactive
        storageRecords[_blobHash].isActive = false;
        
        emit StorageTombstoned(
            _blobHash,
            _reason,
            block.timestamp,
            storageRecords[_blobHash].conversationHash
        );
    }
    
    /**
     * @dev Verify that a blob exists and is accessible
     * @param _blobHash Hash of the blob to verify
     * @return bool True if blob exists and is active
     */
    function verifyStorage(bytes32 _blobHash) external view returns (bool) {
        if (!storageRecords[_blobHash].exists) {
            return false;
        }
        
        if (tombstoneRecords[_blobHash].exists) {
            return false;
        }
        
        return storageRecords[_blobHash].isActive;
    }
    
    /**
     * @dev Get storage record information
     * @param _blobHash Hash of the blob
     * @return StorageRecord Storage record information
     */
    function getStorageRecord(bytes32 _blobHash) external view storageExists(_blobHash) returns (StorageRecord memory) {
        return storageRecords[_blobHash];
    }
    
    /**
     * @dev Get tombstone record information
     * @param _blobHash Hash of the blob
     * @return TombstoneRecord Tombstone record information
     */
    function getTombstoneRecord(bytes32 _blobHash) external view returns (TombstoneRecord memory) {
        require(tombstoneRecords[_blobHash].exists, "StorageProof: tombstone record does not exist");
        return tombstoneRecords[_blobHash];
    }
    
    /**
     * @dev Get all blob hashes for a conversation
     * @param _conversationHash Hash of the conversation
     * @return bytes32[] Array of blob hashes
     */
    function getBlobsForConversation(bytes32 _conversationHash) external view returns (bytes32[] memory) {
        return conversationToBlobs[_conversationHash];
    }
    
    /**
     * @dev Get all blob hashes for a provider
     * @param _providerId Provider identifier
     * @return bytes32[] Array of blob hashes
     */
    function getBlobsForProvider(string memory _providerId) external view returns (bytes32[] memory) {
        return providerToBlobs[_providerId];
    }
    
    /**
     * @dev Check if storage record exists
     * @param _blobHash Hash of the blob
     * @return bool True if storage record exists
     */
    function storageExists(bytes32 _blobHash) external view returns (bool) {
        return storageRecords[_blobHash].exists;
    }
    
    /**
     * @dev Check if storage record is tombstoned
     * @param _blobHash Hash of the blob
     * @return bool True if storage record is tombstoned
     */
    function isTombstoned(bytes32 _blobHash) external view returns (bool) {
        return tombstoneRecords[_blobHash].exists;
    }
    
    /**
     * @dev Get total number of storage records
     * @return uint256 Number of storage records
     */
    function getStorageCount() external view returns (uint256) {
        return blobHashes.length;
    }
    
    /**
     * @dev Get total number of conversation records
     * @return uint256 Number of conversation records
     */
    function getConversationCount() external view returns (uint256) {
        return conversationHashes.length;
    }
    
    /**
     * @dev Get blob hash by index
     * @param _index Index in the blob array
     * @return bytes32 Blob hash
     */
    function getBlobHashByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < blobHashes.length, "StorageProof: index out of bounds");
        return blobHashes[_index];
    }
    
    /**
     * @dev Get conversation hash by index
     * @param _index Index in the conversation array
     * @return bytes32 Conversation hash
     */
    function getConversationHashByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < conversationHashes.length, "StorageProof: index out of bounds");
        return conversationHashes[_index];
    }
    
    /**
     * @dev Get storage statistics
     * @return uint256 Total storage records
     * @return uint256 Active storage records
     * @return uint256 Tombstoned records
     */
    function getStorageStats() external view returns (uint256, uint256, uint256) {
        uint256 total = blobHashes.length;
        uint256 active = 0;
        uint256 tombstoned = 0;
        
        for (uint256 i = 0; i < total; i++) {
            bytes32 blobHash = blobHashes[i];
            if (tombstoneRecords[blobHash].exists) {
                tombstoned++;
            } else if (storageRecords[blobHash].isActive) {
                active++;
            }
        }
        
        return (total, active, tombstoned);
    }
    
    /**
     * @dev Get storage records by provider
     * @param _providerId Provider identifier
     * @return uint256 Number of records for provider
     * @return uint256 Number of active records for provider
     * @return uint256 Number of tombstoned records for provider
     */
    function getProviderStats(string memory _providerId) external view returns (uint256, uint256, uint256) {
        bytes32[] memory providerBlobs = providerToBlobs[_providerId];
        uint256 total = providerBlobs.length;
        uint256 active = 0;
        uint256 tombstoned = 0;
        
        for (uint256 i = 0; i < total; i++) {
            bytes32 blobHash = providerBlobs[i];
            if (tombstoneRecords[blobHash].exists) {
                tombstoned++;
            } else if (storageRecords[blobHash].isActive) {
                active++;
            }
        }
        
        return (total, active, tombstoned);
    }
    
    /**
     * @dev Get storage records by region
     * @param _region Storage region
     * @return uint256 Number of records in region
     * @return uint256 Number of active records in region
     * @return uint256 Number of tombstoned records in region
     */
    function getRegionStats(string memory _region) external view returns (uint256, uint256, uint256) {
        uint256 total = 0;
        uint256 active = 0;
        uint256 tombstoned = 0;
        
        for (uint256 i = 0; i < blobHashes.length; i++) {
            bytes32 blobHash = blobHashes[i];
            StorageRecord memory record = storageRecords[blobHash];
            
            if (keccak256(abi.encodePacked(record.region)) == keccak256(abi.encodePacked(_region))) {
                total++;
                if (tombstoneRecords[blobHash].exists) {
                    tombstoned++;
                } else if (record.isActive) {
                    active++;
                }
            }
        }
        
        return (total, active, tombstoned);
    }
    
    /**
     * @dev Search storage records by URI pattern
     * @param _uriPattern URI pattern to search for
     * @return bytes32[] Array of matching blob hashes
     */
    function searchByUriPattern(string memory _uriPattern) external view returns (bytes32[] memory) {
        bytes32[] memory matches = new bytes32[](blobHashes.length);
        uint256 matchCount = 0;
        
        for (uint256 i = 0; i < blobHashes.length; i++) {
            bytes32 blobHash = blobHashes[i];
            StorageRecord memory record = storageRecords[blobHash];
            
            if (bytes(record.storageUri).length >= bytes(_uriPattern).length) {
                // Simple substring matching - in production, use more sophisticated pattern matching
                bool matchesPattern = true;
                bytes memory uriBytes = bytes(record.storageUri);
                bytes memory patternBytes = bytes(_uriPattern);
                
                for (uint256 j = 0; j < patternBytes.length; j++) {
                    if (uriBytes[j] != patternBytes[j]) {
                        matchesPattern = false;
                        break;
                    }
                }
                
                if (matchesPattern) {
                    matches[matchCount] = blobHash;
                    matchCount++;
                }
            }
        }
        
        // Create result array with correct size
        bytes32[] memory result = new bytes32[](matchCount);
        for (uint256 i = 0; i < matchCount; i++) {
            result[i] = matches[i];
        }
        
        return result;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "StorageProof: new owner is the zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}
