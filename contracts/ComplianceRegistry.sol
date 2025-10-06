// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ComplianceRegistry
 * @dev Smart contract for storing and verifying compliance check results
 * @notice This contract stores compliance hashes and enables verification against blockchain data
 */
contract ComplianceRegistry {
    
    // Structs
    struct ComplianceRecord {
        bytes32 conversationHash;
        bytes32 policyCheckId;
        bool passStatus;
        bytes32 complianceHash;
        uint256 timestamp;
        bytes signature;
        bool exists;
    }
    
    // Mappings
    mapping(bytes32 => ComplianceRecord) public complianceRecords; // conversationHash => ComplianceRecord
    mapping(bytes32 => bytes32[]) public policyCheckToConversations; // policyCheckId => conversationHashes[]
    
    // Arrays for enumeration
    bytes32[] public conversationHashes;
    bytes32[] public policyCheckIds;
    
    // Owner
    address public owner;
    
    // Events
    event ComplianceStored(
        bytes32 indexed conversationHash,
        bytes32 indexed policyCheckId,
        bool passStatus,
        bytes32 complianceHash,
        uint256 timestamp
    );
    
    event ComplianceVerified(
        bytes32 indexed conversationHash,
        bool verified,
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "ComplianceRegistry: caller is not the owner");
        _;
    }
    
    modifier complianceExists(bytes32 _conversationHash) {
        require(complianceRecords[_conversationHash].exists, "ComplianceRegistry: compliance record does not exist");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Store compliance check result
     * @param _conversationHash Hash of the conversation
     * @param _policyCheckId ID of the policy check
     * @param _passStatus Whether the compliance check passed
     * @param _complianceHash Hash of the compliance data
     * @param _signature Digital signature of the compliance data
     */
    function storeCompliance(
        bytes32 _conversationHash,
        bytes32 _policyCheckId,
        bool _passStatus,
        bytes32 _complianceHash,
        bytes memory _signature
    ) external onlyOwner {
        require(_conversationHash != bytes32(0), "ComplianceRegistry: conversation hash cannot be zero");
        require(_policyCheckId != bytes32(0), "ComplianceRegistry: policy check ID cannot be zero");
        require(_complianceHash != bytes32(0), "ComplianceRegistry: compliance hash cannot be zero");
        require(_signature.length > 0, "ComplianceRegistry: signature cannot be empty");
        require(!complianceRecords[_conversationHash].exists, "ComplianceRegistry: compliance record already exists");
        
        complianceRecords[_conversationHash] = ComplianceRecord({
            conversationHash: _conversationHash,
            policyCheckId: _policyCheckId,
            passStatus: _passStatus,
            complianceHash: _complianceHash,
            timestamp: block.timestamp,
            signature: _signature,
            exists: true
        });
        
        // Add to arrays
        conversationHashes.push(_conversationHash);
        policyCheckToConversations[_policyCheckId].push(_conversationHash);
        
        // Add policy check ID if new
        bool policyCheckExists = false;
        for (uint256 i = 0; i < policyCheckIds.length; i++) {
            if (policyCheckIds[i] == _policyCheckId) {
                policyCheckExists = true;
                break;
            }
        }
        if (!policyCheckExists) {
            policyCheckIds.push(_policyCheckId);
        }
        
        emit ComplianceStored(
            _conversationHash,
            _policyCheckId,
            _passStatus,
            _complianceHash,
            block.timestamp
        );
    }
    
    /**
     * @dev Get compliance record by conversation hash
     * @param _conversationHash Hash of the conversation
     * @return ComplianceRecord The compliance record
     */
    function getCompliance(bytes32 _conversationHash) external view complianceExists(_conversationHash) returns (ComplianceRecord memory) {
        return complianceRecords[_conversationHash];
    }
    
    /**
     * @dev Check if compliance record exists
     * @param _conversationHash Hash of the conversation
     * @return bool True if compliance record exists
     */
    function complianceExists(bytes32 _conversationHash) external view returns (bool) {
        return complianceRecords[_conversationHash].exists;
    }
    
    /**
     * @dev Get all conversation hashes for a policy check
     * @param _policyCheckId ID of the policy check
     * @return bytes32[] Array of conversation hashes
     */
    function getConversationsForPolicyCheck(bytes32 _policyCheckId) external view returns (bytes32[] memory) {
        return policyCheckToConversations[_policyCheckId];
    }
    
    /**
     * @dev Verify compliance against stored data
     * @param _conversationHash Hash of the conversation
     * @param _expectedComplianceHash Expected compliance hash
     * @return bool True if verification passes
     */
    function verifyCompliance(bytes32 _conversationHash, bytes32 _expectedComplianceHash) external view returns (bool) {
        if (!complianceRecords[_conversationHash].exists) {
            return false;
        }
        
        ComplianceRecord memory record = complianceRecords[_conversationHash];
        return record.complianceHash == _expectedComplianceHash;
    }
    
    /**
     * @dev Get compliance statistics
     * @return uint256 Total compliance records
     * @return uint256 Passed compliance records
     * @return uint256 Failed compliance records
     */
    function getComplianceStats() external view returns (uint256, uint256, uint256) {
        uint256 total = conversationHashes.length;
        uint256 passed = 0;
        uint256 failed = 0;
        
        for (uint256 i = 0; i < total; i++) {
            bytes32 convHash = conversationHashes[i];
            if (complianceRecords[convHash].passStatus) {
                passed++;
            } else {
                failed++;
            }
        }
        
        return (total, passed, failed);
    }
    
    /**
     * @dev Get compliance statistics for a policy check
     * @param _policyCheckId ID of the policy check
     * @return uint256 Total conversations for this policy check
     * @return uint256 Passed conversations for this policy check
     * @return uint256 Failed conversations for this policy check
     */
    function getPolicyCheckStats(bytes32 _policyCheckId) external view returns (uint256, uint256, uint256) {
        bytes32[] memory conversations = policyCheckToConversations[_policyCheckId];
        uint256 total = conversations.length;
        uint256 passed = 0;
        uint256 failed = 0;
        
        for (uint256 i = 0; i < total; i++) {
            bytes32 convHash = conversations[i];
            if (complianceRecords[convHash].passStatus) {
                passed++;
            } else {
                failed++;
            }
        }
        
        return (total, passed, failed);
    }
    
    /**
     * @dev Get total number of compliance records
     * @return uint256 Number of compliance records
     */
    function getComplianceCount() external view returns (uint256) {
        return conversationHashes.length;
    }
    
    /**
     * @dev Get total number of policy checks
     * @return uint256 Number of policy checks
     */
    function getPolicyCheckCount() external view returns (uint256) {
        return policyCheckIds.length;
    }
    
    /**
     * @dev Get conversation hash by index
     * @param _index Index in the conversation array
     * @return bytes32 Conversation hash
     */
    function getConversationHashByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < conversationHashes.length, "ComplianceRegistry: index out of bounds");
        return conversationHashes[_index];
    }
    
    /**
     * @dev Get policy check ID by index
     * @param _index Index in the policy check array
     * @return bytes32 Policy check ID
     */
    function getPolicyCheckIdByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < policyCheckIds.length, "ComplianceRegistry: index out of bounds");
        return policyCheckIds[_index];
    }
    
    /**
     * @dev Search compliance records by pass status
     * @param _passStatus Pass status to search for
     * @return bytes32[] Array of conversation hashes with the specified pass status
     */
    function searchByPassStatus(bool _passStatus) external view returns (bytes32[] memory) {
        bytes32[] memory matches = new bytes32[](conversationHashes.length);
        uint256 matchCount = 0;
        
        for (uint256 i = 0; i < conversationHashes.length; i++) {
            bytes32 convHash = conversationHashes[i];
            if (complianceRecords[convHash].passStatus == _passStatus) {
                matches[matchCount] = convHash;
                matchCount++;
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
     * @dev Get compliance records in a time range
     * @param _startTime Start timestamp
     * @param _endTime End timestamp
     * @return bytes32[] Array of conversation hashes in the time range
     */
    function getComplianceInTimeRange(uint256 _startTime, uint256 _endTime) external view returns (bytes32[] memory) {
        bytes32[] memory matches = new bytes32[](conversationHashes.length);
        uint256 matchCount = 0;
        
        for (uint256 i = 0; i < conversationHashes.length; i++) {
            bytes32 convHash = conversationHashes[i];
            uint256 timestamp = complianceRecords[convHash].timestamp;
            
            if (timestamp >= _startTime && timestamp <= _endTime) {
                matches[matchCount] = convHash;
                matchCount++;
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
     * @dev Get recent compliance records
     * @param _count Number of recent records to return
     * @return bytes32[] Array of recent conversation hashes
     */
    function getRecentCompliance(uint256 _count) external view returns (bytes32[] memory) {
        uint256 total = conversationHashes.length;
        uint256 count = _count > total ? total : _count;
        
        bytes32[] memory result = new bytes32[](count);
        
        for (uint256 i = 0; i < count; i++) {
            result[i] = conversationHashes[total - 1 - i];
        }
        
        return result;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "ComplianceRegistry: new owner is the zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
}
