// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title PolicyRegistry
 * @dev Smart contract for managing therapy policies, model configurations, and compliance records
 * @notice This contract stores policy hashes, model hashes, and compliance records on-chain
 */
contract PolicyRegistry {
    
    // Structs
    struct PolicyRecord {
        bytes32 policyId;
        string version;
        bytes32 policyHash;
        string documentType;
        uint256 timestamp;
        bool exists;
    }
    
    struct ModelRecord {
        bytes32 modelId;
        string version;
        bytes32 modelHash;
        string provider;
        uint256 timestamp;
        bool exists;
    }
    
    struct ComplianceRecord {
        bytes32 conversationHash;
        bytes32 modelHash;
        bytes32 policyHash;
        bool compliancePass;
        uint256 timestamp;
        bool exists;
    }
    
    // Mappings
    mapping(bytes32 => PolicyRecord) public policies;
    mapping(bytes32 => ModelRecord) public models;
    mapping(bytes32 => ComplianceRecord) public complianceRecords;
    
    // Arrays for enumeration
    bytes32[] public policyIds;
    bytes32[] public modelIds;
    bytes32[] public conversationHashes;
    
    // Owner
    address public owner;
    
    // Events
    event PolicyRegistered(
        bytes32 indexed policyId,
        string version,
        bytes32 policyHash,
        string documentType,
        uint256 timestamp
    );
    
    event ModelRegistered(
        bytes32 indexed modelId,
        string version,
        bytes32 modelHash,
        string provider,
        uint256 timestamp
    );
    
    event ComplianceRegistered(
        bytes32 indexed conversationHash,
        bytes32 modelHash,
        bytes32 policyHash,
        bool compliancePass,
        uint256 timestamp
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "PolicyRegistry: caller is not the owner");
        _;
    }
    
    modifier policyExists(bytes32 _policyId) {
        require(policies[_policyId].exists, "PolicyRegistry: policy does not exist");
        _;
    }
    
    modifier modelExists(bytes32 _modelId) {
        require(models[_modelId].exists, "PolicyRegistry: model does not exist");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Register a new policy document
     * @param _policyId Unique identifier for the policy
     * @param _version Policy version
     * @param _policyHash Hash of the policy content
     * @param _documentType Type of policy document
     */
    function registerPolicy(
        bytes32 _policyId,
        string memory _version,
        bytes32 _policyHash,
        string memory _documentType
    ) external onlyOwner {
        require(!policies[_policyId].exists, "PolicyRegistry: policy already exists");
        require(_policyHash != bytes32(0), "PolicyRegistry: policy hash cannot be zero");
        require(bytes(_version).length > 0, "PolicyRegistry: version cannot be empty");
        require(bytes(_documentType).length > 0, "PolicyRegistry: document type cannot be empty");
        
        policies[_policyId] = PolicyRecord({
            policyId: _policyId,
            version: _version,
            policyHash: _policyHash,
            documentType: _documentType,
            timestamp: block.timestamp,
            exists: true
        });
        
        policyIds.push(_policyId);
        
        emit PolicyRegistered(
            _policyId,
            _version,
            _policyHash,
            _documentType,
            block.timestamp
        );
    }
    
    /**
     * @dev Register a new model configuration
     * @param _modelId Unique identifier for the model
     * @param _version Model version
     * @param _modelHash Hash of the model configuration
     * @param _provider Model provider
     */
    function registerModel(
        bytes32 _modelId,
        string memory _version,
        bytes32 _modelHash,
        string memory _provider
    ) external onlyOwner {
        require(!models[_modelId].exists, "PolicyRegistry: model already exists");
        require(_modelHash != bytes32(0), "PolicyRegistry: model hash cannot be zero");
        require(bytes(_version).length > 0, "PolicyRegistry: version cannot be empty");
        require(bytes(_provider).length > 0, "PolicyRegistry: provider cannot be empty");
        
        models[_modelId] = ModelRecord({
            modelId: _modelId,
            version: _version,
            modelHash: _modelHash,
            provider: _provider,
            timestamp: block.timestamp,
            exists: true
        });
        
        modelIds.push(_modelId);
        
        emit ModelRegistered(
            _modelId,
            _version,
            _modelHash,
            _provider,
            block.timestamp
        );
    }
    
    /**
     * @dev Register a compliance record for a conversation
     * @param _conversationHash Hash of the conversation
     * @param _modelHash Hash of the model used
     * @param _policyHash Hash of the policies used
     * @param _compliancePass Whether compliance passed
     */
    function registerCompliance(
        bytes32 _conversationHash,
        bytes32 _modelHash,
        bytes32 _policyHash,
        bool _compliancePass
    ) external onlyOwner {
        require(_conversationHash != bytes32(0), "PolicyRegistry: conversation hash cannot be zero");
        require(!complianceRecords[_conversationHash].exists, "PolicyRegistry: compliance record already exists");
        
        complianceRecords[_conversationHash] = ComplianceRecord({
            conversationHash: _conversationHash,
            modelHash: _modelHash,
            policyHash: _policyHash,
            compliancePass: _compliancePass,
            timestamp: block.timestamp,
            exists: true
        });
        
        conversationHashes.push(_conversationHash);
        
        emit ComplianceRegistered(
            _conversationHash,
            _modelHash,
            _policyHash,
            _compliancePass,
            block.timestamp
        );
    }
    
    /**
     * @dev Get policy information
     * @param _policyId Policy ID
     * @return PolicyRecord Policy information
     */
    function getPolicy(bytes32 _policyId) external view policyExists(_policyId) returns (PolicyRecord memory) {
        return policies[_policyId];
    }
    
    /**
     * @dev Get model information
     * @param _modelId Model ID
     * @return ModelRecord Model information
     */
    function getModel(bytes32 _modelId) external view modelExists(_modelId) returns (ModelRecord memory) {
        return models[_modelId];
    }
    
    /**
     * @dev Get compliance record
     * @param _conversationHash Conversation hash
     * @return ComplianceRecord Compliance information
     */
    function getCompliance(bytes32 _conversationHash) external view returns (ComplianceRecord memory) {
        require(complianceRecords[_conversationHash].exists, "PolicyRegistry: compliance record does not exist");
        return complianceRecords[_conversationHash];
    }
    
    /**
     * @dev Check if policy exists
     * @param _policyId Policy ID
     * @return bool True if policy exists
     */
    function policyExists(bytes32 _policyId) external view returns (bool) {
        return policies[_policyId].exists;
    }
    
    /**
     * @dev Check if model exists
     * @param _modelId Model ID
     * @return bool True if model exists
     */
    function modelExists(bytes32 _modelId) external view returns (bool) {
        return models[_modelId].exists;
    }
    
    /**
     * @dev Check if compliance record exists
     * @param _conversationHash Conversation hash
     * @return bool True if compliance record exists
     */
    function complianceExists(bytes32 _conversationHash) external view returns (bool) {
        return complianceRecords[_conversationHash].exists;
    }
    
    /**
     * @dev Get total number of policies
     * @return uint256 Number of policies
     */
    function getPolicyCount() external view returns (uint256) {
        return policyIds.length;
    }
    
    /**
     * @dev Get total number of models
     * @return uint256 Number of models
     */
    function getModelCount() external view returns (uint256) {
        return modelIds.length;
    }
    
    /**
     * @dev Get total number of compliance records
     * @return uint256 Number of compliance records
     */
    function getComplianceCount() external view returns (uint256) {
        return conversationHashes.length;
    }
    
    /**
     * @dev Get policy ID by index
     * @param _index Index in the policy array
     * @return bytes32 Policy ID
     */
    function getPolicyIdByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < policyIds.length, "PolicyRegistry: index out of bounds");
        return policyIds[_index];
    }
    
    /**
     * @dev Get model ID by index
     * @param _index Index in the model array
     * @return bytes32 Model ID
     */
    function getModelIdByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < modelIds.length, "PolicyRegistry: index out of bounds");
        return modelIds[_index];
    }
    
    /**
     * @dev Get conversation hash by index
     * @param _index Index in the conversation array
     * @return bytes32 Conversation hash
     */
    function getConversationHashByIndex(uint256 _index) external view returns (bytes32) {
        require(_index < conversationHashes.length, "PolicyRegistry: index out of bounds");
        return conversationHashes[_index];
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
            if (complianceRecords[convHash].compliancePass) {
                passed++;
            } else {
                failed++;
            }
        }
        
        return (total, passed, failed);
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "PolicyRegistry: new owner is the zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
    
    /**
     * @dev Get latest policy hash for a document type
     * @param _documentType Document type to search for
     * @return bytes32 Latest policy hash
     * @return uint256 Timestamp of the latest policy
     */
    function getLatestPolicyHash(string memory _documentType) external view returns (bytes32, uint256) {
        bytes32 latestHash = bytes32(0);
        uint256 latestTimestamp = 0;
        
        for (uint256 i = 0; i < policyIds.length; i++) {
            bytes32 policyId = policyIds[i];
            PolicyRecord memory policy = policies[policyId];
            
            if (keccak256(abi.encodePacked(policy.documentType)) == keccak256(abi.encodePacked(_documentType))) {
                if (policy.timestamp > latestTimestamp) {
                    latestTimestamp = policy.timestamp;
                    latestHash = policy.policyHash;
                }
            }
        }
        
        return (latestHash, latestTimestamp);
    }
    
    /**
     * @dev Get latest model hash for a provider
     * @param _provider Provider to search for
     * @return bytes32 Latest model hash
     * @return uint256 Timestamp of the latest model
     */
    function getLatestModelHash(string memory _provider) external view returns (bytes32, uint256) {
        bytes32 latestHash = bytes32(0);
        uint256 latestTimestamp = 0;
        
        for (uint256 i = 0; i < modelIds.length; i++) {
            bytes32 modelId = modelIds[i];
            ModelRecord memory model = models[modelId];
            
            if (keccak256(abi.encodePacked(model.provider)) == keccak256(abi.encodePacked(_provider))) {
                if (model.timestamp > latestTimestamp) {
                    latestTimestamp = model.timestamp;
                    latestHash = model.modelHash;
                }
            }
        }
        
        return (latestHash, latestTimestamp);
    }
}
