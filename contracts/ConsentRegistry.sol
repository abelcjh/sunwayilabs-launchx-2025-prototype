// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title ConsentRegistry
 * @dev Smart contract for managing user consent for data processing
 * @notice This contract stores consent hashes and manages consent lifecycle
 */
contract ConsentRegistry {
    
    // Struct to store consent information
    struct Consent {
        string subjectDid;        // Decentralized Identifier of the subject (user)
        string controllerDid;     // Decentralized Identifier of the controller (service)
        string consentHash;       // Hash of the consent document (Verifiable Credential)
        uint256 expiresAt;        // Unix timestamp when consent expires
        bool isActive;            // Whether consent is currently active
        bool exists;              // Whether this consent ID exists
    }
    
    // Mapping from consent ID to consent data
    mapping(bytes32 => Consent) public consents;
    
    // Mapping to track consent IDs by subject DID for easy lookup
    mapping(string => bytes32[]) public subjectConsents;
    
    // Mapping to track consent IDs by controller DID for easy lookup
    mapping(string => bytes32[]) public controllerConsents;
    
    // Owner of the contract (can be a multisig or DAO in production)
    address public owner;
    
    // Events
    event ConsentSet(
        bytes32 indexed consentId,
        string indexed subjectDid,
        string indexed controllerDid,
        string consentHash,
        uint256 expiresAt
    );
    
    event ConsentRevoked(
        bytes32 indexed consentId,
        string indexed subjectDid,
        string indexed controllerDid,
        uint256 revokedAt
    );
    
    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "ConsentRegistry: caller is not the owner");
        _;
    }
    
    modifier consentExists(bytes32 _consentId) {
        require(consents[_consentId].exists, "ConsentRegistry: consent does not exist");
        _;
    }
    
    // Constructor
    constructor() {
        owner = msg.sender;
    }
    
    /**
     * @dev Set or update consent for a subject
     * @param _consentId Unique identifier for the consent
     * @param _subjectDid Decentralized Identifier of the subject
     * @param _controllerDid Decentralized Identifier of the controller
     * @param _consentHash Hash of the consent document (Verifiable Credential)
     * @param _expiresAt Unix timestamp when consent expires
     */
    function setConsent(
        bytes32 _consentId,
        string memory _subjectDid,
        string memory _controllerDid,
        string memory _consentHash,
        uint256 _expiresAt
    ) external {
        require(_expiresAt > block.timestamp, "ConsentRegistry: expiration must be in the future");
        require(bytes(_subjectDid).length > 0, "ConsentRegistry: subject DID cannot be empty");
        require(bytes(_controllerDid).length > 0, "ConsentRegistry: controller DID cannot be empty");
        require(bytes(_consentHash).length > 0, "ConsentRegistry: consent hash cannot be empty");
        
        // If this is a new consent, add to subject and controller mappings
        if (!consents[_consentId].exists) {
            subjectConsents[_subjectDid].push(_consentId);
            controllerConsents[_controllerDid].push(_consentId);
        }
        
        // Update or create consent
        consents[_consentId] = Consent({
            subjectDid: _subjectDid,
            controllerDid: _controllerDid,
            consentHash: _consentHash,
            expiresAt: _expiresAt,
            isActive: true,
            exists: true
        });
        
        emit ConsentSet(
            _consentId,
            _subjectDid,
            _controllerDid,
            _consentHash,
            _expiresAt
        );
    }
    
    /**
     * @dev Revoke consent by setting it as inactive
     * @param _consentId Unique identifier for the consent to revoke
     */
    function revokeConsent(bytes32 _consentId) external consentExists(_consentId) {
        Consent storage consent = consents[_consentId];
        
        // Only allow revocation by the subject or controller
        require(
            keccak256(abi.encodePacked(consent.subjectDid)) == keccak256(abi.encodePacked(_getCallerDid())) ||
            keccak256(abi.encodePacked(consent.controllerDid)) == keccak256(abi.encodePacked(_getCallerDid())) ||
            msg.sender == owner,
            "ConsentRegistry: only subject, controller, or owner can revoke consent"
        );
        
        consent.isActive = false;
        
        emit ConsentRevoked(
            _consentId,
            consent.subjectDid,
            consent.controllerDid,
            block.timestamp
        );
    }
    
    /**
     * @dev Check if consent is currently active (not revoked and not expired)
     * @param _consentId Unique identifier for the consent
     * @return bool True if consent is active, false otherwise
     */
    function isActive(bytes32 _consentId) external view returns (bool) {
        if (!consents[_consentId].exists) {
            return false;
        }
        
        Consent memory consent = consents[_consentId];
        return consent.isActive && consent.expiresAt > block.timestamp;
    }
    
    /**
     * @dev Get full consent information
     * @param _consentId Unique identifier for the consent
     * @return Consent struct with all consent data
     */
    function getConsent(bytes32 _consentId) external view consentExists(_consentId) returns (Consent memory) {
        return consents[_consentId];
    }
    
    /**
     * @dev Get all consent IDs for a subject
     * @param _subjectDid Decentralized Identifier of the subject
     * @return bytes32[] Array of consent IDs
     */
    function getSubjectConsents(string memory _subjectDid) external view returns (bytes32[] memory) {
        return subjectConsents[_subjectDid];
    }
    
    /**
     * @dev Get all consent IDs for a controller
     * @param _controllerDid Decentralized Identifier of the controller
     * @return bytes32[] Array of consent IDs
     */
    function getControllerConsents(string memory _controllerDid) external view returns (bytes32[] memory) {
        return controllerConsents[_controllerDid];
    }
    
    /**
     * @dev Check if consent exists
     * @param _consentId Unique identifier for the consent
     * @return bool True if consent exists, false otherwise
     */
    function consentExists(bytes32 _consentId) external view returns (bool) {
        return consents[_consentId].exists;
    }
    
    /**
     * @dev Get consent expiration timestamp
     * @param _consentId Unique identifier for the consent
     * @return uint256 Unix timestamp when consent expires
     */
    function getConsentExpiration(bytes32 _consentId) external view consentExists(_consentId) returns (uint256) {
        return consents[_consentId].expiresAt;
    }
    
    /**
     * @dev Transfer ownership of the contract
     * @param _newOwner Address of the new owner
     */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "ConsentRegistry: new owner is the zero address");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
    
    /**
     * @dev Internal function to get caller's DID (simplified for demo)
     * @notice In production, this would integrate with DID resolution
     * @return string The caller's DID
     */
    function _getCallerDid() internal view returns (string memory) {
        // Simplified implementation - in production, this would resolve the caller's DID
        // from their wallet address using a DID registry
        return string(abi.encodePacked("did:ethr:", _toAsciiString(msg.sender)));
    }
    
    /**
     * @dev Convert address to ASCII string
     * @param x Address to convert
     * @return string ASCII representation of the address
     */
    function _toAsciiString(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(40);
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2*i] = char(hi);
            s[2*i+1] = char(lo);
        }
        return string(s);
    }
    
    /**
     * @dev Convert byte to ASCII character
     * @param b Byte to convert
     * @return bytes1 ASCII character
     */
    function char(bytes1 b) internal pure returns (bytes1) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }
}
