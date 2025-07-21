// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ValidatorFactory.sol";

/**
 * @title TransactionManager
 * @dev Optimistic consensus system with LLM validation and validator signatures
 * Features:
 * - Transaction proposal with optimistic execution
 * - Mock LLM validation (deterministic hash-based)
 * - ECDSA signature verification with 3/5 consensus
 * - Challenge period for disputes
 */
contract TransactionManager {
    // Events
    event ProposalSubmitted(bytes32 indexed proposalId, string transaction, address indexed submitter);
    event ProposalOptimisticallyApproved(bytes32 indexed proposalId);
    event ProposalChallenged(bytes32 indexed proposalId, address indexed challenger);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event ValidatorSigned(bytes32 indexed proposalId, address indexed validator);
    event LLMValidationResult(bytes32 indexed proposalId, bool isValid);

    // State variables
    ValidatorFactory public validatorFactory;
    
    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    mapping(bytes32 => address[]) public proposalSigners;
    uint256 public proposalCount;
    
    // Constants
    uint256 public constant CHALLENGE_PERIOD = 50; // blocks
    uint256 public constant REQUIRED_SIGNATURES = 3; // 3 out of 5 validators
    uint256 public constant VALIDATOR_SET_SIZE = 5; // top 5 validators for consensus

    // Proposal states
    enum ProposalState {
        Proposed,           // Just submitted
        OptimisticApproved, // Enough signatures, optimistically approved
        Challenged,         // Someone challenged the proposal
        Finalized,          // Final decision made
        Reverted           // Proposal was invalid/rejected
    }

    // Structs
    struct Proposal {
        bytes32 proposalId;
        string transaction;
        address proposer;
        uint256 blockNumber;
        uint256 challengeDeadline;
        ProposalState state;
        address challenger;
        uint256 signatureCount;
        bool llmValidation;
        bool executed;
        address[] selectedValidators; // validators selected for this proposal
    }

    constructor(address _validatorFactory) {
        validatorFactory = ValidatorFactory(_validatorFactory);
    }

    /**
     * @dev Submit a proposal for consensus
     * @param transaction Transaction string to be validated (e.g., "Approve loan for user X based on LLM analysis")
     * @return proposalId Unique identifier for the proposal
     */
    function submitProposal(string calldata transaction) external returns (bytes32 proposalId) {
        require(bytes(transaction).length > 0, "Empty transaction");
        
        proposalId = keccak256(abi.encodePacked(transaction, block.timestamp, msg.sender));
        require(proposals[proposalId].proposalId == bytes32(0), "Proposal already exists");

        // Get top validators for this proposal
        address[] memory topValidators = _getTopValidators();
        require(topValidators.length >= REQUIRED_SIGNATURES, "Not enough validators");

        // Perform mock LLM validation
        bool llmResult = _mockLLMValidation(transaction);

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            transaction: transaction,
            proposer: msg.sender,
            blockNumber: block.number,
            state: ProposalState.Proposed,
            challengeDeadline: block.number + CHALLENGE_PERIOD,
            challenger: address(0),
            signatureCount: 0,
            llmValidation: llmResult,
            executed: false,
            selectedValidators: topValidators
        });

        proposalCount++;

        emit ProposalSubmitted(proposalId, transaction, msg.sender);
        emit LLMValidationResult(proposalId, llmResult);

        return proposalId;
    }

    /**
     * @dev Validators sign a proposal using ECDSA signatures
     * @param proposalId Proposal identifier
     * @param signature ECDSA signature of the proposal hash
     */
    function signProposal(bytes32 proposalId, bytes calldata signature) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.proposalId != bytes32(0), "Proposal not found");
        require(proposal.state == ProposalState.Proposed, "Invalid proposal state");
        require(block.number <= proposal.challengeDeadline, "Challenge period expired");
        require(!hasValidatorSigned[proposalId][msg.sender], "Already signed");
        
        // Verify that sender is one of the selected validators for this proposal
        require(_isSelectedValidator(proposalId, msg.sender), "Not a selected validator");
        
        // Verify the signature
        bytes32 messageHash = _getProposalHash(proposalId, proposal.transaction);
        address recoveredSigner = _recoverSigner(messageHash, signature);
        require(recoveredSigner == msg.sender, "Invalid signature");

        // Record the signature
        hasValidatorSigned[proposalId][msg.sender] = true;
        proposalSigners[proposalId].push(msg.sender);
        proposal.signatureCount++;

        emit ValidatorSigned(proposalId, msg.sender);

        // Check if we have enough signatures for optimistic approval
        if (proposal.signatureCount >= REQUIRED_SIGNATURES && proposal.llmValidation) {
            proposal.state = ProposalState.OptimisticApproved;
            proposal.executed = true;
            emit ProposalOptimisticallyApproved(proposalId);
        }
    }

    /**
     * @dev Challenge a proposal during the challenge period
     * @param proposalId Proposal identifier
     */
    function challengeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.proposalId != bytes32(0), "Proposal not found");
        require(proposal.state == ProposalState.OptimisticApproved, "Cannot challenge");
        require(block.number <= proposal.challengeDeadline, "Challenge period expired");
        require(validatorFactory.isActiveValidator(msg.sender), "Not a validator");

        proposal.state = ProposalState.Challenged;
        proposal.challenger = msg.sender;
        proposal.executed = false; // Revert optimistic execution

        emit ProposalChallenged(proposalId, msg.sender);
    }

    /**
     * @dev Finalize a proposal after challenge period or after challenge resolution
     * @param proposalId Proposal identifier
     */
    function finalizeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        require(proposal.proposalId != bytes32(0), "Proposal not found");
        require(block.number > proposal.challengeDeadline, "Challenge period not ended");
        
        bool approved = false;

        if (proposal.state == ProposalState.OptimisticApproved) {
            // No challenge during period - approve
            approved = true;
            proposal.executed = true;
        } else if (proposal.state == ProposalState.Challenged) {
            // Resolve challenge based on signatures and LLM validation
            approved = proposal.signatureCount >= REQUIRED_SIGNATURES && proposal.llmValidation;
            proposal.executed = approved;
        }

        proposal.state = approved ? ProposalState.Finalized : ProposalState.Reverted;

        emit ProposalFinalized(proposalId, approved);
    }

    /**
     * @dev Mock LLM validation using deterministic function
     * @param transaction Transaction string to validate
     * @return isValid Whether the transaction is valid (based on hash even/odd)
     */
    function _mockLLMValidation(string memory transaction) internal pure returns (bool isValid) {
        bytes32 hash = keccak256(abi.encodePacked(transaction));
        // Return true if hash is even (last bit is 0)
        return (uint256(hash) % 2 == 0);
    }

    /**
     * @dev Get top validators for consensus
     * @return validators Array of top validator addresses
     */
    function _getTopValidators() internal view returns (address[] memory) {
        uint256 validatorCount = validatorFactory.getValidatorCount();
        if (validatorCount == 0) {
            return new address[](0);
        }
        
        uint256 count = validatorCount < VALIDATOR_SET_SIZE ? validatorCount : VALIDATOR_SET_SIZE;
        (address[] memory topValidators,) = validatorFactory.getTopNValidators(count);
        return topValidators;
    }

    /**
     * @dev Check if address is a selected validator for the proposal
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return isSelected Whether the validator was selected for this proposal
     */
    function _isSelectedValidator(bytes32 proposalId, address validator) internal view returns (bool isSelected) {
        address[] memory selectedValidators = proposals[proposalId].selectedValidators;
        for (uint256 i = 0; i < selectedValidators.length; i++) {
            if (selectedValidators[i] == validator) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Create proposal hash for signature verification
     * @param proposalId Proposal identifier
     * @param transaction Transaction string
     * @return hash Message hash for signing
     */
    function _getProposalHash(bytes32 proposalId, string memory transaction) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encodePacked(proposalId, transaction))
        ));
    }

    /**
     * @dev Recover signer from signature
     * @param messageHash Message hash
     * @param signature ECDSA signature
     * @return signer Recovered signer address
     */
    function _recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        require(signature.length == 65, "Invalid signature length");
        
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature v value");
        
        return ecrecover(messageHash, v, r, s);
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @dev Get proposal information
     * @param proposalId Proposal identifier
     * @return transaction Transaction string
     * @return proposer Proposal submitter
     * @return blockNumber Block number when submitted
     * @return state Current proposal state
     * @return challengeDeadline Challenge deadline
     * @return challenger Address of challenger
     * @return signatureCount Number of validator signatures
     * @return llmValidation LLM validation result
     * @return executed Whether proposal was executed
     */
    function getProposal(bytes32 proposalId) external view returns (
        string memory transaction,
        address proposer,
        uint256 blockNumber,
        ProposalState state,
        uint256 challengeDeadline,
        address challenger,
        uint256 signatureCount,
        bool llmValidation,
        bool executed
    ) {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.transaction,
            proposal.proposer,
            proposal.blockNumber,
            proposal.state,
            proposal.challengeDeadline,
            proposal.challenger,
            proposal.signatureCount,
            proposal.llmValidation,
            proposal.executed
        );
    }

    /**
     * @dev Get selected validators for a proposal
     * @param proposalId Proposal identifier
     * @return validators Array of selected validator addresses
     */
    function getProposalValidators(bytes32 proposalId) external view returns (address[] memory) {
        return proposals[proposalId].selectedValidators;
    }

    /**
     * @dev Get signers for a proposal
     * @param proposalId Proposal identifier
     * @return signers Array of addresses that signed the proposal
     */
    function getProposalSigners(bytes32 proposalId) external view returns (address[] memory) {
        return proposalSigners[proposalId];
    }

    /**
     * @dev Check if proposal is approved and executed
     * @param proposalId Proposal identifier
     * @return approved Whether the proposal is approved and executed
     */
    function isProposalApproved(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.state == ProposalState.OptimisticApproved || 
               (proposal.state == ProposalState.Finalized && proposal.executed);
    }

    /**
     * @dev Test the mock LLM validation function
     * @param transaction Transaction string to test
     * @return isValid Result of mock LLM validation
     */
    function testLLMValidation(string calldata transaction) external pure returns (bool) {
        return _mockLLMValidation(transaction);
    }

    /**
     * @dev Get current validator count
     * @return count Number of active validators
     */
    function getValidatorCount() external view returns (uint256) {
        return validatorFactory.getValidatorCount();
    }

    /**
     * @dev Get top validators currently selected for consensus
     * @return validators Array of top validator addresses
     */
    function getCurrentTopValidators() external view returns (address[] memory) {
        return _getTopValidators();
    }
} 