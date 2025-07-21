// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ValidatorFactory.sol";
import "./interfaces/ILLMOracle.sol";
import "./interfaces/IConsensusProvider.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title TransactionManagerV2
 * @dev Simplified TransactionManager that delegates consensus to ConsensusManager
 * @notice This version is completely decoupled from voting/challenge logic
 */
contract TransactionManagerV2 is ReentrancyGuard {
    event ProposalSubmitted(bytes32 indexed proposalId, string transaction, address indexed submitter);
    event ProposalOptimisticallyApproved(bytes32 indexed proposalId);
    event ValidatorSigned(bytes32 indexed proposalId, address indexed validator);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event LLMValidationResult(bytes32 indexed proposalId, bool isValid);

    // Custom errors
    error InvalidValidatorFactory();
    error InvalidLLMOracle();
    error InvalidConsensusProvider();
    error EmptyTransaction();
    error ProposalAlreadyExists();
    error ProposalNotFound();
    error InvalidProposalState();
    error ChallengePeriodExpired();
    error NotEnoughValidators();
    error NotASelectedValidator();
    error AlreadySigned();
    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidSignatureV();

    enum ProposalState {
        Proposed,           // Just submitted, awaiting LLM validation
        OptimisticApproved, // LLM approved, in challenge period, collecting signatures
        Challenged,         // Challenge initiated, consensus in progress
        Finalized,          // Approved and executed with validator signatures
        Rejected            // Rejected by LLM or consensus voting
    }

    // Simplified proposal structure - consensus data moved to ConsensusManager
    struct Proposal {
        bytes32 proposalId;
        string transaction;
        address proposer;
        uint256 blockNumber;
        ProposalState state;
        uint8 signatureCount;          // Number of validator signatures (max 5)
        address[] selectedValidators;  // Validators selected for this proposal
    }

    ValidatorFactory public immutable validatorFactory;
    ILLMOracle public immutable llmOracle;
    IConsensusProvider public immutable consensusProvider;

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    mapping(bytes32 => address[]) public proposalSigners;
    uint256 public proposalCount;

    uint256 public constant CHALLENGE_PERIOD = 10; // blocks for challenge period
    uint256 public constant REQUIRED_SIGNATURES = 3; // 3 out of 5 validators
    uint256 public constant VALIDATOR_SET_SIZE = 5; // top 5 validators for consensus

    constructor(address _validatorFactory, address _llmOracle, address _consensusProvider) {
        if (_validatorFactory == address(0)) revert InvalidValidatorFactory();
        if (_llmOracle == address(0)) revert InvalidLLMOracle();
        if (_consensusProvider == address(0)) revert InvalidConsensusProvider();

        validatorFactory = ValidatorFactory(_validatorFactory);
        llmOracle = ILLMOracle(_llmOracle);
        consensusProvider = IConsensusProvider(_consensusProvider);
    }

    /**
     * @dev Submit a proposal for consensus
     * @param transaction Transaction string to be validated
     * @return proposalId Unique identifier for the proposal
     */
    function submitProposal(string calldata transaction) external nonReentrant returns (bytes32 proposalId) {
        if (bytes(transaction).length == 0) revert EmptyTransaction();

        proposalId = keccak256(abi.encodePacked(transaction, block.timestamp, msg.sender));
        if (proposals[proposalId].proposalId != bytes32(0)) revert ProposalAlreadyExists();

        // Get top validators for this proposal  
        address[] memory topValidators = _getTopValidators();
        if (topValidators.length < REQUIRED_SIGNATURES) revert NotEnoughValidators();

        // Perform LLM validation immediately
        bool llmResult = llmOracle.validateTransaction(transaction);
        
        // Create proposal with state based on LLM result
        ProposalState initialState = llmResult ? ProposalState.OptimisticApproved : ProposalState.Rejected;

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            transaction: transaction,
            proposer: msg.sender,
            blockNumber: block.number,
            state: initialState,
            signatureCount: 0,
            selectedValidators: topValidators
        });

        proposalCount++;

        // If LLM approved, initialize consensus process
        if (llmResult) {
            consensusProvider.initializeConsensus(proposalId, topValidators, CHALLENGE_PERIOD);
            emit ProposalOptimisticallyApproved(proposalId);
        }

        emit ProposalSubmitted(proposalId, transaction, msg.sender);
        emit LLMValidationResult(proposalId, llmResult);

        return proposalId;
    }

    /**
     * @dev Validators sign a proposal using ECDSA signatures to finalize it
     * @param proposalId Proposal identifier
     * @param signature ECDSA signature of the proposal hash
     */
    function signProposal(bytes32 proposalId, bytes calldata signature) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.OptimisticApproved) revert InvalidProposalState();
        
        // Check if still in challenge period
        if (!consensusProvider.canChallengeProposal(proposalId)) revert ChallengePeriodExpired();
        if (hasValidatorSigned[proposalId][msg.sender]) revert AlreadySigned();

        // Verify that sender is one of the selected validators for this proposal
        if (!_isSelectedValidator(proposalId, msg.sender)) revert NotASelectedValidator();

        // Verify the signature
        bytes32 messageHash = _getProposalHash(proposalId, proposal.transaction);
        address recoveredSigner = _recoverSigner(messageHash, signature);
        if (recoveredSigner != msg.sender) revert InvalidSignature();

        // Record the signature
        hasValidatorSigned[proposalId][msg.sender] = true;
        proposalSigners[proposalId].push(msg.sender);
        proposal.signatureCount++;

        emit ValidatorSigned(proposalId, msg.sender);

        // Check if we have enough signatures for finalization
        if (proposal.signatureCount >= REQUIRED_SIGNATURES) {
            proposal.state = ProposalState.Finalized;
            emit ProposalFinalized(proposalId, true);
        }
    }

    /**
     * @dev Challenge a proposal during the challenge period (delegates to consensus provider)
     * @param proposalId Proposal identifier
     */
    function challengeProposal(bytes32 proposalId) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.OptimisticApproved) revert InvalidProposalState();

        // Delegate to consensus provider
        consensusProvider.challengeProposal(proposalId, msg.sender);
        
        // Update local state
        proposal.state = ProposalState.Challenged;
    }

    /**
     * @dev Submit a vote on a challenged proposal (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @param support true for yes (approve), false for no (reject)
     * @param signature ECDSA signature of the vote
     */
    function submitVote(bytes32 proposalId, bool support, bytes calldata signature) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Challenged) revert InvalidProposalState();

        // Delegate to consensus provider
        consensusProvider.submitVote(proposalId, msg.sender, support, signature);
    }

    /**
     * @dev Resolve consensus after voting period (delegates to consensus provider)
     * @param proposalId Proposal identifier
     */
    function resolveChallenge(bytes32 proposalId) external nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Challenged) revert InvalidProposalState();

        // Delegate to consensus provider
        bool approved = consensusProvider.resolveConsensus(proposalId);
        
        // Update local state based on consensus result
        proposal.state = approved ? ProposalState.Finalized : ProposalState.Rejected;
        
        emit ProposalFinalized(proposalId, approved);
    }

    // ==================== INTERNAL FUNCTIONS ====================

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
        (address[] memory topValidators, ) = validatorFactory.getTopNValidators(count);
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
        return keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(proposalId, transaction))
            )
        );
    }

    /**
     * @dev Recover signer from signature
     * @param messageHash Message hash
     * @param signature ECDSA signature
     * @return signer Recovered signer address
     */
    function _recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSignatureLength();

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

        if (v != 27 && v != 28) revert InvalidSignatureV();

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
     * @return signatureCount Number of validator signatures
     * @return selectedValidators Validators selected for this proposal
     */
    function getProposal(bytes32 proposalId)
        external
        view
        returns (
            string memory transaction,
            address proposer,
            uint256 blockNumber,
            ProposalState state,
            uint256 signatureCount,
            address[] memory selectedValidators
        )
    {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.transaction,
            proposal.proposer,
            proposal.blockNumber,
            proposal.state,
            proposal.signatureCount,
            proposal.selectedValidators
        );
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
        return proposals[proposalId].state == ProposalState.Finalized;
    }

    /**
     * @dev Test LLM validation using the external oracle
     * @param transaction Transaction string to test
     * @return isValid Result of LLM validation from the oracle
     */
    function testLLMValidation(string calldata transaction) external view returns (bool) {
        return llmOracle.validateTransaction(transaction);
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

    // ==================== CONSENSUS PROVIDER DELEGATION ====================

    /**
     * @dev Check if a proposal can be challenged (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @return canChallenge Whether challenge is possible
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        return consensusProvider.canChallengeProposal(proposalId);
    }

    /**
     * @dev Check if a proposal is in voting period (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @return inVoting Whether the proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        return consensusProvider.isInVotingPeriod(proposalId);
    }

    /**
     * @dev Get consensus state (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @return state Current consensus state
     * @return deadline Current deadline
     * @return yesVotes Number of yes votes
     * @return noVotes Number of no votes
     */
    function getConsensusState(bytes32 proposalId)
        external
        view
        returns (
            IConsensusProvider.ConsensusState state,
            uint256 deadline,
            uint256 yesVotes,
            uint256 noVotes
        )
    {
        return consensusProvider.getConsensusState(proposalId);
    }

    /**
     * @dev Get challenge information (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @return challenger Address that initiated challenge
     * @return challengeBlock Block when challenge was initiated
     */
    function getChallengeInfo(bytes32 proposalId)
        external
        view
        returns (address challenger, uint256 challengeBlock)
    {
        return consensusProvider.getChallengeInfo(proposalId);
    }

    /**
     * @dev Get voters for a proposal (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @return voters Array of addresses that voted
     */
    function getProposalVoters(bytes32 proposalId) external view returns (address[] memory) {
        return consensusProvider.getVoters(proposalId);
    }

    /**
     * @dev Get individual validator's vote (delegates to consensus provider)
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return hasVoted Whether validator has voted
     * @return support Vote direction
     */
    function getValidatorVote(bytes32 proposalId, address validator)
        external
        view
        returns (bool hasVoted, bool support)
    {
        return consensusProvider.getValidatorVote(proposalId, validator);
    }

    /**
     * @dev Get the LLM Oracle address
     * @return oracle Address of the LLM Oracle contract
     */
    function getLLMOracle() external view returns (address) {
        return address(llmOracle);
    }

    /**
     * @dev Get the Consensus Provider address
     * @return provider Address of the Consensus Provider contract
     */
    function getConsensusProvider() external view returns (address) {
        return address(consensusProvider);
    }
} 