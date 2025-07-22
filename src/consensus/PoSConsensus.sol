// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../interfaces/IConsensus.sol";
import "../interfaces/ITransactionManager.sol";
import "./DisputeManager.sol";
import "../staking/StakingManager.sol";

/**
 * @title PoSConsensus
 * @dev Proof of Stake consensus mechanism implementation
 * @notice Implements consensus logic with validator selection, signature collection,
 *         and dispute resolution for transaction approval
 */
contract PoSConsensus is IConsensus, ReentrancyGuard {
    // ==================== EVENTS ====================

    /**
     * @dev Emitted when a proposal is initialized
     * @param proposalId The unique identifier of the proposal
     * @param proposer The address that submitted the proposal
     */
    event ProposalInitialized(bytes32 indexed proposalId, address indexed proposer);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event ChallengeInitiated(bytes32 indexed proposalId, address indexed challenger);
    event ValidatorsAssigned(bytes32 indexed proposalId, address[] validators);
    event SignatureReceived(bytes32 indexed proposalId, address indexed validator, uint8 totalSignatures);
    event ConsensusReached(bytes32 indexed proposalId, address[] signers);
    event DisputeResolved(bytes32 indexed proposalId, bool upheld, address challenger, uint256 slashAmount);
    event ProposalStateUpdatedByConsensus(bytes32 indexed proposalId, IConsensus.ProposalStatus status);

    // ==================== ERRORS ====================
    error InvalidStakingToken();
    error InvalidMinimumStake();
    error InvalidMaxValidators();
    error InvalidValidatorThreshold();
    error InvalidChallengePeriod();
    error InvalidRequiredSignatures();
    error InvalidValidatorSetSize();
    error InvalidVotingPeriod();
    error InvalidSlashPercentage();
    error ProposalNotFound();
    error ProposalAlreadyExists();
    error InvalidProposalState();
    error NotEnoughValidators();
    error NotASelectedValidator();
    error NotAValidator();
    error AlreadySigned();
    error InvalidSignature();
    error InvalidSignatureLength();
    error NotEnoughSignatures();
    error DisputeActive();
    error OnlyAssociatedDispute();
    error DisputeResolutionFailed();
    error MismatchedValidatorData();

    // ==================== STRUCTS ====================
    struct PoSData {
        uint8 signatureCount; // 1 byte - Number of validator signatures collected (max 255)
        bool initialized; // 1 byte - Whether this proposal has been initialized in PoS
        address transactionManager; // 20 bytes - Transaction manager that initialized this proposal
        address[] validators; // 32 bytes - Validators that chosen for the proposal
    }

    // ==================== STATE VARIABLES ====================

    StakingManager public immutable stakingManager;
    DisputeManager public immutable disputeManager;

    /// @dev Duration in blocks for challenge period after consensus
    uint256 public immutable CHALLENGE_PERIOD;
    /// @dev Percentage to slash validators (10%)
    uint256 public immutable SLASH_PERCENTAGE;
    /// @dev Number of validators required to reach consensus
    uint256 public immutable CONSENSUS_THRESHOLD;
    /// @dev Number of validators required to reach consensus
    uint256 public immutable VALIDATOR_SET_SIZE;

    /// @dev Mapping of proposal IDs to their PoS consensus data
    mapping(bytes32 => PoSData) public posData;
    /// @dev Mapping to track which validators have signed each proposal
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    /// @dev Mapping of proposal IDs to arrays of signers
    mapping(bytes32 => address[]) public proposalSigners;

    // ==================== MODIFIERS ====================

    modifier onlyAssociatedDisputeManager() {
        if (msg.sender != address(disputeManager)) {
            revert OnlyAssociatedDispute();
        }
        _;
    }

    // ==================== CONSTRUCTOR ====================

    constructor(
        address _stakingToken,
        uint256 _minimumStake,
        uint16 _maxValidators,
        uint16 _validatorThreshold,
        uint256 _challengePeriod,
        uint8 _requiredSignatures,
        uint8 _validatorSetSize,
        uint256 _votingPeriod,
        uint8 _slashPercentage
    ) {
        if (_stakingToken == address(0)) revert InvalidStakingToken();
        if (_minimumStake == 0) revert InvalidMinimumStake();
        if (_maxValidators == 0) revert InvalidMaxValidators();
        if (_validatorThreshold == 0) revert InvalidValidatorThreshold();
        if (_challengePeriod == 0) revert InvalidChallengePeriod();
        if (_requiredSignatures == 0) revert InvalidRequiredSignatures();
        if (_validatorSetSize == 0) revert InvalidValidatorSetSize();
        if (_votingPeriod == 0) revert InvalidVotingPeriod();
        if (_slashPercentage > 100) revert InvalidSlashPercentage();

        // Set immutable configuration
        CHALLENGE_PERIOD = _challengePeriod;
        CONSENSUS_THRESHOLD = _requiredSignatures;
        VALIDATOR_SET_SIZE = _validatorSetSize;
        SLASH_PERCENTAGE = _slashPercentage;

        // Deploy StakingManager
        stakingManager = new StakingManager(_stakingToken, _minimumStake, _maxValidators, _validatorThreshold);

        // Deploy DisputeManager (slashing handled by PoS, not DisputeManager)
        disputeManager = new DisputeManager(address(stakingManager), address(this), _votingPeriod);
    }

    // ==================== ICONSENSUS IMPLEMENTATION ====================

    /**
     * @dev Initialize consensus for a new proposal
     */
    function initializeConsensus(bytes32 proposalId, string calldata transaction, address proposer)
        external
        nonReentrant
    {
        if (posData[proposalId].initialized) revert ProposalAlreadyExists();

        // Get top validators for this proposal
        address[] memory topValidators = _getTopValidators();
        if (topValidators.length < CONSENSUS_THRESHOLD) revert NotEnoughValidators();

        // Initialize PoS data, assign validators to the proposal
        posData[proposalId] =
            PoSData({signatureCount: 0, initialized: true, transactionManager: msg.sender, validators: topValidators});

        emit ProposalInitialized(proposalId, proposer);
        emit ValidatorsAssigned(proposalId, topValidators);
    }

    /**
     * @dev Finalize a consensus and return the result
     * Can finalize if:
     * 1. Has enough signatures, OR
     * 2. Dispute was resolved
     * Anyone can finalize a proposal if it has enough signatures or if the dispute is resolved but has not been finalized
     */
    function finalizeConsensus(bytes32 proposalId) external nonReentrant {
        _finalizeProposal(proposalId);
    }

    // ==================== CHALLENGE/DISPUTE FUNCTIONS ====================
    /**
     * @dev Submit a challenge against a proposal
     */
    function challengeProposal(bytes32 proposalId) external nonReentrant {
        if (!posData[proposalId].initialized) revert ProposalNotFound();
        if (!_isSelectedValidator(proposalId, msg.sender)) revert NotASelectedValidator();
        if (_isDisputeActive(proposalId)) revert DisputeActive();
        if (!_canBeChallenge(proposalId)) revert InvalidProposalState();

        // Initialize dispute mechanism (only when actually challenged)
        disputeManager.initializeDispute(proposalId, posData[proposalId].validators, CHALLENGE_PERIOD, msg.sender);

        ITransactionManager(posData[proposalId].transactionManager).updateProposalStatus(
            proposalId, IConsensus.ProposalStatus.Challenged
        );

        emit ChallengeInitiated(proposalId, msg.sender);
    }

    /**
     * @dev Check if a proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        return _canBeChallenge(proposalId);
    }

    /**
     * @dev Submit a vote on a challenged proposal
     */
    function submitVote(bytes32 proposalId, address voter, bool support, bytes calldata signature) external {
        if (!posData[proposalId].initialized) revert ProposalNotFound();

        // Check if there's actually an active dispute - use isInVotingPeriod to verify
        // both that the dispute is initialized AND in the correct state
        if (!disputeManager.isInVotingPeriod(proposalId)) revert InvalidProposalState();

        // Delegate to dispute manager
        disputeManager.submitVote(proposalId, voter, support, signature);
    }

    /**
     * @dev Manually resolve a dispute when voting period ends or sufficient votes collected
     * @dev Can be called by anyone to finalize expired disputes
     */
    function resolveDispute(bytes32 proposalId) external nonReentrant {
        if (!posData[proposalId].initialized) revert ProposalNotFound();
        if (!stakingManager.isValidator(msg.sender)) revert NotAValidator();

        // Check if there's actually an active dispute - use isInVotingPeriod to verify
        // both that the dispute is initialized AND in the correct state
        if (!disputeManager.isInVotingPeriod(proposalId)) revert InvalidProposalState();

        // Delegate to dispute manager - it will call back onDisputeResolved
        bool resolved = disputeManager.resolveDispute(proposalId);
        if (!resolved) revert DisputeResolutionFailed();
    }

    // ==================== SIGNATURE COLLECTION ====================

    /**
     * @dev Validators sign a proposal using ECDSA signatures to finalize it
     * @param proposalId Proposal identifier
     * @param signature ECDSA signature of the proposal hash
     */
    function signProposal(bytes32 proposalId, bytes calldata signature) external nonReentrant {
        if (!posData[proposalId].initialized) revert ProposalNotFound();

        // Can't sign if proposal is already finalized
        if (posData[proposalId].signatureCount >= CONSENSUS_THRESHOLD) {
            revert InvalidProposalState();
        }

        // Can't sign if proposal is actively being disputed
        if (_isDisputeActive(proposalId)) {
            revert InvalidProposalState();
        }

        if (hasValidatorSigned[proposalId][msg.sender]) revert AlreadySigned();

        // Verify that sender is one of the selected validators for this proposal
        if (!_isSelectedValidator(proposalId, msg.sender)) revert NotASelectedValidator();

        // Verify the signature
        bytes32 messageHash = _getProposalHash(proposalId);
        address recoveredSigner = _recoverSigner(messageHash, signature);
        if (recoveredSigner != msg.sender) revert InvalidSignature();

        // Record the signature
        hasValidatorSigned[proposalId][msg.sender] = true;
        proposalSigners[proposalId].push(msg.sender);
        posData[proposalId].signatureCount++;

        // Emit signature received event
        emit SignatureReceived(proposalId, msg.sender, posData[proposalId].signatureCount);

        // Check if consensus is reached
        if (posData[proposalId].signatureCount >= CONSENSUS_THRESHOLD) {
            emit ConsensusReached(proposalId, proposalSigners[proposalId]);
        }

        _finalizeProposal(proposalId);
    }

    // ==================== VALIDATOR FUNCTIONS ====================

    /**
     * @dev Get current validators for consensus
     */
    function getValidators() external view returns (address[] memory validators) {
        return _getTopValidators();
    }

    /**
     * @dev Get validator count
     */
    function getValidatorCount() external view returns (uint256 count) {
        return stakingManager.getValidatorCount();
    }

    // ==================== INFO FUNCTIONS ====================

    /**
     * @dev Get consensus type identifier
     */
    function getConsensusType() external pure returns (string memory consensusType) {
        return "PoS";
    }

    /**
     * @dev Check if consensus supports challenges/disputes
     */
    function supportsDisputes() external pure returns (bool) {
        return true;
    }

    // ==================== INTERNAL FUNCTIONS ====================

    /**
     * @dev Get top validators for consensus
     */
    function _getTopValidators() internal view returns (address[] memory) {
        uint256 validatorCount = stakingManager.getValidatorCount();
        if (validatorCount == 0) {
            return new address[](0);
        }

        uint256 count = validatorCount < VALIDATOR_SET_SIZE ? validatorCount : VALIDATOR_SET_SIZE;
        (address[] memory topValidators, uint256[] memory topStakes) = stakingManager.getTopNValidators(count);
        // We only need the validators array for consensus, stakes are not used here
        // but we handle the return value properly to satisfy static analysis
        if (topStakes.length != topValidators.length) revert MismatchedValidatorData();
        return topValidators;
    }

    /**
     * @dev Check if address is a selected validator for the proposal
     * @notice Uses current top validators - this assumes validator set is relatively stable
     */
    function _isSelectedValidator(bytes32 proposalId, address validator) internal view returns (bool) {
        address[] memory validators = posData[proposalId].validators;
        for (uint256 i = 0; i < validators.length;) {
            if (validators[i] == validator) {
                return true;
            }
            unchecked {
                ++i;
            }
        }
        return false;
    }

    /**
     * @dev Create proposal hash for signature verification
     */
    function _getProposalHash(bytes32 proposalId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", proposalId));
    }

    /**
     * @dev Recover signer from signature
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

        if (v != 27 && v != 28) revert InvalidSignature();

        return ecrecover(messageHash, v, r, s);
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @dev Get signature count for a proposal
     */
    function getSignatureCount(bytes32 proposalId) external view returns (uint256) {
        return posData[proposalId].signatureCount;
    }

    /**
     * @dev Check if proposal is initialized in PoS consensus
     */
    function isProposalInitialized(bytes32 proposalId) external view returns (bool) {
        return posData[proposalId].initialized;
    }

    /**
     * @dev Get signers for a proposal
     */
    function getProposalSigners(bytes32 proposalId) external view returns (address[] memory) {
        return proposalSigners[proposalId];
    }

    /**
     * @dev Get current status of a proposal (IConsensus interface method)
     * @dev Delegates to TransactionManager for the authoritative state
     */
    function getProposalStatus(bytes32 proposalId) external view returns (ProposalStatus status) {
        if (!posData[proposalId].initialized) {
            return ProposalStatus.Proposed;
        }

        // Get the authoritative status from TransactionManager
        address transactionManager = posData[proposalId].transactionManager;
        return ITransactionManager(transactionManager).getProposalStatus(proposalId);
    }

    /**
     * @dev Get current dispute state for a proposal
     * @dev Returns the dispute state if a dispute exists, reverts if no dispute initialized
     */
    function getDisputeState(bytes32 proposalId) external view returns (DisputeManager.DisputeState) {
        return disputeManager.getDisputeState(proposalId);
    }

    /**
     * @dev Check if proposal has an active dispute
     */
    function hasActiveDispute(bytes32 proposalId) external view returns (bool) {
        if (!posData[proposalId].initialized) {
            return false;
        }

        try disputeManager.getDisputeState(proposalId) returns (DisputeManager.DisputeState disputeState) {
            return disputeState == DisputeManager.DisputeState.Disputed;
        } catch {
            return false; // No dispute initialized
        }
    }

    /**
     * @dev Check if a proposal can be finalized (IConsensus interface method)
     */
    function canFinalizeProposal(bytes32 proposalId) external view returns (bool canFinalize) {
        if (!posData[proposalId].initialized) return false;

        // Can finalize if has enough signatures OR if dispute is resolved
        if (posData[proposalId].signatureCount >= CONSENSUS_THRESHOLD) {
            return true;
        }

        // Check if dispute is resolved
        try disputeManager.getDisputeState(proposalId) returns (DisputeManager.DisputeState disputeState) {
            return disputeState == DisputeManager.DisputeState.Upheld
                || disputeState == DisputeManager.DisputeState.Overturned;
        } catch {
            return false;
        }
    }

    /**
     * @dev Finalize a proposal (IConsensus interface method)
     */
    function finalizeProposal(bytes32 proposalId) external returns (bool approved) {
        _finalizeProposal(proposalId);
        return posData[proposalId].signatureCount >= CONSENSUS_THRESHOLD;
    }

    /**
     * @dev Challenge a proposal (IConsensus interface method with challenger parameter)
     */
    function challengeProposal(bytes32 proposalId, address challenger) external {
        if (!posData[proposalId].initialized) revert ProposalNotFound();
        if (!_isSelectedValidator(proposalId, challenger)) revert NotASelectedValidator();
        if (!_canBeChallenge(proposalId)) revert InvalidProposalState();
        if (_isDisputeActive(proposalId)) revert DisputeActive();

        // Emit event BEFORE external calls to prevent reentrancy issues
        emit ChallengeInitiated(proposalId, challenger);

        // External calls come after event emission
        disputeManager.initializeDispute(proposalId, posData[proposalId].validators, CHALLENGE_PERIOD, challenger);

        ITransactionManager(posData[proposalId].transactionManager).updateProposalStatus(
            proposalId, IConsensus.ProposalStatus.Challenged
        );
    }

    // ==================== INTERNAL FUNCTIONS ====================

    function _finalizeProposal(bytes32 proposalId) internal {
        if (!posData[proposalId].initialized) revert ProposalNotFound();

        // Only finalize if we have enough signatures AND no active dispute
        if (posData[proposalId].signatureCount >= CONSENSUS_THRESHOLD && !_isDisputeActive(proposalId)) {
            ITransactionManager(posData[proposalId].transactionManager).updateProposalStatus(
                proposalId, IConsensus.ProposalStatus.Finalized
            );
            emit ProposalStateUpdatedByConsensus(proposalId, IConsensus.ProposalStatus.Finalized);
        }
        // If not enough signatures, just return without doing anything (allow more signatures)
    }

    function _canBeChallenge(bytes32 proposalId) internal view returns (bool) {
        // If proposal block + CHALLENGE_PERIOD has passed, it cannot be challenged
        // Also if the proposal is challenged, it cannot be challenged again
        address transactionManager = posData[proposalId].transactionManager;
        uint256 blockNumber = ITransactionManager(transactionManager).getProposalBlockNumber(proposalId);
        if (
            block.number > blockNumber + CHALLENGE_PERIOD
                || ITransactionManager(transactionManager).getProposalStatus(proposalId)
                    == IConsensus.ProposalStatus.Challenged
        ) {
            return false;
        }

        return true;
    }

    function _isDisputeActive(bytes32 proposalId) internal view returns (bool) {
        address transactionManager = posData[proposalId].transactionManager;
        IConsensus.ProposalStatus status = ITransactionManager(transactionManager).getProposalStatus(proposalId);
        if (status == IConsensus.ProposalStatus.Challenged) {
            if (disputeManager.getDisputeState(proposalId) == DisputeManager.DisputeState.Disputed) {
                return true;
            }
        }

        return false;
    }

    // ==================== DISPUTE RESOLUTION CALLBACK ====================

    /**
     * @dev Called by dispute manager when dispute is resolved
     * @param proposalId The proposal ID
     * @param upheld Whether the original decision was upheld (true) or overturned (false)
     * @param challenger The address that initiated the challenge
     */
    function onDisputeResolved(bytes32 proposalId, bool upheld, address challenger)
        external
        onlyAssociatedDisputeManager
        nonReentrant
    {
        if (!posData[proposalId].initialized) revert ProposalNotFound();

        uint256 slashAmount = 0;
        address transactionManager = posData[proposalId].transactionManager;

        if (!upheld) {
            // Challenge was successful - proposal is rejected/overturned
            // Slash all who submitted signatures for invalid proposal
            for (uint256 i = 0; i < proposalSigners[proposalId].length; i++) {
                address validator = proposalSigners[proposalId][i];
                if (validator == challenger) continue;
                uint256 validatorStake = stakingManager.getValidatorStake(validator);
                if (validatorStake > 0) {
                    uint256 validatorSlashAmount = (validatorStake * SLASH_PERCENTAGE) / 100;
                    stakingManager.slashValidator(validator, validatorSlashAmount, "Invalid proposal approved");
                    slashAmount += validatorSlashAmount; // Accumulate total slash amount
                }
            }
            // Give rewards to honest challenger who detected invalid proposal
            if (slashAmount > 0) {
                stakingManager.distributeRewards(slashAmount, challenger);
            }
            ITransactionManager(transactionManager).updateProposalStatus(proposalId, IConsensus.ProposalStatus.Rejected);
        } else {
            // Challenge failed - original decision upheld
            // Slash the challenger for false challenge
            uint256 challengerStake = stakingManager.getValidatorStake(challenger);
            if (challengerStake > 0) {
                // Use a reasonable slash percentage (e.g., 10%)
                slashAmount = (challengerStake * 10) / 100;
                stakingManager.slashValidator(challenger, slashAmount, "False challenge");
            }
            // Distribute slash amount among validators who signed (excluding challenger if they signed)
            uint256 recipientCount = 0;
            for (uint256 i = 0; i < proposalSigners[proposalId].length; i++) {
                if (proposalSigners[proposalId][i] != challenger) {
                    recipientCount++;
                }
            }

            if (recipientCount > 0 && slashAmount > 0) {
                uint256 rewardPerValidator = slashAmount / recipientCount;
                for (uint256 i = 0; i < proposalSigners[proposalId].length; i++) {
                    if (proposalSigners[proposalId][i] != challenger) {
                        stakingManager.distributeRewards(rewardPerValidator, proposalSigners[proposalId][i]);
                    }
                }
            }
            ITransactionManager(transactionManager).updateProposalStatus(
                proposalId, IConsensus.ProposalStatus.Finalized
            );
        }

        emit DisputeResolved(proposalId, upheld, challenger, slashAmount);
    }
}
