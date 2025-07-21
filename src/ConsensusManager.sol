// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/IConsensusProvider.sol";
import "./ValidatorFactory.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title ConsensusManager
 * @dev Handles challenge and voting mechanisms for optimistic consensus
 * @notice This contract is completely decoupled from proposal logic
 */
contract ConsensusManager is IConsensusProvider, ReentrancyGuard {
    error InvalidProposalId();
    error ConsensusNotInitialized();
    error ConsensusAlreadyInitialized();
    error InvalidState();
    error ChallengePeriodExpired();
    error VotingPeriodExpired();
    error VotingPeriodNotEnded();
    error NotAValidator();
    error NotASelectedValidator();
    error AlreadyVoted();
    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidSignatureV();
    error OnlyTransactionManager();

    struct ConsensusData {
        ConsensusState state;
        uint256 deadline;              // Challenge or voting deadline
        address[] selectedValidators;  // Validators for this proposal
        bool initialized;
    }

    struct ChallengeInfo {
        address challenger;
        uint256 challengeBlock;
    }

    // Optimized voting data structure using bitmaps
    struct VoteData {
        uint8 yesVotes;        // Count of yes votes (max 5 validators)
        uint8 noVotes;         // Count of no votes (max 5 validators)
        uint8 votersBitmap;    // Bitmap: bit i set if validator i voted
        uint8 votesBitmap;     // Bitmap: bit i set if validator i voted YES
    }

    ValidatorFactory public immutable validatorFactory;
    address public immutable transactionManager;

    mapping(bytes32 => ConsensusData) public consensusData;
    mapping(bytes32 => ChallengeInfo) public challengeInfo;
    mapping(bytes32 => VoteData) public voteData;

    uint256 public constant VOTING_PERIOD = 30; // blocks for voting after challenge
    uint256 public constant SLASH_PERCENTAGE = 10; // 10% slash for false challenges

    modifier onlyTransactionManager() {
        if (msg.sender != transactionManager) revert OnlyTransactionManager();
        _;
    }

    modifier onlyValidConsensus(bytes32 proposalId) {
        if (!consensusData[proposalId].initialized) revert ConsensusNotInitialized();
        _;
    }

    constructor(address _validatorFactory, address _transactionManager) {
        validatorFactory = ValidatorFactory(_validatorFactory);
        transactionManager = _transactionManager;
    }

    /**
     * @dev Initialize consensus process for a proposal
     */
    function initializeConsensus(
        bytes32 proposalId,
        address[] calldata selectedValidators,
        uint256 challengePeriod
    ) external onlyTransactionManager {
        if (consensusData[proposalId].initialized) revert ConsensusAlreadyInitialized();

        consensusData[proposalId] = ConsensusData({
            state: ConsensusState.Pending,
            deadline: block.number + challengePeriod,
            selectedValidators: selectedValidators,
            initialized: true
        });
    }

    /**
     * @dev Challenge a proposal during challenge period
     */
    function challengeProposal(bytes32 proposalId, address challenger) 
        external 
        onlyTransactionManager 
        onlyValidConsensus(proposalId)
    {
        ConsensusData storage consensus = consensusData[proposalId];
        if (consensus.state != ConsensusState.Pending) revert InvalidState();
        if (block.number > consensus.deadline) revert ChallengePeriodExpired();
        if (!validatorFactory.isActiveValidator(challenger)) revert NotAValidator();

        // Transition to challenged state with voting deadline
        consensus.state = ConsensusState.Challenged;
        consensus.deadline = block.number + VOTING_PERIOD;

        // Store challenge information
        challengeInfo[proposalId] = ChallengeInfo({
            challenger: challenger,
            challengeBlock: block.number
        });

        emit ChallengeInitiated(proposalId, challenger);
    }

    /**
     * @dev Submit a vote on a challenged proposal
     */
    function submitVote(
        bytes32 proposalId,
        address voter,
        bool support,
        bytes calldata signature
    ) external onlyTransactionManager onlyValidConsensus(proposalId) {
        ConsensusData storage consensus = consensusData[proposalId];
        if (consensus.state != ConsensusState.Challenged) revert InvalidState();
        if (block.number > consensus.deadline) revert VotingPeriodExpired();
        if (!validatorFactory.isActiveValidator(voter)) revert NotAValidator();
        if (_hasValidatorVoted(proposalId, voter)) revert AlreadyVoted();

        // Verify the vote signature
        bytes32 voteHash = _getVoteHash(proposalId, support);
        address recoveredSigner = _recoverSigner(voteHash, signature);
        if (recoveredSigner != voter) revert InvalidSignature();

        // Record the vote using optimized bitmap
        _recordVote(proposalId, voter, support);

        emit VoteSubmitted(proposalId, voter, support);
    }

    /**
     * @dev Resolve consensus after voting period or challenge period expires
     */
    function resolveConsensus(bytes32 proposalId) 
        external 
        onlyTransactionManager 
        onlyValidConsensus(proposalId) 
        returns (bool approved) 
    {
        ConsensusData storage consensus = consensusData[proposalId];

        if (consensus.state == ConsensusState.Pending) {
            // Challenge period ended without challenge - approve
            if (block.number <= consensus.deadline) revert ChallengePeriodExpired();
            approved = true;
            consensus.state = ConsensusState.Approved;
        } else if (consensus.state == ConsensusState.Challenged) {
            // Resolve voting
            if (block.number <= consensus.deadline) revert VotingPeriodNotEnded();
            approved = _resolveVoting(proposalId);
            consensus.state = approved ? ConsensusState.Approved : ConsensusState.Rejected;
        } else {
            revert InvalidState();
        }

        VoteData memory votes = voteData[proposalId];
        emit ConsensusReached(proposalId, approved, votes.yesVotes, votes.noVotes);
    }

    /**
     * @dev Internal function to resolve voting results and handle slashing
     */
    function _resolveVoting(bytes32 proposalId) internal returns (bool approved) {
        VoteData memory votes = voteData[proposalId];
        ChallengeInfo memory challenge = challengeInfo[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;

        if (totalVotes > 0) {
            // Majority decides - if >=50% vote no, reject the proposal
            uint256 rejectionThreshold = (totalVotes + 1) / 2;
            approved = votes.noVotes < rejectionThreshold;
        } else {
            // No votes cast - default to original decision (approved by LLM)
            approved = true;
        }

        // Handle slashing
        _handleSlashing(proposalId, challenge.challenger, !approved);

        return approved;
    }

    /**
     * @dev Handle slashing for challenge resolution
     */
    function _handleSlashing(bytes32 proposalId, address challenger, bool challengeWasHonest) internal {
        if (!challengeWasHonest) {
            // False challenge - slash challenger's stake
            uint256 challengerStake = validatorFactory.getValidatorStake(challenger);
            if (challengerStake > 0) {
                uint256 slashAmount = (challengerStake * SLASH_PERCENTAGE) / 100;
                validatorFactory.slashValidator(challenger, slashAmount, "False challenge");
                emit ValidatorSlashed(proposalId, challenger, slashAmount, false);
            }
        } else {
            // Honest challenge - no slashing needed
            emit ValidatorSlashed(proposalId, challenger, 0, true);
        }
    }

    // ==================== BITMAP VOTING FUNCTIONS ====================

    /**
     * @dev Get validator index in the selected validators array
     */
    function _getValidatorIndex(bytes32 proposalId, address validator) internal view returns (uint8 index) {
        address[] memory selectedValidators = consensusData[proposalId].selectedValidators;
        for (uint8 i = 0; i < selectedValidators.length; i++) {
            if (selectedValidators[i] == validator) {
                return i;
            }
        }
        revert NotASelectedValidator();
    }

    /**
     * @dev Check if validator has voted using bitmap
     */
    function _hasValidatorVoted(bytes32 proposalId, address validator) internal view returns (bool) {
        uint8 index = _getValidatorIndex(proposalId, validator);
        uint8 votersBitmap = voteData[proposalId].votersBitmap;
        return (votersBitmap >> index) & 1 == 1;
    }

    /**
     * @dev Record validator vote using bitmaps
     */
    function _recordVote(bytes32 proposalId, address validator, bool support) internal {
        uint8 index = _getValidatorIndex(proposalId, validator);
        VoteData storage votes = voteData[proposalId];

        // Set voted bit
        votes.votersBitmap |= uint8(1 << index);

        // Set/clear vote bit and update counters
        if (support) {
            votes.votesBitmap |= uint8(1 << index);
            votes.yesVotes++;
        } else {
            votes.votesBitmap &= ~uint8(1 << index);
            votes.noVotes++;
        }
    }

    // ==================== SIGNATURE VERIFICATION ====================

    /**
     * @dev Create vote hash for signature verification
     */
    function _getVoteHash(bytes32 proposalId, bool support) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
        );
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
     * @dev Get current consensus state for a proposal
     */
    function getConsensusState(bytes32 proposalId)
        external
        view
        returns (ConsensusState state, uint256 deadline, uint256 yesVotes, uint256 noVotes)
    {
        ConsensusData memory consensus = consensusData[proposalId];
        VoteData memory votes = voteData[proposalId];

        return (consensus.state, consensus.deadline, votes.yesVotes, votes.noVotes);
    }

    /**
     * @dev Check if a proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        ConsensusData memory consensus = consensusData[proposalId];
        return consensus.initialized && 
               consensus.state == ConsensusState.Pending && 
               block.number <= consensus.deadline;
    }

    /**
     * @dev Check if proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        ConsensusData memory consensus = consensusData[proposalId];
        return consensus.initialized && 
               consensus.state == ConsensusState.Challenged && 
               block.number <= consensus.deadline;
    }

    /**
     * @dev Get challenge information
     */
    function getChallengeInfo(bytes32 proposalId)
        external
        view
        returns (address challenger, uint256 challengeBlock)
    {
        ChallengeInfo memory challenge = challengeInfo[proposalId];
        return (challenge.challenger, challenge.challengeBlock);
    }

    /**
     * @dev Get voters for a proposal
     */
    function getVoters(bytes32 proposalId) external view returns (address[] memory voters) {
        ConsensusData memory consensus = consensusData[proposalId];
        address[] memory selectedValidators = consensus.selectedValidators;
        uint8 votersBitmap = voteData[proposalId].votersBitmap;

        // Count voters first
        uint256 voterCount = 0;
        for (uint8 i = 0; i < selectedValidators.length; i++) {
            if ((votersBitmap >> i) & 1 == 1) {
                voterCount++;
            }
        }

        // Build voters array
        voters = new address[](voterCount);
        uint256 index = 0;
        for (uint8 i = 0; i < selectedValidators.length; i++) {
            if ((votersBitmap >> i) & 1 == 1) {
                voters[index] = selectedValidators[i];
                index++;
            }
        }
    }

    /**
     * @dev Get individual validator's vote
     */
    function getValidatorVote(bytes32 proposalId, address validator)
        external
        view
        returns (bool hasVoted, bool support)
    {
        try this.getValidatorIndexExternal(proposalId, validator) returns (uint8 index) {
            uint8 votersBitmap = voteData[proposalId].votersBitmap;
            uint8 votesBitmap = voteData[proposalId].votesBitmap;
            hasVoted = (votersBitmap >> index) & 1 == 1;
            support = (votesBitmap >> index) & 1 == 1;
        } catch {
            // Validator not selected for this proposal
            hasVoted = false;
            support = false;
        }
    }

    /**
     * @dev External wrapper for _getValidatorIndex (needed for try/catch)
     */
    function getValidatorIndexExternal(bytes32 proposalId, address validator) external view returns (uint8) {
        return _getValidatorIndex(proposalId, validator);
    }
} 