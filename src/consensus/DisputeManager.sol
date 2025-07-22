// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "../staking/StakingManager.sol";
import "../interfaces/IConsensus.sol";

/**
 * @title DisputeManager
 * @dev Dispute resolution system for consensus mechanisms
 * @notice This contract provides challenge and voting mechanisms that can be
 *         integrated with consensus mechanisms to provide dispute resolution functionality
 */
contract DisputeManager is ReentrancyGuard {
    // ==================== ENUMS ====================

    enum DisputeState {
        Disputed, // Challenge initiated, voting in progress
        Upheld, // Dispute resolved - original decision upheld
        Overturned // Dispute resolved - original decision overturned
    }

    // ==================== EVENTS ====================

    event ChallengeInitiated(bytes32 indexed proposalId, address indexed challenger);
    event VoteSubmitted(bytes32 indexed proposalId, address indexed voter, bool support);
    event DisputeResolved(bytes32 indexed proposalId, bool upheld, uint256 yesVotes, uint256 noVotes);
    event ValidatorSlashed(bytes32 indexed proposalId, address indexed challenger, uint256 amount, bool wasHonest);
    event ConsensusNotificationFailed(bytes32 indexed proposalId, bool upheld, address challenger);

    // ==================== ERRORS ====================

    error InvalidProposalId();
    error DisputeNotInitialized();
    error DisputeAlreadyInitialized();
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
    error OnlyConsensusContract();

    // ==================== STRUCTS ====================

    struct DisputeData {
        DisputeState state;
        uint256 deadline; // Challenge or voting deadline
        address[] selectedValidators; // Validators for this proposal
        bool initialized;
        address challenger;
    }

    // Optimized voting data structure using bitmaps
    struct VoteData {
        uint8 yesVotes; // Count of votes to uphold (max 5 validators)
        uint8 noVotes; // Count of votes to overturn (max 5 validators)
        uint8 votersBitmap; // Bitmap: bit i set if validator i voted
        uint8 votesBitmap; // Bitmap: bit i set if validator i voted YES (uphold)
    }

    // ==================== STATE VARIABLES ====================

    StakingManager public immutable stakingManager;
    address public immutable consensusContract;

    mapping(bytes32 => DisputeData) public disputeData;
    mapping(bytes32 => VoteData) public voteData;

    uint256 public immutable VOTING_PERIOD; // blocks for voting after challenge

    // ==================== MODIFIERS ====================

    modifier onlyConsensusContract() {
        if (msg.sender != consensusContract) revert OnlyConsensusContract();
        _;
    }

    modifier onlyValidDispute(bytes32 proposalId) {
        if (!disputeData[proposalId].initialized) revert DisputeNotInitialized();
        _;
    }

    // ==================== CONSTRUCTOR ====================

    constructor(address _stakingManager, address _consensusContract, uint256 _votingPeriod) {
        stakingManager = StakingManager(_stakingManager);
        consensusContract = _consensusContract;
        VOTING_PERIOD = _votingPeriod;
    }

    // ==================== CORE FUNCTIONS ====================

    /**
     * @dev Initialize dispute mechanism for a proposal
     */
    function initializeDispute(
        bytes32 proposalId,
        address[] calldata selectedValidators,
        uint256 challengePeriod,
        address _challenger
    ) external onlyConsensusContract {
        if (disputeData[proposalId].initialized) revert DisputeAlreadyInitialized();

        disputeData[proposalId] = DisputeData({
            state: DisputeState.Disputed,
            deadline: block.number + challengePeriod,
            selectedValidators: selectedValidators,
            initialized: true,
            challenger: _challenger
        });
    }

    /**
     * @dev Submit a vote on a disputed proposal
     */
    function submitVote(
        bytes32 proposalId,
        address voter,
        bool support,
        bytes calldata signature
    ) external onlyConsensusContract onlyValidDispute(proposalId) {
        DisputeData storage dispute = disputeData[proposalId];
        if (dispute.state != DisputeState.Disputed) revert InvalidState();
        if (block.number > dispute.deadline) revert VotingPeriodExpired();
        if (!stakingManager.isActiveValidator(voter)) revert NotAValidator();
        if (_hasValidatorVoted(proposalId, voter)) revert AlreadyVoted();

        // Verify the vote signature
        bytes32 voteHash = _getVoteHash(proposalId, support);
        address recoveredSigner = _recoverSigner(voteHash, signature);
        if (recoveredSigner != voter) revert InvalidSignature();

        // Record the vote using optimized bitmap
        _recordVote(proposalId, voter, support);

        emit VoteSubmitted(proposalId, voter, support);

        _resolveDispute(proposalId);
    }

    /**
     * @dev Resolve dispute after voting period or challenge period expires
     */
    function resolveDispute(
        bytes32 proposalId
    ) external onlyConsensusContract onlyValidDispute(proposalId) returns (bool upheld) {
        return _resolveDispute(proposalId);
    }

    /**
     * @dev Internal function to resolve voting results and handle slashing
     */
    function _resolveVoting(bytes32 proposalId) internal returns (bool upheld) {
        VoteData memory votes = voteData[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;

        if (totalVotes > 0) {
            // Majority decides - if >=50% vote to overturn, overturn the proposal
            uint256 overturnThreshold = (totalVotes + 1) / 2;
            upheld = votes.noVotes < overturnThreshold; // upheld if not enough votes to overturn
        } else {
            // No votes cast - default to uphold original decision
            upheld = true;
        }

        // No slashing handled here - will be handled by consensus contract callback

        return upheld;
    }

    /**
     * @dev Notify consensus contract about dispute resolution
     * @dev Consensus contract will handle slashing and state updates
     */

    // ==================== BITMAP VOTING FUNCTIONS ====================

    /**
     * @dev Get validator index in the selected validators array
     */
    function _getValidatorIndex(bytes32 proposalId, address validator) internal view returns (uint8 index) {
        address[] memory selectedValidators = disputeData[proposalId].selectedValidators;
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
            votes.yesVotes++; // votes to uphold
        } else {
            votes.votesBitmap &= ~uint8(1 << index);
            votes.noVotes++; // votes to overturn
        }
    }

    // ==================== SIGNATURE VERIFICATION ====================

    /**
     * @dev Create vote hash for signature verification
     */
    function _getVoteHash(bytes32 proposalId, bool support) internal pure returns (bytes32) {
        return
            keccak256(
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

    function _resolveDispute(bytes32 proposalId) internal returns (bool) {
        DisputeData storage dispute = disputeData[proposalId];

        // Check if it's time to resolve or if we have decisive majority
        if (!_shouldResolveNow(proposalId)) {
            return false; // Not ready to resolve yet
        }

        bool upheld = _resolveVoting(proposalId);
        dispute.state = upheld ? DisputeState.Upheld : DisputeState.Overturned;

        VoteData memory votes = voteData[proposalId];

        // Notify consensus contract about resolution
        IConsensus(consensusContract).onDisputeResolved(proposalId, upheld, dispute.challenger);

        emit DisputeResolved(proposalId, upheld, votes.yesVotes, votes.noVotes);
        return true;
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @dev Get current dispute state for a proposal
     */
    function getDisputeState(bytes32 proposalId) external view returns (DisputeState state) {
        return disputeData[proposalId].state;
    }

    /**
     * @dev Get full dispute state for a proposal
     */
    function getFullDisputeState(
        bytes32 proposalId
    ) external view returns (DisputeState state, uint256 deadline, uint256 yesVotes, uint256 noVotes) {
        DisputeData memory dispute = disputeData[proposalId];
        VoteData memory votes = voteData[proposalId];

        return (dispute.state, dispute.deadline, votes.yesVotes, votes.noVotes);
    }

    /**
     * @dev Check if a proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        return dispute.initialized && dispute.state == DisputeState.Disputed && block.number <= dispute.deadline;
    }

    /**
     * @dev Check if proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        return dispute.initialized && dispute.state == DisputeState.Disputed && block.number <= dispute.deadline;
    }

    /**
     * @dev Get challenge information
     */
    function getChallengeInfo(bytes32 proposalId) external view returns (address challenger, uint256 challengeBlock) {
        DisputeData memory dispute = disputeData[proposalId];
        return (dispute.challenger, 0); // challengeBlock no longer stored
    }

    /**
     * @dev Get voters for a proposal
     */
    function getVoters(bytes32 proposalId) external view returns (address[] memory voters) {
        DisputeData memory dispute = disputeData[proposalId];
        address[] memory selectedValidators = dispute.selectedValidators;
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
    function getValidatorVote(
        bytes32 proposalId,
        address validator
    ) external view returns (bool hasVoted, bool support) {
        try this.getValidatorIndexExternal(proposalId, validator) returns (uint8 index) {
            uint8 votersBitmap = voteData[proposalId].votersBitmap;
            uint8 votesBitmap = voteData[proposalId].votesBitmap;
            hasVoted = (votersBitmap >> index) & 1 == 1;
            support = (votesBitmap >> index) & 1 == 1; // true = uphold, false = overturn
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

    function _shouldResolveNow(bytes32 proposalId) internal view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        VoteData memory votes = voteData[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;
        uint256 totalValidators = dispute.selectedValidators.length;
        
        // Resolve if voting period ended OR if majority of validators voted
        return block.number > dispute.deadline || 
               totalVotes > totalValidators / 2;
    }
}
