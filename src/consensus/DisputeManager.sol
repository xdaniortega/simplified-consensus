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

    /**
     * @dev Emitted when a challenge is initiated against a proposal
     * @param proposalId The ID of the challenged proposal
     * @param challenger The address that initiated the challenge
     */
    event ChallengeInitiated(bytes32 indexed proposalId, address indexed challenger);

    /**
     * @dev Emitted when a validator submits a vote on a disputed proposal
     * @param proposalId The ID of the disputed proposal
     * @param voter The address of the voting validator
     * @param support Whether the vote supports upholding (true) or overturning (false) the proposal
     */
    event VoteSubmitted(bytes32 indexed proposalId, address indexed voter, bool support);

    /**
     * @dev Emitted when dispute voting is completed
     * @param proposalId The ID of the disputed proposal
     * @param upheld Whether the original decision was upheld
     * @param yesVotes Number of votes to uphold
     * @param noVotes Number of votes to overturn
     */
    event DisputeVotingCompleted(bytes32 indexed proposalId, bool upheld, uint256 yesVotes, uint256 noVotes);
    // ==================== CUSTOM ERRORS ====================

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
    error AlreadyResolved();
    error ZeroAddress();

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

    /// @dev Reference to the staking manager contract
    StakingManager public immutable stakingManager;
    /// @dev Address of the consensus contract that can call dispute functions
    address public immutable consensusContract;
    /// @dev Mapping of proposal IDs to their dispute data
    mapping(bytes32 => DisputeData) public disputeData;
    /// @dev Mapping of proposal IDs to their voting data
    mapping(bytes32 => VoteData) public voteData;
    /// @dev Duration in blocks for voting after challenge
    uint256 public immutable VOTING_PERIOD;

    // ==================== MODIFIERS ====================

    /**
     * @dev Restricts function access to only the consensus contract
     */
    modifier onlyConsensusContract() {
        if (msg.sender != consensusContract) revert OnlyConsensusContract();
        _;
    }

    /**
     * @dev Ensures the dispute for a proposal is initialized
     * @param proposalId The proposal ID to check
     */
    modifier onlyValidDispute(bytes32 proposalId) {
        if (!disputeData[proposalId].initialized) revert DisputeNotInitialized();
        _;
    }

    // ==================== CONSTRUCTOR ====================
    constructor(address _stakingManager, address _consensusContract, uint256 _votingPeriod) {
        if (_stakingManager == address(0)) revert ZeroAddress();
        if (_consensusContract == address(0)) revert ZeroAddress();
        if (_votingPeriod == 0) revert InvalidState();

        stakingManager = StakingManager(_stakingManager);
        consensusContract = _consensusContract;
        VOTING_PERIOD = _votingPeriod;
    }

    // ==================== EXTERNAL FUNCTIONS ====================

    /**
     * @dev Initialize dispute mechanism for a proposal
     * @param proposalId The unique identifier of the proposal
     * @param selectedValidators Array of validators selected for this proposal
     * @param challengePeriod Duration in blocks for challenge period
     * @param _challenger Address of the challenger
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
     * @param proposalId The unique identifier of the disputed proposal
     * @param voter Address of the validator submitting the vote
     * @param support Whether the vote supports upholding (true) or overturning (false) the proposal
     * @param signature ECDSA signature proving the vote came from the validator
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
     * @dev Resolve dispute after voting period or when decisive majority is reached
     * @param proposalId The unique identifier of the disputed proposal
     * @return upheld Whether the original decision was upheld
     */
    function resolveDispute(
        bytes32 proposalId
    ) external onlyConsensusContract onlyValidDispute(proposalId) returns (bool upheld) {
        return _resolveDispute(proposalId);
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @dev Get current dispute state for a proposal
     * @param proposalId The unique identifier of the proposal
     * @return state The current state of the dispute
     */
    function getDisputeState(bytes32 proposalId) external view returns (DisputeState state) {
        return disputeData[proposalId].state;
    }

    /**
     * @dev Get full dispute state for a proposal
     * @param proposalId The unique identifier of the proposal
     * @return state The current dispute state
     * @return deadline The voting deadline block number
     * @return yesVotes Number of votes to uphold
     * @return noVotes Number of votes to overturn
     */
    function getFullDisputeState(
        bytes32 proposalId
    ) external view returns (DisputeState state, uint256 deadline, uint256 yesVotes, uint256 noVotes) {
        DisputeData memory dispute = disputeData[proposalId];
        VoteData memory votes = voteData[proposalId];

        return (dispute.state, dispute.deadline, votes.yesVotes, votes.noVotes);
    }

    /**
     * @dev Check if proposal can be challenged
     * @param proposalId The unique identifier of the proposal
     * @return bool Whether the proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        // Safer enum comparison - check if dispute is in disputing state and deadline not passed
        return
            dispute.initialized &&
            _isDisputeInState(dispute, DisputeState.Disputed) &&
            block.number <= dispute.deadline;
    }

    /**
     * @dev Check if proposal is in voting period
     * @param proposalId The unique identifier of the proposal
     * @return bool Whether the proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        // Safer enum comparison - check if dispute is in disputing state and deadline not passed
        return
            dispute.initialized &&
            _isDisputeInState(dispute, DisputeState.Disputed) &&
            block.number <= dispute.deadline;
    }

    /**
     * @dev Get challenge information for a proposal
     * @param proposalId The unique identifier of the proposal
     * @return challenger Address of the challenger
     * @return challengeBlock Block number when challenge was initiated (deprecated, returns 0)
     */
    function getChallengeInfo(bytes32 proposalId) external view returns (address challenger, uint256 challengeBlock) {
        DisputeData memory dispute = disputeData[proposalId];
        return (dispute.challenger, 0); // challengeBlock no longer stored
    }

    /**
     * @dev Get all voters for a proposal
     * @param proposalId The unique identifier of the proposal
     * @return voters Array of addresses that voted on the proposal
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
     * @dev Get individual validator's vote information
     * @param proposalId The unique identifier of the proposal
     * @param validator Address of the validator to check
     * @return hasVoted Whether the validator has voted
     * @return support The validator's vote (true = uphold, false = overturn)
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
     * @param proposalId The unique identifier of the proposal
     * @param validator Address of the validator
     * @return index The index of the validator in the selected validators array
     */
    function getValidatorIndexExternal(bytes32 proposalId, address validator) external view returns (uint8) {
        return _getValidatorIndex(proposalId, validator);
    }

    // ==================== INTERNAL FUNCTIONS ====================

    /**
     * @dev Internal function to resolve voting results and handle dispute resolution
     * @param proposalId The unique identifier of the disputed proposal
     * @return upheld Whether the original decision was upheld
     */
    function _resolveVoting(bytes32 proposalId) internal view returns (bool upheld) {
        VoteData memory votes = voteData[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;

        if (totalVotes > 0) {
            // Strict majority needed to overturn - more than 50%
            // In tie votes (50%-50%), uphold the original decision
            upheld = votes.noVotes * 2 <= totalVotes; // upheld if noVotes <= 50%
        } else {
            // No votes cast - default to uphold original decision
            upheld = true;
        }

        return upheld;
    }

    /**
     * @dev Internal function to resolve a dispute
     * @param proposalId The unique identifier of the disputed proposal
     * @return upheld Whether the original decision was upheld
     */
    function _resolveDispute(bytes32 proposalId) internal returns (bool) {
        DisputeData storage dispute = disputeData[proposalId];

        // Check if already resolved
        if (dispute.state != DisputeState.Disputed) {
            revert AlreadyResolved();
        }

        // Check if it's time to resolve or if we have decisive majority
        if (!_shouldResolveNow(proposalId)) {
            return false;
        }

        bool upheld = _resolveVoting(proposalId);
        dispute.state = upheld ? DisputeState.Upheld : DisputeState.Overturned;

        VoteData memory votes = voteData[proposalId];

        //Emit event BEFORE external call to prevent reentrancy issues
        emit DisputeVotingCompleted(proposalId, upheld, votes.yesVotes, votes.noVotes);

        // External call comes after state changes and event emission
        IConsensus(consensusContract).onDisputeResolved(proposalId, upheld, dispute.challenger);

        return upheld;
    }

    /**
     * @dev Check if dispute should be resolved now
     * @param proposalId The unique identifier of the disputed proposal
     * @return Whether the dispute should be resolved
     */
    function _shouldResolveNow(bytes32 proposalId) internal view returns (bool) {
        DisputeData memory dispute = disputeData[proposalId];
        VoteData memory votes = voteData[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;
        uint256 totalValidators = dispute.selectedValidators.length;

        // Resolve if voting period ended OR if majority of validators voted
        return block.number > dispute.deadline || totalVotes > totalValidators / 2;
    }

    /**
     * @dev Get validator index in the selected validators array
     * @param proposalId The unique identifier of the proposal
     * @param validator Address of the validator
     * @return index The index of the validator in the array
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
     * @param proposalId The unique identifier of the proposal
     * @param validator Address of the validator
     * @return Whether the validator has already voted
     */
    function _hasValidatorVoted(bytes32 proposalId, address validator) internal view returns (bool) {
        uint8 index = _getValidatorIndex(proposalId, validator);
        uint8 votersBitmap = voteData[proposalId].votersBitmap;
        return (votersBitmap >> index) & 1 == 1;
    }

    /**
     * @dev Record validator vote using bitmaps
     * @param proposalId The unique identifier of the proposal
     * @param validator Address of the validator
     * @param support Whether the vote supports upholding the proposal
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

    /**
     * @dev Create vote hash for signature verification
     * @param proposalId The unique identifier of the proposal
     * @param support Whether the vote supports upholding the proposal
     * @return The hash that should be signed by the validator
     */
    function _getVoteHash(bytes32 proposalId, bool support) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
            );
    }

    /**
     * @dev Recover signer from signature
     * @param messageHash The hash that was signed
     * @param signature The ECDSA signature
     * @return The address that created the signature
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

    /**
     * @dev Helper to check if a dispute is in a specific state
     * @param dispute The dispute data
     * @param state The state to check for
     * @return bool Whether the dispute is in the specified state
     */
    function _isDisputeInState(DisputeData memory dispute, DisputeState state) internal pure returns (bool) {
        // Direct enum comparison is safer than casting to uint8
        return dispute.state == state;
    }
}
