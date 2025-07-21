// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IConsensusProvider
 * @dev Interface for consensus providers that handle challenges and voting mechanisms
 */
interface IConsensusProvider {
    enum ConsensusState {
        Pending,        // Awaiting consensus decision
        Challenged,     // Challenge initiated, voting in progress  
        Approved,       // Consensus reached - proposal approved
        Rejected        // Consensus reached - proposal rejected
    }

    event ChallengeInitiated(bytes32 indexed proposalId, address indexed challenger);
    event VoteSubmitted(bytes32 indexed proposalId, address indexed voter, bool support);
    event ConsensusReached(bytes32 indexed proposalId, bool approved, uint256 yesVotes, uint256 noVotes);
    event ValidatorSlashed(bytes32 indexed proposalId, address indexed challenger, uint256 amount, bool wasHonest);

    /**
     * @dev Initialize consensus process for a proposal
     * @param proposalId Unique proposal identifier
     * @param selectedValidators Array of validators selected for this proposal
     * @param challengePeriod Number of blocks for challenge period
     */
    function initializeConsensus(
        bytes32 proposalId, 
        address[] calldata selectedValidators,
        uint256 challengePeriod
    ) external;

    /**
     * @dev Challenge a proposal during challenge period
     * @param proposalId Proposal identifier
     * @param challenger Address initiating the challenge
     */
    function challengeProposal(bytes32 proposalId, address challenger) external;

    /**
     * @dev Submit a vote on a challenged proposal
     * @param proposalId Proposal identifier
     * @param voter Validator address
     * @param support Vote (true = approve, false = reject)
     * @param signature ECDSA signature of the vote
     */
    function submitVote(
        bytes32 proposalId, 
        address voter, 
        bool support, 
        bytes calldata signature
    ) external;

    /**
     * @dev Resolve consensus after voting period or challenge period expires
     * @param proposalId Proposal identifier
     * @return approved Whether the proposal was approved
     */
    function resolveConsensus(bytes32 proposalId) external returns (bool approved);

    /**
     * @dev Get current consensus state for a proposal
     * @param proposalId Proposal identifier
     * @return state Current consensus state
     * @return deadline Current deadline (challenge or voting)
     * @return yesVotes Number of yes votes
     * @return noVotes Number of no votes
     */
    function getConsensusState(bytes32 proposalId) 
        external 
        view 
        returns (
            ConsensusState state,
            uint256 deadline, 
            uint256 yesVotes, 
            uint256 noVotes
        );

    /**
     * @dev Check if a proposal can be challenged
     * @param proposalId Proposal identifier
     * @return canChallenge Whether challenge is possible
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool canChallenge);

    /**
     * @dev Check if proposal is in voting period
     * @param proposalId Proposal identifier
     * @return inVoting Whether voting is active
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool inVoting);

    /**
     * @dev Get challenge information
     * @param proposalId Proposal identifier
     * @return challenger Address that initiated challenge
     * @return challengeBlock Block when challenge was initiated
     */
    function getChallengeInfo(bytes32 proposalId) 
        external 
        view 
        returns (address challenger, uint256 challengeBlock);

    /**
     * @dev Get voters for a proposal
     * @param proposalId Proposal identifier
     * @return voters Array of addresses that voted
     */
    function getVoters(bytes32 proposalId) external view returns (address[] memory voters);

    /**
     * @dev Get individual validator's vote
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return hasVoted Whether validator has voted
     * @return support Vote direction (true = yes, false = no)
     */
    function getValidatorVote(bytes32 proposalId, address validator) 
        external 
        view 
        returns (bool hasVoted, bool support);
} 