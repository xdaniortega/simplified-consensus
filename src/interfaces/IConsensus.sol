// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IConsensus
 * @notice Generic interface for consensus mechanisms
 * @dev This interface allows different consensus implementations (PoS, Authority, etc.)
 *      to be used interchangeably by the TransactionManager
 */
interface IConsensus {
    // ==================== STRUCTS ====================

    enum ProposalStatus {
        Proposed, // Proposal submitted, awaiting consensus
        OptimisticApproved, // LLM Optimistic approved
        Rejected, // Consensus reached - rejected
        Challenged, // Under dispute/challenge
        Finalized // Final state, no more changes

    }

    // ==================== CORE FUNCTIONS ====================

    /**
     * @dev Initialize consensus for a new proposal
     * @param proposalId Unique identifier for the proposal
     * @param transaction Transaction data
     * @param proposer Address that submitted the proposal
     */
    function initializeConsensus(bytes32 proposalId, string calldata transaction, address proposer) external;

    /**
     * @dev Finalize a consensus
     * @param proposalId Proposal identifier
     */
    function finalizeConsensus(bytes32 proposalId) external;

    // ==================== VALIDATOR FUNCTIONS ====================

    /**
     * @dev Get current validators for consensus
     * @return validators Array of validator addresses
     */
    function getValidators() external view returns (address[] memory validators);

    /**
     * @dev Get validator count
     * @return count Number of active validators
     */
    function getValidatorCount() external view returns (uint256 count);

    /**
     * @dev Get signature count for a proposal
     * @param proposalId Proposal identifier
     * @return count Number of signatures collected
     */
    function getSignatureCount(bytes32 proposalId) external view returns (uint256 count);

    /**
     * @dev Check if a proposal is initialized
     * @param proposalId Proposal identifier
     * @return initialized Whether the proposal is initialized
     */
    function isProposalInitialized(bytes32 proposalId) external view returns (bool initialized);

    /**
     * @dev Get signers for a proposal
     * @param proposalId Proposal identifier
     * @return signers Array of addresses that signed the proposal
     */
    function getProposalSigners(bytes32 proposalId) external view returns (address[] memory signers);

    // ==================== CHALLENGE/DISPUTE FUNCTIONS ====================

    /**
     * @dev Check if a proposal can be challenged
     * @param proposalId Proposal identifier
     * @return canChallenge Whether the proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool canChallenge);

    /**
     * @dev Submit a challenge against a proposal
     * @param proposalId Proposal identifier
     */
    function challengeProposal(bytes32 proposalId) external;

    /**
     * @dev Submit a vote on a challenged proposal (if supported)
     * @param proposalId Proposal identifier
     * @param voter Voter address
     * @param support Vote direction (true = approve, false = reject)
     * @param signature Vote signature (if required)
     */
    function submitVote(bytes32 proposalId, address voter, bool support, bytes calldata signature) external;

    // ==================== STATUS QUERY FUNCTIONS ====================

    /**
     * @dev Get current status of a proposal
     * @param proposalId Proposal identifier
     * @return status Current proposal status
     */
    function getProposalStatus(bytes32 proposalId) external view returns (ProposalStatus status);

    /**
     * @dev Check if proposal has an active dispute
     * @param proposalId Proposal identifier
     * @return hasDispute Whether the proposal has an active dispute
     */
    function hasActiveDispute(bytes32 proposalId) external view returns (bool hasDispute);

    // ==================== INFO FUNCTIONS ====================

    /**
     * @dev Get consensus type identifier
     * @return consensusType String identifier (e.g., "PoS", "Authority", "Hybrid")
     */
    function getConsensusType() external pure returns (string memory consensusType);

    /**
     * @dev Check if consensus supports challenges/disputes
     * @return disputesSupported Whether this consensus mechanism supports disputes
     */
    function supportsDisputes() external pure returns (bool disputesSupported);

    // ==================== CALLBACK FUNCTIONS ====================

    /**
     * @dev Callback function for dispute resolution
     * @param proposalId Proposal identifier
     * @param upheld Whether the dispute was upheld
     * @param challenger Address that challenged the proposal
     */
    function onDisputeResolved(bytes32 proposalId, bool upheld, address challenger) external;
}
