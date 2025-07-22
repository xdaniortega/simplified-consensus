// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IConsensus.sol";

/**
 * @title ITransactionManager
 * @notice Interface for TransactionManager contract
 */
interface ITransactionManager {
    /**
     * @dev Update proposal status (called by consensus contracts)
     */
    function updateProposalStatus(bytes32 proposalId, IConsensus.ProposalStatus newStatus) external;

    /**
     * @dev Get proposal status
     */
    function getProposalStatus(bytes32 proposalId) external view returns (IConsensus.ProposalStatus status);

    /**
     * @dev Get proposal block number
     */
    function getProposalBlockNumber(bytes32 proposalId) external view returns (uint256 blockNumber);
}
