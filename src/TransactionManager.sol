// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces/ILLMOracle.sol";
import "./interfaces/IConsensus.sol";
import "./consensus/PoSConsensus.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title TransactionManager
 * @dev Simplified TransactionManager that delegates consensus to ConsensusManager,
 *  NOTE: Possible improvement:
 * - I would just store onchain the hash o the proposal, as we could ensure
 *   Data availability is guaranteed by the emission of `ProposalSubmitted` events
 * - This version is completely decoupled from voting/challenge logic
 */
contract TransactionManager is ReentrancyGuard {
    event ProposalSubmitted(bytes32 indexed proposalId, string transaction, address indexed submitter);
    event ProposalOptimisticallyApproved(bytes32 indexed proposalId);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event ProposalRejected(bytes32 indexed proposalId);
    event LLMValidationResult(bytes32 indexed proposalId, bool isValid);
    event ProposalStatusUpdated(bytes32 indexed proposalId, IConsensus.ProposalStatus newStatus);

    error InvalidConsensus();
    error InvalidLLMOracle();
    error EmptyTransaction();
    error ProposalAlreadyExists();
    error ProposalNotFound();
    error InvalidProposalState();

    struct Proposal {
        string transaction;
        address proposer;
        uint256 blockNumber;
        IConsensus.ProposalStatus status;
    }

    ILLMOracle public immutable llmOracle;
    IConsensus public immutable consensus;

    mapping(bytes32 => Proposal) public proposals;
    uint256 public proposalCount;

    modifier onlyConsensus() {
        if (msg.sender != address(consensus)) revert InvalidConsensus();
        _;
    }

    constructor(address _consensus, address _llmOracle) {
        if (_consensus == address(0)) revert InvalidConsensus();
        if (_llmOracle == address(0)) revert InvalidLLMOracle();

        consensus = IConsensus(_consensus);
        llmOracle = ILLMOracle(_llmOracle);
    }

    /**
     * @dev Submit a proposal for consensus
     * @param transaction Transaction string to be validated
     * @return proposalId Unique identifier for the proposal
     */
    function submitProposal(string calldata transaction) external nonReentrant returns (bytes32 proposalId) {
        if (bytes(transaction).length == 0) revert EmptyTransaction();

        proposalId = keccak256(abi.encodePacked(transaction, block.timestamp, msg.sender));
        if (bytes(proposals[proposalId].transaction).length != 0) revert ProposalAlreadyExists();

        proposals[proposalId] = Proposal({
            transaction: transaction,
            proposer: msg.sender,
            blockNumber: block.number,
            status: IConsensus.ProposalStatus.Proposed
        });

        // Perform LLM validation immediately, this could be async in a future version with a callback
        bool llmResult = llmOracle.validateTransaction(transaction);
        if (llmResult) {
            // If LLM approved, delegate to consensus mechanism
            consensus.initializeConsensus(proposalId, transaction, msg.sender);
            // Update the proposal status to optimistic approved
            proposals[proposalId].status = IConsensus.ProposalStatus.OptimisticApproved;
            emit ProposalOptimisticallyApproved(proposalId);
        } else {
            // LLM rejected - store as rejected
            proposals[proposalId].status = IConsensus.ProposalStatus.Rejected;
            emit ProposalRejected(proposalId);
        }

        proposalCount++;
        emit LLMValidationResult(proposalId, llmResult);
        emit ProposalSubmitted(proposalId, transaction, msg.sender);
        return proposalId;
    }

    function updateProposalStatus(bytes32 proposalId, IConsensus.ProposalStatus newStatus) external onlyConsensus {
        Proposal storage proposal = proposals[proposalId];
        if (bytes(proposal.transaction).length == 0) revert ProposalNotFound();
        proposal.status = newStatus;
        emit ProposalStatusUpdated(proposalId, newStatus);
    }

    // ==================== VIEW FUNCTIONS ====================

    /**
     * @dev Get proposal information
     * @param proposalId Proposal identifier
     * @return transaction Transaction string
     * @return proposer Proposal submitter
     * @return blockNumber Block number when submitted
     * @return status Current proposal status
     */
    function getProposal(
        bytes32 proposalId
    )
        external
        view
        returns (string memory transaction, address proposer, uint256 blockNumber, IConsensus.ProposalStatus status)
    {
        Proposal storage proposal = proposals[proposalId];

        return (proposal.transaction, proposal.proposer, proposal.blockNumber, proposal.status);
    }

    /**
     * @dev Check if proposal is approved (optimistically or finalized)
     * @param proposalId Proposal identifier
     * @return approved Whether the proposal is approved
     */
    function isProposalApproved(bytes32 proposalId) external view returns (bool) {
        IConsensus.ProposalStatus status = this.getProposalStatus(proposalId);
        return status == IConsensus.ProposalStatus.OptimisticApproved || status == IConsensus.ProposalStatus.Finalized;
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
        return consensus.getValidatorCount();
    }

    /**
     * @dev Get top validators currently selected for consensus
     * @return validators Array of top validator addresses
     */
    function getCurrentTopValidators() external view returns (address[] memory) {
        return consensus.getValidators();
    }

    // ==================== CONSENSUS DELEGATION ====================

    /**
     * @dev Check if a proposal can be challenged (delegates to consensus)
     * @param proposalId Proposal identifier
     * @return canChallenge Whether challenge is possible
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        return consensus.canChallengeProposal(proposalId);
    }

    /**
     * @dev Check if consensus supports disputes
     * @return supportsDisputes Whether the consensus mechanism supports disputes
     */
    function supportsDisputes() external view returns (bool) {
        return consensus.supportsDisputes();
    }

    /**
     * @dev Get the Consensus contract address
     * @return consensus Address of the Consensus contract
     */
    function getConsensus() external view returns (IConsensus) {
        return consensus;
    }

    /**
     * @dev Get the LLM Oracle address
     * @return oracle Address of the LLM Oracle contract
     */
    function getLLMOracle() external view returns (address) {
        return address(llmOracle);
    }

    /**
     * @dev Get current status of a proposal
     * @param proposalId Proposal identifier
     * @return status Current proposal status
     */
    function getProposalStatus(bytes32 proposalId) external view returns (IConsensus.ProposalStatus status) {
        Proposal storage proposal = proposals[proposalId];
        if (bytes(proposal.transaction).length == 0) revert ProposalNotFound();

        return proposal.status;
    }

    /**
     * @dev Get the consensus type
     * @return consensusType String identifier of the consensus type
     */
    function getConsensusType() external view returns (string memory) {
        return consensus.getConsensusType();
    }

    /**
     * @dev Get proposal block number
     * @param proposalId Proposal identifier
     * @return blockNumber Block number when proposal was submitted
     */
    function getProposalBlockNumber(bytes32 proposalId) external view returns (uint256 blockNumber) {
        Proposal storage proposal = proposals[proposalId];
        if (bytes(proposal.transaction).length == 0) revert ProposalNotFound();
        return proposal.blockNumber;
    }
}
