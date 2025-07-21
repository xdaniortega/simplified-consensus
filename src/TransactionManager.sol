// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ValidatorFactory.sol";
import "./interfaces/ILLMOracle.sol";

/**
 * @title TransactionManager
 * @dev Optimistic consensus system with LLM validation and validator signatures
 * Features:
 * - Transaction proposal with optimistic execution
 * - External LLM Oracle for validation
 * - ECDSA signature verification with 3/5 consensus
 * - Challenge period for disputes
 * - Dispute resolution with validator voting
 * - Slashing mechanism for false challenges
 */
contract TransactionManager {
    event ProposalSubmitted(bytes32 indexed proposalId, string transaction, address indexed submitter);
    event ProposalOptimisticallyApproved(bytes32 indexed proposalId);
    event ProposalChallenged(bytes32 indexed proposalId, address indexed challenger);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);
    event ValidatorSigned(bytes32 indexed proposalId, address indexed validator);
    event LLMValidationResult(bytes32 indexed proposalId, bool isValid);
    event VoteSubmitted(bytes32 indexed proposalId, address indexed validator, bool support);
    event ChallengeResolved(bytes32 indexed proposalId, bool approved, uint256 yesVotes, uint256 noVotes);
    event ValidatorSlashed(bytes32 indexed proposalId, address indexed challenger, uint256 amount, bool wasHonest);

    error InvalidValidatorFactory();
    error InvalidLLMOracle();
    error EmptyTransaction();
    error ProposalAlreadyExists();
    error ChallengePeriodExpired();
    error NotEnoughValidators();
    error NotAValidator();
    error AlreadyVoted();
    error InvalidSignature();
    error ChallengePeriodNotEnded();
    error UseResolveChallengeForVotingProposals();
    error InvalidProposalStateForFinalization();
    error VotingPeriodNotEnded();
    error InvalidProposalState();
    error ProposalNotFound();
    error NotASelectedValidator();
    error AlreadySigned();
    error VotingPeriodExpired();
    error NotInVotingPeriod();
    error InvalidSignatureLength();
    error InvalidSignatureV();

    ValidatorFactory public validatorFactory;
    ILLMOracle public llmOracle;

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    mapping(bytes32 => mapping(address => bool)) public hasValidatorVoted;
    mapping(bytes32 => mapping(address => bool)) public validatorVotes; // true = yes, false = no
    mapping(bytes32 => address[]) public proposalSigners;
    mapping(bytes32 => address[]) public proposalVoters;
    uint256 public proposalCount;

    uint256 public constant CHALLENGE_PERIOD = 10; // blocks - as per requirement
    uint256 public constant VOTING_PERIOD = 30; // blocks for voting after challenge
    uint256 public constant REQUIRED_SIGNATURES = 3; // 3 out of 5 validators
    uint256 public constant VALIDATOR_SET_SIZE = 5; // top 5 validators for consensus
    uint256 public constant SLASH_PERCENTAGE = 10; // 10% slash for false challenges

    enum ProposalState {
        Proposed, // Just submitted
        OptimisticApproved, // Enough signatures, optimistically approved
        Challenged, // Someone challenged the proposal
        Voting, // In voting period after challenge
        Finalized, // Final decision made
        Reverted // Proposal was invalid/rejected
    }

    struct Proposal {
        bytes32 proposalId;
        string transaction;
        address proposer;
        uint256 blockNumber;
        uint256 challengeDeadline;
        uint256 votingDeadline;
        ProposalState state;
        address challenger;
        uint256 signatureCount;
        uint256 yesVotes;
        uint256 noVotes;
        bool llmValidation;
        bool executed;
        address[] selectedValidators; // validators selected for this proposal
    }

    constructor(address _validatorFactory, address _llmOracle) {
        if (_validatorFactory == address(0)) revert InvalidValidatorFactory();
        if (_llmOracle == address(0)) revert InvalidLLMOracle();

        validatorFactory = ValidatorFactory(_validatorFactory);
        llmOracle = ILLMOracle(_llmOracle);
    }

    /**
     * @dev Submit a proposal for consensus
     * @param transaction Transaction string to be validated (e.g., "Approve loan for user X based on LLM analysis")
     * @return proposalId Unique identifier for the proposal
     */
    function submitProposal(string calldata transaction) external returns (bytes32 proposalId) {
        if (bytes(transaction).length == 0) revert EmptyTransaction();

        proposalId = keccak256(abi.encodePacked(transaction, block.timestamp, msg.sender));
        if (proposals[proposalId].proposalId != bytes32(0)) revert ProposalAlreadyExists();

        // Get top validators for this proposal
        address[] memory topValidators = _getTopValidators();
        if (topValidators.length < REQUIRED_SIGNATURES) revert NotEnoughValidators();

        // Perform LLM validation using external oracle
        bool llmResult = llmOracle.validateTransaction(transaction);

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            transaction: transaction,
            proposer: msg.sender,
            blockNumber: block.number,
            state: ProposalState.Proposed,
            challengeDeadline: block.number + CHALLENGE_PERIOD,
            votingDeadline: 0,
            challenger: address(0),
            signatureCount: 0,
            yesVotes: 0,
            noVotes: 0,
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
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Proposed) revert InvalidProposalState();
        if (block.number > proposal.challengeDeadline) revert ChallengePeriodExpired();
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
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.OptimisticApproved) revert InvalidProposalState();
        if (block.number > proposal.challengeDeadline) revert ChallengePeriodExpired();
        if (!validatorFactory.isActiveValidator(msg.sender)) revert NotAValidator();

        proposal.state = ProposalState.Voting;
        proposal.challenger = msg.sender;
        proposal.executed = false; // Revert optimistic execution
        proposal.votingDeadline = block.number + VOTING_PERIOD;

        emit ProposalChallenged(proposalId, msg.sender);
    }

    /**
     * @dev Submit a vote on a challenged proposal
     * @param proposalId Proposal identifier
     * @param support true for yes (approve), false for no (reject)
     * @param signature ECDSA signature of the vote
     */
    function submitVote(bytes32 proposalId, bool support, bytes calldata signature) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Voting) revert InvalidProposalState();
        if (block.number > proposal.votingDeadline) revert VotingPeriodExpired();
        if (!validatorFactory.isActiveValidator(msg.sender)) revert NotAValidator();
        if (hasValidatorVoted[proposalId][msg.sender]) revert AlreadyVoted();

        // Verify the vote signature
        bytes32 voteHash = _getVoteHash(proposalId, support);
        address recoveredSigner = _recoverSigner(voteHash, signature);
        if (recoveredSigner != msg.sender) revert InvalidSignature();

        // Record the vote
        hasValidatorVoted[proposalId][msg.sender] = true;
        validatorVotes[proposalId][msg.sender] = support;
        proposalVoters[proposalId].push(msg.sender);

        if (support) {
            proposal.yesVotes++;
        } else {
            proposal.noVotes++;
        }

        emit VoteSubmitted(proposalId, msg.sender, support);
    }

    /**
     * @dev Resolve a challenge after voting period ends
     * @param proposalId Proposal identifier
     */
    function resolveChallenge(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Voting) revert InvalidProposalState();
        if (block.number <= proposal.votingDeadline) revert VotingPeriodNotEnded();

        uint256 totalVotes = proposal.yesVotes + proposal.noVotes;
        bool approved = false;

        if (totalVotes > 0) {
            // Majority decides - if >=50% vote no, reject the proposal
            uint256 rejectionThreshold = (totalVotes + 1) / 2; // Ceiling division for >=50%
            approved = proposal.noVotes < rejectionThreshold;
        } else {
            // No votes cast - default to original decision (signatures + LLM)
            approved = proposal.signatureCount >= REQUIRED_SIGNATURES && proposal.llmValidation;
        }

        // Determine if challenge was honest or false
        bool challengeWasHonest = !approved; // Challenge was honest if proposal was ultimately rejected

        // Handle slashing
        _handleSlashing(proposalId, proposal.challenger, challengeWasHonest);

        // Update proposal state
        proposal.state = approved ? ProposalState.Finalized : ProposalState.Reverted;
        proposal.executed = approved;

        emit ChallengeResolved(proposalId, approved, proposal.yesVotes, proposal.noVotes);
        emit ProposalFinalized(proposalId, approved);
    }

    /**
     * @dev Finalize a proposal after challenge period or after challenge resolution
     * @param proposalId Proposal identifier
     */
    function finalizeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();

        bool approved = false;

        if (proposal.state == ProposalState.OptimisticApproved) {
            if (block.number <= proposal.challengeDeadline) revert ChallengePeriodNotEnded();
            // No challenge during period - approve
            approved = true;
            proposal.executed = true;
            proposal.state = ProposalState.Finalized;
        } else if (proposal.state == ProposalState.Voting) {
            // Should use resolveChallenge instead
            revert UseResolveChallengeForVotingProposals();
        } else {
            revert InvalidProposalStateForFinalization();
        }

        emit ProposalFinalized(proposalId, approved);
    }

    /**
     * @dev Handle slashing for challenge resolution
     * @param proposalId Proposal identifier
     * @param challenger Address of the challenger
     * @param wasHonest Whether the challenge was honest
     */
    function _handleSlashing(bytes32 proposalId, address challenger, bool wasHonest) internal {
        if (!wasHonest) {
            // False challenge - slash challenger's stake
            uint256 challengerStake = validatorFactory.getValidatorStake(challenger);
            if (challengerStake > 0) {
                uint256 slashAmount = (challengerStake * SLASH_PERCENTAGE) / 100;
                // Actually perform the slashing
                validatorFactory.slashValidator(challenger, slashAmount, "False challenge");
                emit ValidatorSlashed(proposalId, challenger, slashAmount, false);
            }
        } else {
            // Honest challenge - no slashing needed
            emit ValidatorSlashed(proposalId, challenger, 0, true);
        }
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
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    keccak256(abi.encodePacked(proposalId, transaction))
                )
            );
    }

    /**
     * @dev Create vote hash for signature verification
     * @param proposalId Proposal identifier
     * @param support Vote (true for yes, false for no)
     * @return hash Vote hash for signing
     */
    function _getVoteHash(bytes32 proposalId, bool support) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
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

    // Struct for returning proposal info (reduces stack depth)
    struct ProposalInfo {
        string transaction;
        address proposer;
        uint256 blockNumber;
        ProposalState state;
        uint256 challengeDeadline;
        uint256 votingDeadline;
        address challenger;
        uint256 signatureCount;
        uint256 yesVotes;
        uint256 noVotes;
        bool llmValidation;
        bool executed;
    }

    /**
     * @dev Get proposal information (backward compatible)
     * @param proposalId Proposal identifier
     * @return transaction Transaction string
     * @return proposer Proposal submitter
     * @return blockNumber Block number when submitted
     * @return state Current proposal state
     * @return challengeDeadline Challenge deadline
     * @return votingDeadline Voting deadline (if in voting)
     * @return challenger Address of challenger
     * @return signatureCount Number of validator signatures
     * @return yesVotes Number of yes votes
     * @return noVotes Number of no votes
     * @return llmValidation LLM validation result
     * @return executed Whether proposal was executed
     */
    function getProposal(
        bytes32 proposalId
    )
        external
        view
        returns (
            string memory transaction,
            address proposer,
            uint256 blockNumber,
            ProposalState state,
            uint256 challengeDeadline,
            uint256 votingDeadline,
            address challenger,
            uint256 signatureCount,
            uint256 yesVotes,
            uint256 noVotes,
            bool llmValidation,
            bool executed
        )
    {
        Proposal storage proposal = proposals[proposalId];
        return (
            proposal.transaction,
            proposal.proposer,
            proposal.blockNumber,
            proposal.state,
            proposal.challengeDeadline,
            proposal.votingDeadline,
            proposal.challenger,
            proposal.signatureCount,
            proposal.yesVotes,
            proposal.noVotes,
            proposal.llmValidation,
            proposal.executed
        );
    }

    /**
     * @dev Get proposal information as struct (stack optimized)
     * @param proposalId Proposal identifier
     * @return info Complete proposal information
     */
    function getProposalStruct(bytes32 proposalId) external view returns (ProposalInfo memory info) {
        Proposal storage proposal = proposals[proposalId];
        info.transaction = proposal.transaction;
        info.proposer = proposal.proposer;
        info.blockNumber = proposal.blockNumber;
        info.state = proposal.state;
        info.challengeDeadline = proposal.challengeDeadline;
        info.votingDeadline = proposal.votingDeadline;
        info.challenger = proposal.challenger;
        info.signatureCount = proposal.signatureCount;
        info.yesVotes = proposal.yesVotes;
        info.noVotes = proposal.noVotes;
        info.llmValidation = proposal.llmValidation;
        info.executed = proposal.executed;
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
     * @dev Get voters for a proposal
     * @param proposalId Proposal identifier
     * @return voters Array of addresses that voted on the proposal
     */
    function getProposalVoters(bytes32 proposalId) external view returns (address[] memory) {
        return proposalVoters[proposalId];
    }

    /**
     * @dev Get a validator's vote on a proposal
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return hasVoted Whether the validator voted
     * @return vote The vote (true for yes, false for no)
     */
    function getValidatorVote(bytes32 proposalId, address validator) external view returns (bool hasVoted, bool vote) {
        hasVoted = hasValidatorVoted[proposalId][validator];
        vote = validatorVotes[proposalId][validator];
    }

    /**
     * @dev Check if proposal is approved and executed
     * @param proposalId Proposal identifier
     * @return approved Whether the proposal is approved and executed
     */
    function isProposalApproved(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return
            proposal.state == ProposalState.OptimisticApproved ||
            (proposal.state == ProposalState.Finalized && proposal.executed);
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

    /**
     * @dev Check if a proposal can be challenged
     * @param proposalId Proposal identifier
     * @return canChallenge Whether the proposal can be challenged
     */
    function canChallengeProposal(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.state == ProposalState.OptimisticApproved && block.number <= proposal.challengeDeadline;
    }

    /**
     * @dev Check if a proposal is in voting period
     * @param proposalId Proposal identifier
     * @return inVoting Whether the proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.state == ProposalState.Voting && block.number <= proposal.votingDeadline;
    }

    /**
     * @dev Get the LLM Oracle address
     * @return oracle Address of the LLM Oracle contract
     */
    function getLLMOracle() external view returns (address) {
        return address(llmOracle);
    }

    /**
     * @dev Get the LLM Oracle type/version
     * @return oracleType String identifying the oracle type
     */
    function getLLMOracleType() external view returns (string memory) {
        return llmOracle.getOracleType();
    }
}
