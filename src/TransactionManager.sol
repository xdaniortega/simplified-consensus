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
    error UseSignProposalToFinalize();

    ValidatorFactory public validatorFactory;
    ILLMOracle public llmOracle;

    // Optimized voting data structure
    struct VoteData {
        uint8 yesVotes; // Count of yes votes (max 5 validators)
        uint8 noVotes; // Count of no votes (max 5 validators)
        uint8 votersBitmap; // Bitmap: bit i set if validator i voted
        uint8 votesBitmap; // Bitmap: bit i set if validator i voted YES
    }

    mapping(bytes32 => Proposal) public proposals;
    mapping(bytes32 => ChallengeData) public challengeData;
    mapping(bytes32 => VoteData) public proposalVotes; // Optimized vote storage
    mapping(bytes32 => mapping(address => bool)) public hasValidatorSigned;
    mapping(bytes32 => address[]) public proposalSigners;
    uint256 public proposalCount;

    uint256 public constant CHALLENGE_PERIOD = 10; // blocks - as per requirement
    uint256 public constant VOTING_PERIOD = 30; // blocks for voting after challenge
    uint256 public constant REQUIRED_SIGNATURES = 3; // 3 out of 5 validators
    uint256 public constant VALIDATOR_SET_SIZE = 5; // top 5 validators for consensus
    uint256 public constant SLASH_PERCENTAGE = 10; // 10% slash for false challenges

    enum ProposalState {
        Proposed,           // Just submitted, awaiting LLM validation
        OptimisticApproved, // LLM approved, in challenge period
        Challenged,         // Challenge initiated, voting in progress
        Finalized,          // Approved and executed
        Rejected            // Rejected by LLM or challenge voting
    }

    // Core proposal data - optimized structure
    struct Proposal {
        bytes32 proposalId;
        string transaction;
        address proposer;
        uint256 blockNumber;
        ProposalState state;
        uint256 deadline;              // Universal deadline (challenge or voting)
        uint8 signatureCount;          // Number of validator signatures (max 5)
        address[] selectedValidators;  // Validators selected for this proposal
    }

    // Challenge-specific data - separated for modularity
    struct ChallengeData {
        address challenger;
        uint256 challengeBlock;
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
     * @dev NOTE: For async Oracle validation, we could use a callback function to update the proposal state.
     * @return proposalId Unique identifier for the proposal
     */
    function submitProposal(string calldata transaction) external returns (bytes32 proposalId) {
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
        uint256 deadline = llmResult ? block.number + CHALLENGE_PERIOD : 0;

        proposals[proposalId] = Proposal({
            proposalId: proposalId,
            transaction: transaction,
            proposer: msg.sender,
            blockNumber: block.number,
            state: initialState,
            deadline: deadline,
            signatureCount: 0,
            selectedValidators: topValidators
        });

        proposalCount++;

        emit ProposalSubmitted(proposalId, transaction, msg.sender);
        emit LLMValidationResult(proposalId, llmResult);

        return proposalId;
    }

    /**
     * @dev Validators sign a proposal using ECDSA signatures to finalize it
     * @param proposalId Proposal identifier
     * @param signature ECDSA signature of the proposal hash
     */
    function signProposal(bytes32 proposalId, bytes calldata signature) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.OptimisticApproved) revert InvalidProposalState();
        if (block.number > proposal.deadline) revert ChallengePeriodExpired();
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
     * @dev Challenge a proposal during the challenge period
     * @param proposalId Proposal identifier
     */
    function challengeProposal(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.OptimisticApproved) revert InvalidProposalState();
        if (block.number > proposal.deadline) revert ChallengePeriodExpired();
        if (!validatorFactory.isActiveValidator(msg.sender)) revert NotAValidator();

        // Set proposal to challenged state with voting deadline
        proposal.state = ProposalState.Challenged;
        proposal.deadline = block.number + VOTING_PERIOD;
        
        // Store challenge data separately
        challengeData[proposalId] = ChallengeData({
            challenger: msg.sender,
            challengeBlock: block.number
        });

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
        if (proposal.state != ProposalState.Challenged) revert InvalidProposalState();
        if (block.number > proposal.deadline) revert VotingPeriodExpired();
        if (!validatorFactory.isActiveValidator(msg.sender)) revert NotAValidator();
        if (_hasValidatorVoted(proposalId, msg.sender)) revert AlreadyVoted();

        // Verify the vote signature
        bytes32 voteHash = _getVoteHash(proposalId, support);
        address recoveredSigner = _recoverSigner(voteHash, signature);
        if (recoveredSigner != msg.sender) revert InvalidSignature();

        // Record the vote using optimized bitmap
        _recordVote(proposalId, msg.sender, support);

        emit VoteSubmitted(proposalId, msg.sender, support);
    }

    /**
     * @dev Resolve a challenge after voting period ends
     * @param proposalId Proposal identifier
     */
    function resolveChallenge(bytes32 proposalId) external {
        Proposal storage proposal = proposals[proposalId];
        if (proposal.proposalId == bytes32(0)) revert ProposalNotFound();
        if (proposal.state != ProposalState.Challenged) revert InvalidProposalState();
        if (block.number <= proposal.deadline) revert VotingPeriodNotEnded();

        VoteData memory votes = proposalVotes[proposalId];
        ChallengeData memory challenge = challengeData[proposalId];
        uint256 totalVotes = votes.yesVotes + votes.noVotes;
        bool approved = false;

        if (totalVotes > 0) {
            // Majority decides - if >=50% vote no, reject the proposal
            uint256 rejectionThreshold = (totalVotes + 1) / 2; // Ceiling division for >=50%
            approved = votes.noVotes < rejectionThreshold;
        } else {
            // No votes cast - default to original LLM decision (was already OptimisticApproved)
            approved = true;
        }

        // Determine if challenge was honest or false
        bool challengeWasHonest = !approved; // Challenge was honest if proposal was ultimately rejected

        // Handle slashing
        _handleSlashing(proposalId, challenge.challenger, challengeWasHonest);

        // Update proposal state
        proposal.state = approved ? ProposalState.Finalized : ProposalState.Rejected;

        emit ChallengeResolved(proposalId, approved, votes.yesVotes, votes.noVotes);
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
            // Check if challenge period has ended
            if (block.number <= proposal.deadline) revert ChallengePeriodNotEnded();
            // No challenge during period - but still need validator signatures for finalization
            // This function just expires the challenge period, validators still need to sign
            // Proposal remains in OptimisticApproved state waiting for signatures
            revert UseSignProposalToFinalize();
        } else if (proposal.state == ProposalState.Challenged) {
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
     * @dev Get validator index in the selected validators array for a proposal
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return index Validator index (0-4), reverts if not found
     */
    function _getValidatorIndex(bytes32 proposalId, address validator) public view returns (uint8 index) {
        address[] memory selectedValidators = proposals[proposalId].selectedValidators;
        for (uint8 i = 0; i < selectedValidators.length; i++) {
            if (selectedValidators[i] == validator) {
                return i;
            }
        }
        revert NotASelectedValidator();
    }

    /**
     * @dev Check if validator has voted using bitmap
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return hasVoted Whether validator has voted
     */
    function _hasValidatorVoted(bytes32 proposalId, address validator) internal view returns (bool hasVoted) {
        uint8 index = _getValidatorIndex(proposalId, validator);
        uint8 votersBitmap = proposalVotes[proposalId].votersBitmap;
        return (votersBitmap >> index) & 1 == 1;
    }

    /**
     * @dev Get validator vote using bitmap
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return support Vote (true = yes, false = no)
     */
    function _getValidatorVote(bytes32 proposalId, address validator) internal view returns (bool support) {
        uint8 index = _getValidatorIndex(proposalId, validator);
        uint8 votesBitmap = proposalVotes[proposalId].votesBitmap;
        return (votesBitmap >> index) & 1 == 1;
    }

    /**
     * @dev Record validator vote using bitmaps
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @param support Vote (true = yes, false = no)
     */
    function _recordVote(bytes32 proposalId, address validator, bool support) internal {
        uint8 index = _getValidatorIndex(proposalId, validator);
        VoteData storage votes = proposalVotes[proposalId];

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
        VoteData memory votes = proposalVotes[proposalId];
        ChallengeData memory challenge = challengeData[proposalId];
        
        // Map deadline based on state
        uint256 challengeDeadline_ = (proposal.state == ProposalState.OptimisticApproved) ? proposal.deadline : 0;
        uint256 votingDeadline_ = (proposal.state == ProposalState.Challenged) ? proposal.deadline : 0;
        
        // Derive execution status from state
        bool executed_ = (proposal.state == ProposalState.Finalized);
        // Derive LLM validation from state (if OptimisticApproved or Finalized, LLM said yes)
        bool llmValidation_ = (proposal.state != ProposalState.Rejected);
        
        return (
            proposal.transaction,
            proposal.proposer,
            proposal.blockNumber,
            proposal.state,
            challengeDeadline_,
            votingDeadline_,
            challenge.challenger,
            proposal.signatureCount,
            votes.yesVotes,
            votes.noVotes,
            llmValidation_,
            executed_
        );
    }

    /**
     * @dev Get proposal information as struct (stack optimized)
     * @param proposalId Proposal identifier
     * @return info Complete proposal information
     */
    function getProposalStruct(bytes32 proposalId) external view returns (ProposalInfo memory info) {
        Proposal storage proposal = proposals[proposalId];
        VoteData memory votes = proposalVotes[proposalId];
        ChallengeData memory challenge = challengeData[proposalId];
        
        // Map deadline based on state
        uint256 challengeDeadline_ = (proposal.state == ProposalState.OptimisticApproved) ? proposal.deadline : 0;
        uint256 votingDeadline_ = (proposal.state == ProposalState.Challenged) ? proposal.deadline : 0;
        
        // Derive execution status from state
        bool executed_ = (proposal.state == ProposalState.Finalized);
        // Derive LLM validation from state (if OptimisticApproved or Finalized, LLM said yes)
        bool llmValidation_ = (proposal.state != ProposalState.Rejected);
        
        info.transaction = proposal.transaction;
        info.proposer = proposal.proposer;
        info.blockNumber = proposal.blockNumber;
        info.state = proposal.state;
        info.challengeDeadline = challengeDeadline_;
        info.votingDeadline = votingDeadline_;
        info.challenger = challenge.challenger;
        info.signatureCount = proposal.signatureCount;
        info.yesVotes = votes.yesVotes;
        info.noVotes = votes.noVotes;
        info.llmValidation = llmValidation_;
        info.executed = executed_;
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
    function getProposalVoters(bytes32 proposalId) external view returns (address[] memory voters) {
        address[] memory selectedValidators = proposals[proposalId].selectedValidators;
        uint8 votersBitmap = proposalVotes[proposalId].votersBitmap;

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
     * @dev Get a validator's vote on a proposal
     * @param proposalId Proposal identifier
     * @param validator Validator address
     * @return hasVoted Whether the validator voted
     * @return vote The vote (true for yes, false for no)
     */
    function getValidatorVote(bytes32 proposalId, address validator) external view returns (bool hasVoted, bool vote) {
        // Check if validator is in selected validators (will revert if not found)
        try this._getValidatorIndex(proposalId, validator) returns (uint8 index) {
            uint8 votersBitmap = proposalVotes[proposalId].votersBitmap;
            uint8 votesBitmap = proposalVotes[proposalId].votesBitmap;
            hasVoted = (votersBitmap >> index) & 1 == 1;
            vote = (votesBitmap >> index) & 1 == 1;
        } catch {
            // Validator not selected for this proposal
            hasVoted = false;
            vote = false;
        }
    }

    /**
     * @dev Check if proposal is approved and executed
     * @param proposalId Proposal identifier
     * @return approved Whether the proposal is approved and executed
     */
    function isProposalApproved(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.state == ProposalState.Finalized;
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
        return proposal.state == ProposalState.OptimisticApproved && block.number <= proposal.deadline;
    }

    /**
     * @dev Check if a proposal is in voting period
     * @param proposalId Proposal identifier
     * @return inVoting Whether the proposal is in voting period
     */
    function isInVotingPeriod(bytes32 proposalId) external view returns (bool) {
        Proposal storage proposal = proposals[proposalId];
        return proposal.state == ProposalState.Challenged && block.number <= proposal.deadline;
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
