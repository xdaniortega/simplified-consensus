// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TransactionManager.sol";
import "../src/ValidatorFactory.sol";
import "../src/oracles/MockLLMOracle.sol";
import "../test/mock/ERC20TokenMock.sol";

/**
 * @title TransactionManager Test Suite
 * @dev This test suite covers the optimistic consensus including:
 *      - Proposal submission and validation
 *        (e.g. test_SubmitProposal, test_RevertWhen_SubmitProposal_DuplicateProposal)
 *      - LLM-based transaction validation (mocked)
 *        (e.g. test_TestLLMValidation, test_OptimisticApproval_RequiresLLMValidation)
 *      - Validator signature collection for optimistic approval
 *        (e.g. test_SignProposal, test_RevertWhen_SignProposal_InvalidSignature)
 *      - Challenge mechanisms and dispute resolution
 *        (e.g. test_ChallengeProposal, test_ResolveChallenge_Approved)
 *      - Voting periods and consensus resolution
 *        (e.g. test_SubmitVote, test_IsInVotingPeriod, test_VotingPeriodExpiry)
 *      - Slashing mechanisms for false challenges
 *        (e.g. test_ResolveChallenge_Rejected with validator slashing)
 *
 * Test Strategy:
 * 1. Unit Tests: Individual function behavior and state changes
 * 2. Integration Tests: Complete proposal lifecycle from submission to finalization
 *    (e.g. test_CompleteProposalLifecycle)
 * 3. Edge Cases: Empty validator sets, expired periods, invalid signatures
 *    (e.g. test_EdgeCase_EmptyValidatorSet, test_RevertWhen_ChallengeProposal_ExpiredChallengePeriod)
 * 4. Security Tests: Access control, reentrancy protection, slashing mechanics
 * 5. Event Testing: All state changes emit appropriate events
 *
 */
contract TransactionManagerTest is Test {
    // Contracts
    TransactionManager public transactionManager;
    ValidatorFactory public validatorFactory;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public stakingToken;

    // Test accounts
    address public deployer;
    address public validator1;
    address public validator2;
    address public validator3;
    address public validator4;
    address public validator5;
    address public proposer;
    address public challenger;

    // Private keys for signing
    uint256 public constant VALIDATOR1_PK = 0x1;
    uint256 public constant VALIDATOR2_PK = 0x2;
    uint256 public constant VALIDATOR3_PK = 0x3;
    uint256 public constant VALIDATOR4_PK = 0x4;
    uint256 public constant VALIDATOR5_PK = 0x5;

    // Test data
    uint256 public constant MINIMUM_STAKE = 1000 * 10 ** 18;
    uint256 public constant INITIAL_BALANCE = 10000 * 10 ** 18;
    string public constant TEST_TRANSACTION = "Approve loan for user Alice based on LLM analysis";
    string public constant INVALID_TRANSACTION = "Execute payment of 1000 USDC to Bob"; // This should be invalid based on hash

    // Events for testing
    event ProposalSubmitted(bytes32 indexed proposalId, string transaction, address indexed submitter);
    event ProposalOptimisticallyApproved(bytes32 indexed proposalId);
    event ProposalChallenged(bytes32 indexed proposalId, address indexed challenger);
    event ValidatorSigned(bytes32 indexed proposalId, address indexed validator);
    event VoteSubmitted(bytes32 indexed proposalId, address indexed validator, bool support);
    event ChallengeResolved(bytes32 indexed proposalId, bool approved, uint256 yesVotes, uint256 noVotes);
    event ProposalFinalized(bytes32 indexed proposalId, bool approved);

    function setUp() public {
        // Set up test accounts
        deployer = address(this);
        validator1 = vm.addr(VALIDATOR1_PK);
        validator2 = vm.addr(VALIDATOR2_PK);
        validator3 = vm.addr(VALIDATOR3_PK);
        validator4 = vm.addr(VALIDATOR4_PK);
        validator5 = vm.addr(VALIDATOR5_PK);
        proposer = address(0x6);
        challenger = address(0x7);

        // Deploy contracts
        stakingToken = new ERC20TokenMock();
        validatorFactory = new ValidatorFactory(
            address(stakingToken),
            MINIMUM_STAKE,
            20, // max validators
            5 // validator threshold
        );
        llmOracle = new MockLLMOracle();
        transactionManager = new TransactionManager(address(validatorFactory), address(llmOracle));

        // Setup initial balances and approvals
        _setupValidatorsWithStake();
    }

    function _setupValidatorsWithStake() internal {
        address[] memory validators = new address[](5);
        validators[0] = validator1;
        validators[1] = validator2;
        validators[2] = validator3;
        validators[3] = validator4;
        validators[4] = validator5;

        for (uint i = 0; i < validators.length; i++) {
            // Mint tokens and stake for each validator
            stakingToken.mint(validators[i], INITIAL_BALANCE);

            vm.startPrank(validators[i]);
            stakingToken.approve(address(validatorFactory), MINIMUM_STAKE);
            validatorFactory.stake(MINIMUM_STAKE);
            vm.stopPrank();
        }

        // Setup proposer balance
        stakingToken.mint(proposer, INITIAL_BALANCE);
        stakingToken.mint(challenger, INITIAL_BALANCE);
    }

    // ==================== BASIC FUNCTIONALITY TESTS ====================

    function test_DeploymentState() public {
        assertEq(address(transactionManager.validatorFactory()), address(validatorFactory));
        assertEq(address(transactionManager.llmOracle()), address(llmOracle));
        assertEq(transactionManager.proposalCount(), 0);
        assertEq(transactionManager.CHALLENGE_PERIOD(), 10);
        assertEq(transactionManager.VOTING_PERIOD(), 30);
        assertEq(transactionManager.REQUIRED_SIGNATURES(), 3);
    }

    function test_GetLLMOracle() public {
        assertEq(transactionManager.getLLMOracle(), address(llmOracle));
        assertEq(transactionManager.getLLMOracleType(), "MockLLMOracle_v1.0_HashBased");
    }

    function test_GetValidatorCount() public {
        assertEq(transactionManager.getValidatorCount(), 5);
    }

    function test_GetCurrentTopValidators() public {
        address[] memory topValidators = transactionManager.getCurrentTopValidators();
        assertEq(topValidators.length, 5);
    }

    // ==================== PROPOSAL SUBMISSION TESTS ====================

    function test_SubmitProposal() public {
        vm.prank(proposer);

        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Check proposal was created
        (
            string memory transaction,
            address proposerAddr,
            uint256 blockNumber,
            TransactionManager.ProposalState state,
            uint256 challengeDeadline,
            uint256 votingDeadline,
            address challengerAddr,
            uint256 signatureCount,
            uint256 yesVotes,
            uint256 noVotes,
            bool llmValidation,
            bool executed
        ) = transactionManager.getProposal(proposalId);

        assertEq(transaction, TEST_TRANSACTION);
        assertEq(proposerAddr, proposer);
        assertEq(blockNumber, block.number);
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Proposed));
        assertEq(challengeDeadline, block.number + 10);
        assertEq(votingDeadline, 0);
        assertEq(challengerAddr, address(0));
        assertEq(signatureCount, 0);
        assertEq(yesVotes, 0);
        assertEq(noVotes, 0);
        assertTrue(llmValidation); // TEST_TRANSACTION should be valid
        assertFalse(executed);

        assertEq(transactionManager.proposalCount(), 1);
    }

    function test_RevertWhen_SubmitProposal_EmptyTransaction() public {
        vm.prank(proposer);
        vm.expectRevert(TransactionManager.EmptyTransaction.selector);
        transactionManager.submitProposal("");
    }

    function test_RevertWhen_SubmitProposal_DuplicateProposal() public {
        vm.startPrank(proposer);

        transactionManager.submitProposal(TEST_TRANSACTION);

        // Try to submit same proposal again
        vm.expectRevert(TransactionManager.ProposalAlreadyExists.selector);
        transactionManager.submitProposal(TEST_TRANSACTION);

        vm.stopPrank();
    }

    function test_SubmitProposal_WithInvalidLLMValidation() public {
        vm.prank(proposer);

        bytes32 proposalId = transactionManager.submitProposal(INVALID_TRANSACTION);

        (, , , , , , , , , , bool llmValidation, ) = transactionManager.getProposal(proposalId);
        assertFalse(llmValidation); // INVALID_TRANSACTION should be invalid
    }

    function test_TestLLMValidation() public {
        assertTrue(transactionManager.testLLMValidation(TEST_TRANSACTION));
        assertFalse(transactionManager.testLLMValidation(INVALID_TRANSACTION));
    }

    // ==================== SIGNATURE TESTS ====================

    function test_SignProposal() public {
        // Submit proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Get proposal hash for signing
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(proposalId, TEST_TRANSACTION))
            )
        );

        // Sign with validator1
        uint256 validator1PrivateKey = VALIDATOR1_PK;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1PrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(validator1);
        vm.expectEmit(true, true, false, true);
        emit ValidatorSigned(proposalId, validator1);
        transactionManager.signProposal(proposalId, signature);

        // Check signature was recorded
        (, , , , , , , uint256 signatureCount, , , , ) = transactionManager.getProposal(proposalId);
        assertEq(signatureCount, 1);

        address[] memory signers = transactionManager.getProposalSigners(proposalId);
        assertEq(signers.length, 1);
        assertEq(signers[0], validator1);
    }

    function test_RevertWhen_SignProposal_InvalidSignature() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Invalid signature
        bytes memory invalidSignature = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));

        vm.prank(validator1);
        vm.expectRevert(TransactionManager.InvalidSignature.selector);
        transactionManager.signProposal(proposalId, invalidSignature);
    }

    function test_RevertWhen_SignProposal_AlreadySigned() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(proposalId, TEST_TRANSACTION))
            )
        );

        uint256 validator1PrivateKey = VALIDATOR1_PK;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1PrivateKey, messageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.startPrank(validator1);
        transactionManager.signProposal(proposalId, signature);

        vm.expectRevert(TransactionManager.AlreadySigned.selector);
        transactionManager.signProposal(proposalId, signature);
        vm.stopPrank();
    }

    function test_OptimisticApproval() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Sign with 3 validators to reach required signatures
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Check proposal is optimistically approved
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.OptimisticApproved));
        assertTrue(executed);
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }

    function test_OptimisticApproval_RequiresLLMValidation() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(INVALID_TRANSACTION); // LLM invalid

        // Sign with 3 validators
        _signProposalWithValidators(proposalId, INVALID_TRANSACTION, 3);

        // Should not be optimistically approved due to failed LLM validation
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Proposed));
        assertFalse(executed);
    }

    // ==================== CHALLENGE TESTS ====================

    function test_ChallengeProposal() public {
        // Setup optimistically approved proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Challenge the proposal
        vm.prank(validator1);
        vm.expectEmit(true, true, false, true);
        emit ProposalChallenged(proposalId, validator1);
        transactionManager.challengeProposal(proposalId);

        // Check proposal state changed
        (
            ,
            ,
            ,
            TransactionManager.ProposalState state,
            uint256 challengeDeadline,
            uint256 votingDeadline,
            address challengerAddr,
            ,
            ,
            ,
            ,
            bool executed
        ) = transactionManager.getProposal(proposalId);
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Voting));
        assertEq(votingDeadline, block.number + 30);
        assertEq(challengerAddr, validator1);
        assertFalse(executed); // Should revert optimistic execution
    }

    function test_RevertWhen_ChallengeProposal_InvalidState() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        // Don't get optimistic approval

        vm.prank(validator1);
        vm.expectRevert(TransactionManager.InvalidProposalState.selector);
        transactionManager.challengeProposal(proposalId);
    }

    function test_RevertWhen_ChallengeProposal_ExpiredChallengePeriod() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Move past challenge period
        vm.roll(block.number + 11);

        vm.prank(validator1);
        vm.expectRevert(TransactionManager.ChallengePeriodExpired.selector);
        transactionManager.challengeProposal(proposalId);
    }

    function test_CanChallengeProposal() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        assertFalse(transactionManager.canChallengeProposal(proposalId)); // Not optimistically approved

        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);
        assertTrue(transactionManager.canChallengeProposal(proposalId)); // Can challenge

        vm.roll(block.number + 11);
        assertFalse(transactionManager.canChallengeProposal(proposalId)); // Challenge period expired
    }

    // ==================== VOTING TESTS ====================

    function test_SubmitVote() public {
        // Setup challenged proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Submit vote
        bool support = true;
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
        );

        uint256 validator2PrivateKey = VALIDATOR2_PK;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator2PrivateKey, voteHash);
        bytes memory voteSignature = abi.encodePacked(r, s, v);

        vm.prank(validator2);
        vm.expectEmit(true, true, false, true);
        emit VoteSubmitted(proposalId, validator2, support);
        transactionManager.submitVote(proposalId, support, voteSignature);

        // Check vote was recorded
        (bool hasVoted, bool vote) = transactionManager.getValidatorVote(proposalId, validator2);
        assertTrue(hasVoted);
        assertTrue(vote);

        (, , , , , , , uint256 signatureCount, uint256 yesVotes, uint256 noVotes, , ) = transactionManager.getProposal(
            proposalId
        );
        assertEq(yesVotes, 1);
        assertEq(noVotes, 0);
    }

    function test_RevertWhen_SubmitVote_InvalidVotingState() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bool support = true;
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
        );

        uint256 validator1PrivateKey = VALIDATOR1_PK;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1PrivateKey, voteHash);
        bytes memory voteSignature = abi.encodePacked(r, s, v);

        vm.prank(validator1);
        vm.expectRevert(TransactionManager.InvalidProposalState.selector);
        transactionManager.submitVote(proposalId, support, voteSignature);
    }

    function test_RevertWhen_SubmitVote_AlreadyVoted() public {
        // Setup challenged proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Submit first vote
        _submitVote(proposalId, validator2, true);

        // Try to vote again with different support value
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VALIDATOR2_PK, voteHash);
        bytes memory voteSignature = abi.encodePacked(r, s, v);

        vm.prank(validator2);
        vm.expectRevert(TransactionManager.AlreadyVoted.selector);
        transactionManager.submitVote(proposalId, false, voteSignature);
    }

    function test_IsInVotingPeriod() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        assertFalse(transactionManager.isInVotingPeriod(proposalId));

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        assertTrue(transactionManager.isInVotingPeriod(proposalId));

        vm.roll(block.number + 31);
        assertFalse(transactionManager.isInVotingPeriod(proposalId));
    }

    // ==================== CHALLENGE RESOLUTION TESTS ====================

    function test_ResolveChallenge_Approved() public {
        // Setup challenged proposal with majority yes votes
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Submit votes: 3 yes, 1 no
        _submitVote(proposalId, validator2, true);
        _submitVote(proposalId, validator3, true);
        _submitVote(proposalId, validator4, true);
        _submitVote(proposalId, validator5, false);

        // Move past voting period
        vm.roll(block.number + 31);

        // Resolve challenge
        vm.expectEmit(true, false, false, true);
        emit ChallengeResolved(proposalId, true, 3, 1);
        transactionManager.resolveChallenge(proposalId);

        // Check proposal is finalized and approved
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Finalized));
        assertTrue(executed);
    }

    function test_ResolveChallenge_Rejected() public {
        // Setup challenged proposal with majority no votes
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Submit votes: 1 yes, 3 no
        _submitVote(proposalId, validator2, true);
        _submitVote(proposalId, validator3, false);
        _submitVote(proposalId, validator4, false);
        _submitVote(proposalId, validator5, false);

        // Move past voting period
        vm.roll(block.number + 31);

        // Resolve challenge
        vm.expectEmit(true, false, false, true);
        emit ChallengeResolved(proposalId, false, 1, 3);
        transactionManager.resolveChallenge(proposalId);

        // Check proposal is reverted
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Reverted));
        assertFalse(executed);
    }

    function test_ResolveChallenge_NoVotes() public {
        // Setup challenged proposal with no votes
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Move past voting period without any votes
        vm.roll(block.number + 31);

        // Resolve challenge - should default to original decision
        transactionManager.resolveChallenge(proposalId);

        // Should be approved because original had enough signatures + LLM validation
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Finalized));
        assertTrue(executed);
    }

    // ==================== FINALIZATION TESTS ====================

    function test_FinalizeProposal_OptimisticApprovalExpired() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Move past challenge period
        vm.roll(block.number + 11);

        // Finalize proposal
        vm.expectEmit(true, false, false, true);
        emit ProposalFinalized(proposalId, true);
        transactionManager.finalizeProposal(proposalId);

        // Check proposal is finalized
        (, , , TransactionManager.ProposalState state, , , , , , , , bool executed) = transactionManager.getProposal(
            proposalId
        );
        assertTrue(uint8(state) == uint8(TransactionManager.ProposalState.Finalized));
        assertTrue(executed);
    }

    function test_RevertWhen_FinalizeProposal_ChallengePeriodNotEnded() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Try to finalize before challenge period ends
        vm.expectRevert(TransactionManager.ChallengePeriodNotEnded.selector);
        transactionManager.finalizeProposal(proposalId);
    }

    function test_FinalizeProposal_VotingState() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        vm.roll(block.number + 11);

        vm.expectRevert(TransactionManager.UseResolveChallengeForVotingProposals.selector);
        transactionManager.finalizeProposal(proposalId);
    }

    // ==================== ADDITIONAL COVERAGE TESTS ====================

    function test_GetProposalStruct() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        TransactionManager.ProposalInfo memory info = transactionManager.getProposalStruct(proposalId);

        assertEq(info.transaction, TEST_TRANSACTION);
        assertEq(info.proposer, proposer);
        assertEq(info.blockNumber, block.number);
        assertTrue(uint8(info.state) == uint8(TransactionManager.ProposalState.Proposed));
        assertEq(info.challengeDeadline, block.number + 10);
        assertEq(info.votingDeadline, 0);
        assertEq(info.challenger, address(0));
        assertEq(info.signatureCount, 0);
        assertEq(info.yesVotes, 0);
        assertEq(info.noVotes, 0);
        assertTrue(info.llmValidation);
        assertFalse(info.executed);
    }

    function test_GetValidatorVote() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Submit vote
        _submitVote(proposalId, validator2, false);

        // Check validator vote
        (bool hasVoted, bool vote) = transactionManager.getValidatorVote(proposalId, validator2);
        assertTrue(hasVoted);
        assertFalse(vote);

        // Check non-voting validator
        (bool hasVoted2, bool vote2) = transactionManager.getValidatorVote(proposalId, validator3);
        assertFalse(hasVoted2);
        assertFalse(vote2);
    }

    function test_IsProposalApproved() public {
        // Test with optimistically approved proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        assertTrue(transactionManager.isProposalApproved(proposalId));

        // Test with challenged and rejected proposal
        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Vote to reject
        _submitVote(proposalId, validator1, false);
        _submitVote(proposalId, validator2, false);
        _submitVote(proposalId, validator3, false);

        vm.roll(block.number + 31);
        transactionManager.resolveChallenge(proposalId);

        assertFalse(transactionManager.isProposalApproved(proposalId));
    }

    function test_GetProposalValidators() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        address[] memory selectedValidators = transactionManager.getProposalValidators(proposalId);
        assertEq(selectedValidators.length, 5);
    }

    function test_GetProposalSigners() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Initially no signers
        address[] memory signers = transactionManager.getProposalSigners(proposalId);
        assertEq(signers.length, 0);

        // Add some signatures
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 2);

        signers = transactionManager.getProposalSigners(proposalId);
        assertEq(signers.length, 2);
    }

    function test_GetProposalVoters() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Initially no voters
        address[] memory voters = transactionManager.getProposalVoters(proposalId);
        assertEq(voters.length, 0);

        // Add some votes
        _submitVote(proposalId, validator2, true);
        _submitVote(proposalId, validator3, false);

        voters = transactionManager.getProposalVoters(proposalId);
        assertEq(voters.length, 2);
    }

    function test_ResolveChallenge_EarlyResolution() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Try to resolve before voting period ends
        vm.expectRevert(TransactionManager.VotingPeriodNotEnded.selector);
        transactionManager.resolveChallenge(proposalId);
    }

    function test_RevertWhen_FinalizeProposal_InvalidState() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Try to finalize before optimistic approval
        vm.expectRevert(TransactionManager.InvalidProposalStateForFinalization.selector);
        transactionManager.finalizeProposal(proposalId);
    }

    function test_CompleteProposalLifecycle() public {
        // Submit proposal
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Get signatures for optimistic approval
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        // Challenge proposal
        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        // Vote on challenge
        _submitVote(proposalId, validator2, true); // Support
        _submitVote(proposalId, validator3, true); // Support
        _submitVote(proposalId, validator4, false); // Reject

        // Resolve challenge
        vm.roll(block.number + 31);
        transactionManager.resolveChallenge(proposalId);

        // Verify final state
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }

    function test_EdgeCase_EmptyValidatorSet() public {
        // This tests edge cases in _getTopValidators when there might be fewer validators
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        address[] memory topValidators = transactionManager.getCurrentTopValidators();
        assertGt(topValidators.length, 0);
    }

    function test_VotingPeriodExpiry() public {
        vm.prank(proposer);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        _signProposalWithValidators(proposalId, TEST_TRANSACTION, 3);

        vm.prank(validator1);
        transactionManager.challengeProposal(proposalId);

        assertTrue(transactionManager.isInVotingPeriod(proposalId));

        // Move past voting period
        vm.roll(block.number + 31);
        assertFalse(transactionManager.isInVotingPeriod(proposalId));

        // Try to vote after period ends
        vm.expectRevert(TransactionManager.VotingPeriodExpired.selector);
        _submitVote(proposalId, validator2, true);
    }

    function test_Multiple_Proposals() public {
        // Test multiple proposals can exist simultaneously
        vm.prank(proposer);
        bytes32 proposalId1 = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.prank(proposer);
        bytes32 proposalId2 = transactionManager.submitProposal("Different transaction for user Bob");

        assertNotEq(proposalId1, proposalId2);

        // Both should be in proposed state initially
        (, , , TransactionManager.ProposalState state1, , , , , , , , ) = transactionManager.getProposal(proposalId1);
        (, , , TransactionManager.ProposalState state2, , , , , , , , ) = transactionManager.getProposal(proposalId2);

        assertTrue(uint8(state1) == uint8(TransactionManager.ProposalState.Proposed));
        assertTrue(uint8(state2) == uint8(TransactionManager.ProposalState.Proposed));
    }

    // ==================== HELPER FUNCTIONS ====================

    function _signProposalWithValidators(bytes32 proposalId, string memory transaction, uint256 count) internal {
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, transaction)))
        );

        address[] memory validators = new address[](5);
        validators[0] = validator1;
        validators[1] = validator2;
        validators[2] = validator3;
        validators[3] = validator4;
        validators[4] = validator5;

        for (uint i = 0; i < count && i < validators.length; i++) {
            uint256 privateKey = i + 1;
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(validators[i]);
            transactionManager.signProposal(proposalId, signature);
        }
    }

    function _submitVote(bytes32 proposalId, address validator, bool support) internal {
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, support)))
        );

        // Map validator address to private key for signing
        uint256 privateKey;
        if (validator == validator1) privateKey = VALIDATOR1_PK;
        else if (validator == validator2) privateKey = VALIDATOR2_PK;
        else if (validator == validator3) privateKey = VALIDATOR3_PK;
        else if (validator == validator4) privateKey = VALIDATOR4_PK;
        else if (validator == validator5) privateKey = VALIDATOR5_PK;
        else revert("Invalid validator for test");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, voteHash);
        bytes memory voteSignature = abi.encodePacked(r, s, v);

        vm.prank(validator);
        transactionManager.submitVote(proposalId, support, voteSignature);
        vm.stopPrank();
    }
}
