// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {PoSConsensus} from "../../src/consensus/PoSConsensus.sol";
import {DisputeManager} from "../../src/consensus/DisputeManager.sol";
import {StakingManager} from "../../src/staking/StakingManager.sol";
import {TransactionManager} from "../../src/TransactionManager.sol";
import {MockLLMOracle} from "../../src/oracles/MockLLMOracle.sol";
import {ERC20TokenMock} from "../mock/ERC20TokenMock.sol";
import {IConsensus} from "../../src/interfaces/IConsensus.sol";

/**
 * @title PoSConsensus Test Suite
 * @notice Comprehensive tests for Proof of Stake consensus mechanism
 */
contract PoSConsensusTest is Test {
    PoSConsensus public posConsensus;
    DisputeManager public disputeManager;
    StakingManager public stakingManager;
    TransactionManager public transactionManager;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;

    address public owner = vm.addr(100);
    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);

    string public constant TEST_TRANSACTION = "Transfer 100 tokens based on LLM analysis";
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;

    address[] public validators;

    function setUp() public {
        token = new ERC20TokenMock();

        // Deploy PoS Consensus with all parameters
        posConsensus = new PoSConsensus(
            address(token), // _stakingToken
            MIN_STAKE, // _minimumStake
            10, // _maxValidators
            5, // _validatorThreshold
            CHALLENGE_PERIOD, // _challengePeriod
            3, // _requiredSignatures
            5, // _validatorSetSize
            VOTING_PERIOD, // _votingPeriod
            10 // _slashPercentage (10%)
        );

        // Get references to deployed contracts
        stakingManager = posConsensus.stakingManager();
        disputeManager = posConsensus.disputeManager();

        // Deploy mock LLM Oracle and Transaction Manager
        llmOracle = new MockLLMOracle();
        transactionManager = new TransactionManager(address(posConsensus), address(llmOracle));

        validators = [alice, bob, charlie, david, eve];
        setupValidators();
    }

    function setupValidators() internal {
        vm.deal(owner, 100 ether);

        for (uint256 i = 0; i < validators.length; i++) {
            vm.deal(validators[i], 100 ether);

            // Mint tokens as the owner (this contract)
            token.mint(validators[i], MIN_STAKE);

            // Now let the validator approve and stake
            vm.startPrank(validators[i]);
            token.approve(address(stakingManager), MIN_STAKE);
            stakingManager.stake(MIN_STAKE);
            vm.stopPrank();
        }
    }

    // ==================== DEPLOYMENT TESTS ====================

    function test_Deployment() public {
        assertTrue(address(posConsensus) != address(0));
        assertTrue(address(stakingManager) != address(0));
        assertTrue(address(disputeManager) != address(0));

        assertEq(posConsensus.CHALLENGE_PERIOD(), CHALLENGE_PERIOD);
        assertEq(posConsensus.CONSENSUS_THRESHOLD(), 3);
        assertEq(posConsensus.VALIDATOR_SET_SIZE(), 5);

        assertTrue(posConsensus.supportsDisputes());
        assertEq(posConsensus.getConsensusType(), "PoS");
    }

    // ==================== PROPOSAL MANAGEMENT TESTS ====================

    function test_InitializeConsensus() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Check PoS-specific data
        assertTrue(posConsensus.isProposalInitialized(proposalId));
        assertEq(posConsensus.getSignatureCount(proposalId), 0);
        assertEq(
            uint8(transactionManager.getProposalStatus(proposalId)), uint8(IConsensus.ProposalStatus.OptimisticApproved)
        );

        // Verify validators are available
        address[] memory currentValidators = posConsensus.getValidators();
        assertEq(currentValidators.length, 5);
    }

    function test_SignProposal() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes memory signature = createValidatorSignature(1, proposalId, TEST_TRANSACTION);

        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature);

        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);
        IConsensus.ProposalStatus status = transactionManager.getProposalStatus(proposalId);

        assertEq(signatureCount, 1);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.OptimisticApproved));

        address[] memory signers = posConsensus.getProposalSigners(proposalId);
        assertEq(signers.length, 1);
        assertEq(signers[0], alice);
    }

    function test_AutoFinalization() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Get 3 signatures for auto-finalization
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);
        IConsensus.ProposalStatus status = transactionManager.getProposalStatus(proposalId);

        assertEq(signatureCount, 3);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Finalized));
    }

    // ==================== CHALLENGE TESTS ====================

    function test_ChallengeProposal() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        assertTrue(posConsensus.canChallengeProposal(proposalId));

        // Challenge the proposal (bob must be a selected validator)
        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);

        IConsensus.ProposalStatus status = transactionManager.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Challenged));

        assertFalse(posConsensus.canChallengeProposal(proposalId));
    }

    function test_SubmitVote() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(3, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(charlie);
        posConsensus.submitVote(proposalId, charlie, true, signature);

        (bool hasVoted, bool support) = disputeManager.getValidatorVote(proposalId, charlie);
        assertTrue(hasVoted);
        assertTrue(support);
    }

    // ==================== ADDITIONAL COVERAGE TESTS ====================

    function test_Constructor_InvalidParameters() public {
        // Test invalid staking token
        vm.expectRevert(PoSConsensus.InvalidStakingToken.selector);
        new PoSConsensus(address(0), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        // Test invalid minimum stake
        vm.expectRevert(PoSConsensus.InvalidMinimumStake.selector);
        new PoSConsensus(address(token), 0, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        // Test invalid max validators
        vm.expectRevert(PoSConsensus.InvalidMaxValidators.selector);
        new PoSConsensus(address(token), MIN_STAKE, 0, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        // Test invalid validator threshold
        vm.expectRevert(PoSConsensus.InvalidValidatorThreshold.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 0, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        // Test invalid challenge period
        vm.expectRevert(PoSConsensus.InvalidChallengePeriod.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 5, 0, 3, 5, VOTING_PERIOD, 10);

        // Test invalid required signatures
        vm.expectRevert(PoSConsensus.InvalidRequiredSignatures.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 0, 5, VOTING_PERIOD, 10);

        // Test invalid validator set size
        vm.expectRevert(PoSConsensus.InvalidValidatorSetSize.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 0, VOTING_PERIOD, 10);

        // Test invalid voting period
        vm.expectRevert(PoSConsensus.InvalidVotingPeriod.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, 0, 10);

        // Test invalid slash percentage
        vm.expectRevert(PoSConsensus.InvalidSlashPercentage.selector);
        new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 101);
    }

    function test_InitializeConsensus_NotEnoughValidators() public {
        // Remove all validators to test edge case
        vm.startPrank(alice);
        stakingManager.unstake(2000);
        vm.stopPrank();
        vm.startPrank(bob);
        stakingManager.unstake(2000);
        vm.stopPrank();
        vm.startPrank(charlie);
        stakingManager.unstake(2000);
        vm.stopPrank();
        vm.startPrank(david);
        stakingManager.unstake(2000);
        vm.stopPrank();
        vm.startPrank(eve);
        stakingManager.unstake(2000);
        vm.stopPrank();

        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));

        vm.expectRevert(PoSConsensus.NotEnoughValidators.selector);
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);
    }

    function test_InitializeConsensus_ProposalAlreadyExists() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));

        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);

        vm.expectRevert(PoSConsensus.ProposalAlreadyExists.selector);
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, bob);
    }

    function test_SignProposal_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");
        bytes memory signature = createValidatorSignature(1, nonExistentProposal, TEST_TRANSACTION);

        vm.expectRevert(PoSConsensus.ProposalNotFound.selector);
        vm.prank(alice);
        posConsensus.signProposal(nonExistentProposal, signature);
    }

    function test_SignProposal_AlreadyFinalized() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Sign with enough validators to finalize
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        // Try to sign again - should revert because already finalized
        bytes memory signature4 = createValidatorSignature(4, proposalId, TEST_TRANSACTION);
        vm.expectRevert(PoSConsensus.InvalidProposalState.selector);
        vm.prank(david);
        posConsensus.signProposal(proposalId, signature4);
    }

    function test_SignProposal_AlreadySigned() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes memory signature = createValidatorSignature(1, proposalId, TEST_TRANSACTION);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature);

        // Try to sign again with same validator
        vm.expectRevert(PoSConsensus.AlreadySigned.selector);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature);
    }

    function test_SignProposal_NotASelectedValidator() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Create a non-validator address
        address nonValidator = makeAddr("nonValidator");
        bytes memory signature = createValidatorSignature(99, proposalId, TEST_TRANSACTION);

        vm.expectRevert(PoSConsensus.NotASelectedValidator.selector);
        vm.prank(nonValidator);
        posConsensus.signProposal(proposalId, signature);
    }

    function test_SignProposal_InvalidSignature() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Create invalid signature (wrong private key)
        bytes memory invalidSignature = createValidatorSignature(99, proposalId, TEST_TRANSACTION);

        vm.expectRevert(PoSConsensus.InvalidSignature.selector);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, invalidSignature);
    }

    function test_SignProposal_InvalidSignatureLength() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes memory invalidSignature = new bytes(64); // Wrong length

        vm.expectRevert(PoSConsensus.InvalidSignatureLength.selector);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, invalidSignature);
    }

    function test_ChallengeProposal_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(PoSConsensus.ProposalNotFound.selector);
        vm.prank(alice);
        posConsensus.challengeProposal(nonExistentProposal);
    }

    function test_ChallengeProposal_NotASelectedValidator() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        address nonValidator = makeAddr("nonValidator");

        vm.expectRevert(PoSConsensus.NotASelectedValidator.selector);
        vm.prank(nonValidator);
        posConsensus.challengeProposal(proposalId);
    }

    function test_ChallengeProposal_ChallengePeriodExpired() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Fast forward past challenge period
        vm.roll(block.number + CHALLENGE_PERIOD + 1);

        vm.expectRevert(PoSConsensus.InvalidProposalState.selector);
        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);
    }

    function test_ChallengeProposal_AlreadyChallenged() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);

        // Try to challenge again
        vm.expectRevert(PoSConsensus.DisputeActive.selector);
        vm.prank(charlie);
        posConsensus.challengeProposal(proposalId);
    }

    function test_SubmitVote_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");
        bytes memory signature = new bytes(65);

        vm.expectRevert(PoSConsensus.ProposalNotFound.selector);
        posConsensus.submitVote(nonExistentProposal, alice, true, signature);
    }

    function test_SubmitVote_NoActiveDispute() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes memory signature = new bytes(65);

        vm.expectRevert(PoSConsensus.InvalidProposalState.selector);
        posConsensus.submitVote(proposalId, alice, true, signature);
    }

    function test_ResolveDispute_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(PoSConsensus.ProposalNotFound.selector);
        vm.prank(alice);
        posConsensus.resolveDispute(nonExistentProposal);
    }

    function test_ResolveDispute_NotAValidator() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        address nonValidator = makeAddr("nonValidator");

        vm.expectRevert(PoSConsensus.NotAValidator.selector);
        vm.prank(nonValidator);
        posConsensus.resolveDispute(proposalId);
    }

    function test_ResolveDispute_NoActiveDispute() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.expectRevert(PoSConsensus.InvalidProposalState.selector);
        vm.prank(bob);
        posConsensus.resolveDispute(proposalId);
    }

    function test_GetProposalStatus_NotInitialized() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        IConsensus.ProposalStatus status = posConsensus.getProposalStatus(nonExistentProposal);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Proposed));
    }

    function test_HasActiveDispute_NotInitialized() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        bool hasDispute = posConsensus.hasActiveDispute(nonExistentProposal);
        assertFalse(hasDispute);
    }

    function test_CanFinalizeProposal_NotInitialized() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        bool canFinalize = posConsensus.canFinalizeProposal(nonExistentProposal);
        assertFalse(canFinalize);
    }

    function test_GetConsensusType() public view {
        string memory consensusType = posConsensus.getConsensusType();
        assertEq(consensusType, "PoS");
    }

    function test_SupportsDisputes() public view {
        bool supportsDisputes = posConsensus.supportsDisputes();
        assertTrue(supportsDisputes);
    }

    function test_OnDisputeResolved_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(PoSConsensus.ProposalNotFound.selector);
        vm.prank(address(disputeManager));
        posConsensus.onDisputeResolved(nonExistentProposal, true, alice);
    }

    function test_OnDisputeResolved_NotFromDisputeManager() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.expectRevert(PoSConsensus.OnlyAssociatedDispute.selector);
        vm.prank(alice);
        posConsensus.onDisputeResolved(proposalId, true, alice);
    }

    function test_DisputeResolution_Overturned_WithSlashing() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Sign the proposal first (so there are signers to slash)
        bytes memory signature1 = createValidatorSignature(1, proposalId, TEST_TRANSACTION);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature1);

        bytes memory signature2 = createValidatorSignature(2, proposalId, TEST_TRANSACTION);
        vm.prank(bob);
        posConsensus.signProposal(proposalId, signature2);

        // Challenge the proposal
        vm.prank(charlie);
        posConsensus.challengeProposal(proposalId);

        uint256 aliceStakeBefore = stakingManager.getValidatorStake(alice);
        uint256 bobStakeBefore = stakingManager.getValidatorStake(bob);
        uint256 charlieStakeBefore = stakingManager.getValidatorStake(charlie);

        // Calculate expected slash amounts (10% of each signer's stake)
        uint256 expectedSlashPerValidator = (MIN_STAKE * posConsensus.SLASH_PERCENTAGE()) / 100;
        uint256 expectedTotalSlashAmount = expectedSlashPerValidator * 2; // alice + bob

        // Simulate dispute resolution: overturned (false)
        vm.expectEmit(true, true, false, true);
        emit PoSConsensus.DisputeResolved(proposalId, false, charlie, expectedTotalSlashAmount);

        vm.prank(address(disputeManager));
        posConsensus.onDisputeResolved(proposalId, false, charlie);

        // Check that signers (alice, bob) were slashed and challenger rewarded
        uint256 aliceStakeAfter = stakingManager.getValidatorStake(alice);
        uint256 bobStakeAfter = stakingManager.getValidatorStake(bob);
        uint256 charlieStakeAfter = stakingManager.getValidatorStake(charlie);

        assertTrue(aliceStakeAfter < aliceStakeBefore, "Alice should be slashed");
        assertTrue(bobStakeAfter < bobStakeBefore, "Bob should be slashed");
        assertTrue(charlieStakeAfter > charlieStakeBefore, "Charlie should be rewarded");
    }

    function test_DisputeResolution_Upheld_ChallengerSlashed() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Sign the proposal first
        bytes memory signature1 = createValidatorSignature(1, proposalId, TEST_TRANSACTION);
        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature1);

        // Challenge the proposal (bob will be slashed)
        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);

        uint256 bobStakeBefore = stakingManager.getValidatorStake(bob);
        uint256 aliceStakeBefore = stakingManager.getValidatorStake(alice);

        // Calculate expected slash amount for challenger (10% of challenger's stake)
        uint256 expectedSlashAmount = (MIN_STAKE * 10) / 100; // 10% hardcoded in the contract for false challenges

        // Simulate dispute resolution: upheld (true)
        vm.expectEmit(true, true, false, true);
        emit PoSConsensus.DisputeResolved(proposalId, true, bob, expectedSlashAmount);

        vm.prank(address(disputeManager));
        posConsensus.onDisputeResolved(proposalId, true, bob);

        // Check that challenger (bob) was slashed
        uint256 bobStakeAfter = stakingManager.getValidatorStake(bob);
        uint256 aliceStakeAfter = stakingManager.getValidatorStake(alice);

        assertTrue(bobStakeAfter < bobStakeBefore, "Bob (challenger) should be slashed");
        assertTrue(aliceStakeAfter > aliceStakeBefore, "Alice should be rewarded");
    }

    function test_ChallengeProposal_WithChallengerParameter() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.expectEmit(true, true, false, false);
        emit PoSConsensus.ChallengeInitiated(proposalId, bob);

        posConsensus.challengeProposal(proposalId, bob);

        // Verify the challenge was initialized correctly
        (address challenger,) = disputeManager.getChallengeInfo(proposalId);
        assertEq(challenger, bob);
    }

    function test_FinalizeConsensus_Public() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Sign with enough validators
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        // Anyone can finalize
        vm.prank(eve);
        posConsensus.finalizeConsensus(proposalId);

        // Check that it's finalized
        IConsensus.ProposalStatus status = transactionManager.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Finalized));
    }

    // ==================== UTILITY FUNCTIONS ====================

    function createValidatorSignature(uint256 privateKey, bytes32 proposalId, string memory transaction)
        internal
        view
        returns (bytes memory)
    {
        // Use the same hash method as PoSConsensus._getProposalHash()
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", proposalId));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }
}
