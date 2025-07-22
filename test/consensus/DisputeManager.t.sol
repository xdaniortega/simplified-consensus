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
 * @title DisputeManager Test Suite
 * @notice Comprehensive tests for dispute resolution mechanism
 */
contract DisputeManagerTest is Test {
    PoSConsensus public posConsensus;
    DisputeManager public disputeManager;
    StakingManager public stakingManager;
    TransactionManager public transactionManager;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;

    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);

    string public constant TEST_TRANSACTION = "b";
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;

    address[] public validators;

    function setUp() public {
        token = new ERC20TokenMock();

        posConsensus = new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        stakingManager = posConsensus.stakingManager();
        disputeManager = posConsensus.disputeManager();

        // Deploy mock LLM Oracle and Transaction Manager
        llmOracle = new MockLLMOracle();
        llmOracle.setValidationEnabled(true); // Enable validation by default
        transactionManager = new TransactionManager(address(posConsensus), address(llmOracle));

        validators = [alice, bob, charlie, david, eve];
        setupValidators();
    }

    function setupValidators() internal {
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

    // ==================== INITIALIZATION TESTS ====================

    function test_InitializeDispute() public {
        bytes32 proposalId = keccak256("test");
        address[] memory selectedValidators = new address[](3);
        selectedValidators[0] = alice;
        selectedValidators[1] = bob;
        selectedValidators[2] = charlie;

        vm.prank(address(posConsensus));
        disputeManager.initializeDispute(proposalId, selectedValidators, CHALLENGE_PERIOD, alice);

        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Disputed));

        assertTrue(disputeManager.isInVotingPeriod(proposalId));
    }

    // ==================== CHALLENGE TESTS ====================

    function test_ChallengeProposal() public {
        bytes32 proposalId = setupDisputeProposal();

        // In new architecture, setupDisputeProposal already initializes the dispute
        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Disputed));

        assertTrue(disputeManager.isInVotingPeriod(proposalId));

        (address challenger,) = disputeManager.getChallengeInfo(proposalId);
        assertEq(challenger, bob);
    }

    function test_RevertWhen_VoteAfterPeriod() public {
        bytes32 proposalId = setupDisputeProposal();

        // Move past voting period
        vm.roll(block.number + CHALLENGE_PERIOD + 1);

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(DisputeManager.VotingPeriodExpired.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    // ==================== VOTING TESTS ====================

    function test_SubmitVote() public {
        bytes32 proposalId = setupChallengedProposal();

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, bob, true, signature);

        (bool hasVoted, bool support) = disputeManager.getValidatorVote(proposalId, bob);
        assertTrue(hasVoted);
        assertTrue(support);
    }

    function test_RevertWhen_DoubleVoting() public {
        bytes32 proposalId = setupChallengedProposal();

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, bob, true, signature);

        vm.expectRevert(DisputeManager.AlreadyVoted.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, bob, false, signature);
    }

    function test_RevertWhen_NonValidatorVoting() public {
        bytes32 proposalId = setupChallengedProposal();
        address nonValidator = vm.addr(999);

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(999, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(DisputeManager.NotAValidator.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, nonValidator, true, signature);
    }

    // ==================== RESOLUTION TESTS ====================

    function test_ResolveDispute_Upheld() public {
        bytes32 proposalId = setupChallengedProposal(); // Just challenged, not voted yet

        // Submit only 1 yes vote (no majority) - won't auto-resolve
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, voteHash); // Use bob's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, validators[1], true, signature); // validators[1] = bob

        // Wait for voting period to end
        vm.roll(block.number + VOTING_PERIOD + 1);

        // Manually resolve - this should now work since it wasn't auto-resolved
        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        assertTrue(upheld); // 1 yes vote = upheld (default is to uphold)

        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Upheld));
    }

    function test_ResolveDispute_Overturned() public {
        bytes32 proposalId = setupChallengedProposal(); // Just challenged, not voted yet

        // Submit only 1 vote (no majoriy) - won't auto-resolve
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(2, voteHash); // Use bob's key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, validators[1], false, signature); // validators[1] = bob

        // Wait for voting period to end
        vm.roll(block.number + VOTING_PERIOD + 1);

        // Manually resolve - this should now work since it wasn't auto-resolved
        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        assertFalse(upheld); // 1 no vote = overturned

        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Overturned));
    }

    function test_ResolveDispute_WithSlashing() public {
        bytes32 proposalId = setupChallengedProposal(); // Just challenged, not voted yet
        uint256 initialStake = stakingManager.getValidatorStake(bob); // bob is the challenger

        // Submit 3 yes votes to uphold the proposal (false challenge -> slash challenger)
        for (uint256 i = 0; i < 3; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i], true, signature);
        }

        // Check slashing happened (dispute auto-resolved when 3 votes submitted)
        uint256 finalStake = stakingManager.getValidatorStake(bob);
        assertTrue(finalStake < initialStake, "Challenger should be slashed for false challenge");
    }

    // ==================== ADDITIONAL COVERAGE TESTS ====================

    function test_InitializeDispute_DisputeAlreadyInitialized() public {
        bytes32 proposalId = setupChallengedProposal();

        // Try to initialize again
        vm.expectRevert(DisputeManager.DisputeAlreadyInitialized.selector);
        vm.prank(address(posConsensus));
        disputeManager.initializeDispute(proposalId, validators, CHALLENGE_PERIOD, bob);
    }

    function test_InitializeDispute_OnlyConsensusContract() public {
        bytes32 proposalId = keccak256("test_proposal");

        vm.expectRevert(DisputeManager.OnlyConsensusContract.selector);
        vm.prank(alice);
        disputeManager.initializeDispute(proposalId, validators, CHALLENGE_PERIOD, bob);
    }

    function test_SubmitVote_DisputeNotInitialized() public {
        bytes32 proposalId = keccak256("nonexistent");
        bytes memory signature = new bytes(65);

        vm.expectRevert(DisputeManager.DisputeNotInitialized.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    function test_SubmitVote_OnlyConsensusContract() public {
        bytes32 proposalId = setupChallengedProposal();
        bytes memory signature = new bytes(65);

        vm.expectRevert(DisputeManager.OnlyConsensusContract.selector);
        vm.prank(alice);
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    function test_SubmitVote_VotingPeriodExpired() public {
        bytes32 proposalId = setupChallengedProposal();

        // Fast forward past voting deadline
        vm.roll(block.number + VOTING_PERIOD + 1);

        bytes memory signature = new bytes(65);
        vm.expectRevert(DisputeManager.VotingPeriodExpired.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    function test_SubmitVote_NotAValidator() public {
        bytes32 proposalId = setupChallengedProposal();
        address nonValidator = makeAddr("nonValidator");

        bytes memory signature = new bytes(65);
        vm.expectRevert(DisputeManager.NotAValidator.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, nonValidator, true, signature);
    }

    function test_SubmitVote_InvalidSignatureLength() public {
        bytes32 proposalId = setupChallengedProposal();

        bytes memory invalidSignature = new bytes(64); // Wrong length
        vm.expectRevert(DisputeManager.InvalidSignatureLength.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, invalidSignature);
    }

    function test_SubmitVote_InvalidSignature_WrongSigner() public {
        bytes32 proposalId = setupChallengedProposal();

        // Create signature with wrong private key
        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(99, voteHash); // Wrong private key
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(DisputeManager.InvalidSignature.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    function test_SubmitVote_InvalidSignature_MalformedV() public {
        bytes32 proposalId = setupChallengedProposal();

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, voteHash);

        // Corrupt the v value
        bytes memory signature = abi.encodePacked(r, s, uint8(29)); // Invalid v

        vm.expectRevert(DisputeManager.InvalidSignature.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, signature);
    }

    function test_SubmitVote_NotASelectedValidator() public {
        bytes32 proposalId = setupChallengedProposal();

        // Create and stake a new validator not in the selected set
        address newValidator = makeAddr("newValidator");
        deal(address(token), newValidator, MIN_STAKE);
        vm.startPrank(newValidator);
        token.approve(address(stakingManager), MIN_STAKE);
        stakingManager.stake(MIN_STAKE);
        vm.stopPrank();

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(99, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert(DisputeManager.NotASelectedValidator.selector);
        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, newValidator, true, signature);
    }

    function test_ResolveDispute_OnlyConsensusContract() public {
        bytes32 proposalId = setupChallengedProposal();

        vm.expectRevert(DisputeManager.OnlyConsensusContract.selector);
        vm.prank(alice);
        disputeManager.resolveDispute(proposalId);
    }

    function test_ResolveDispute_DisputeNotInitialized() public {
        bytes32 proposalId = keccak256("nonexistent");

        vm.expectRevert(DisputeManager.DisputeNotInitialized.selector);
        vm.prank(address(posConsensus));
        disputeManager.resolveDispute(proposalId);
    }

    function test_ResolveDispute_AlreadyResolved() public {
        bytes32 proposalId = setupVotedProposal(3, 0); // Auto-resolved with 3 yes votes

        vm.expectRevert(DisputeManager.AlreadyResolved.selector);
        vm.prank(address(posConsensus));
        disputeManager.resolveDispute(proposalId);
    }

    function test_ResolveDispute_NotReadyToResolve() public {
        bytes32 proposalId = setupChallengedProposal();

        // Try to resolve without enough votes or timeout
        vm.prank(address(posConsensus));
        bool result = disputeManager.resolveDispute(proposalId);
        assertFalse(result, "Should not be ready to resolve yet");
    }

    function test_ResolveDispute_TimeoutWithNoVotes() public {
        bytes32 proposalId = setupChallengedProposal();

        // Fast forward past voting deadline
        vm.roll(block.number + VOTING_PERIOD + 1);

        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        // With no votes, should default to uphold (true)
        assertTrue(upheld);

        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Upheld));
    }

    function test_ResolveDispute_TimeoutWithTieVotes() public {
        bytes32 proposalId = setupChallengedProposal();

        // Submit 1 yes vote and 1 no vote (tie)
        bytes32 yesHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        bytes32 noHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
        );

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(1, yesHash);
        bytes memory yesSignature = abi.encodePacked(r1, s1, v1);

        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(2, noHash);
        bytes memory noSignature = abi.encodePacked(r2, s2, v2);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, alice, true, yesSignature);

        vm.prank(address(posConsensus));
        disputeManager.submitVote(proposalId, bob, false, noSignature);

        // Fast forward past voting deadline
        vm.roll(block.number + VOTING_PERIOD + 1);

        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        // With tie vote (1 yes, 1 no), need majority to overturn, so upheld
        assertTrue(upheld);
    }

    function test_GetFullDisputeState() public {
        bytes32 proposalId = setupVotedProposal(2, 1); // 2 yes, 1 no

        (DisputeManager.DisputeState state, uint256 deadline, uint256 yesVotes, uint256 noVotes) =
            disputeManager.getFullDisputeState(proposalId);

        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Upheld));
        assertTrue(deadline > 0);
        assertEq(yesVotes, 2);
        assertEq(noVotes, 1);
    }

    function test_CanChallengeProposal() public {
        bytes32 proposalId = setupChallengedProposal();

        // Should be able to challenge during voting period
        bool canChallenge = disputeManager.canChallengeProposal(proposalId);
        assertTrue(canChallenge);

        // After voting period expires, should not be able to challenge
        vm.roll(block.number + VOTING_PERIOD + 1);
        canChallenge = disputeManager.canChallengeProposal(proposalId);
        assertFalse(canChallenge);
    }

    function test_IsInVotingPeriod() public {
        bytes32 proposalId = setupChallengedProposal();

        // Should be in voting period initially
        bool inPeriod = disputeManager.isInVotingPeriod(proposalId);
        assertTrue(inPeriod);

        // After voting period expires, should not be in voting period
        vm.roll(block.number + VOTING_PERIOD + 1);
        inPeriod = disputeManager.isInVotingPeriod(proposalId);
        assertFalse(inPeriod);
    }

    function test_GetChallengeInfo() public {
        bytes32 proposalId = setupChallengedProposal();

        (address challenger, uint256 challengeBlock) = disputeManager.getChallengeInfo(proposalId);
        assertEq(challenger, bob);
        assertEq(challengeBlock, 0); // challengeBlock no longer stored
    }

    function test_GetVoters() public {
        bytes32 proposalId = setupVotedProposal(2, 1); // alice, bob vote yes; charlie votes no

        address[] memory voters = disputeManager.getVoters(proposalId);
        assertEq(voters.length, 3);

        // Check that all three validators who voted are in the list
        bool foundAlice = false;
        bool foundBob = false;
        bool foundCharlie = false;

        for (uint256 i = 0; i < voters.length; i++) {
            if (voters[i] == alice) foundAlice = true;
            if (voters[i] == bob) foundBob = true;
            if (voters[i] == charlie) foundCharlie = true;
        }

        assertTrue(foundAlice);
        assertTrue(foundBob);
        assertTrue(foundCharlie);
    }

    function test_GetValidatorVote_ValidValidator() public {
        bytes32 proposalId = setupVotedProposal(1, 1); // alice votes yes, bob votes no

        (bool hasVotedAlice, bool supportAlice) = disputeManager.getValidatorVote(proposalId, alice);
        assertTrue(hasVotedAlice);
        assertTrue(supportAlice); // alice voted yes (uphold)

        (bool hasVotedBob, bool supportBob) = disputeManager.getValidatorVote(proposalId, bob);
        assertTrue(hasVotedBob);
        assertFalse(supportBob); // bob voted no (overturn)
    }

    function test_GetValidatorVote_ValidatorDidNotVote() public {
        bytes32 proposalId = setupVotedProposal(1, 0); // only alice votes

        (bool hasVotedBob, bool supportBob) = disputeManager.getValidatorVote(proposalId, bob);
        assertFalse(hasVotedBob);
        assertFalse(supportBob);
    }

    function test_GetValidatorVote_ValidatorNotSelected() public {
        bytes32 proposalId = setupChallengedProposal();
        address nonSelectedValidator = makeAddr("nonSelected");

        (bool hasVoted, bool support) = disputeManager.getValidatorVote(proposalId, nonSelectedValidator);
        assertFalse(hasVoted);
        assertFalse(support);
    }

    function test_GetValidatorIndexExternal_ValidValidator() public {
        bytes32 proposalId = setupChallengedProposal();

        uint8 index = disputeManager.getValidatorIndexExternal(proposalId, alice);
        assertEq(index, 0); // alice is first validator

        index = disputeManager.getValidatorIndexExternal(proposalId, bob);
        assertEq(index, 1); // bob is second validator
    }

    function test_GetValidatorIndexExternal_InvalidValidator() public {
        bytes32 proposalId = setupChallengedProposal();
        address nonValidator = makeAddr("nonValidator");

        vm.expectRevert(DisputeManager.NotASelectedValidator.selector);
        disputeManager.getValidatorIndexExternal(proposalId, nonValidator);
    }

    function test_DisputeState_NonExistentProposal() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        // Should return default state for non-existent proposal
        DisputeManager.DisputeState state = disputeManager.getDisputeState(nonExistentProposal);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Disputed)); // Default enum value
    }

    function test_VotingBitmapFunctionality() public {
        bytes32 proposalId = setupChallengedProposal();

        // Submit votes for first 3 validators
        for (uint256 i = 0; i < 3; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, i % 2 == 0))
                )
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i], i % 2 == 0, signature);
        }

        // Verify votes were recorded correctly
        (bool hasVoted0, bool support0) = disputeManager.getValidatorVote(proposalId, validators[0]);
        assertTrue(hasVoted0);
        assertTrue(support0); // even index -> true vote

        (bool hasVoted1, bool support1) = disputeManager.getValidatorVote(proposalId, validators[1]);
        assertTrue(hasVoted1);
        assertFalse(support1); // odd index -> false vote

        (bool hasVoted2, bool support2) = disputeManager.getValidatorVote(proposalId, validators[2]);
        assertTrue(hasVoted2);
        assertTrue(support2); // even index -> true vote
    }

    function test_AutoResolveWhenMajorityReached() public {
        bytes32 proposalId = setupChallengedProposal();

        // With 5 validators, majority is 3. Submit 3 "no" votes to auto-resolve as overturned
        for (uint256 i = 0; i < 3; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i], false, signature);
        }

        // Should have auto-resolved as overturned
        DisputeManager.DisputeState state = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Overturned));
    }

    // ==================== HELPER FUNCTIONS ====================

    function setupDisputeProposal() internal returns (bytes32) {
        // Create proposal through proper flow: TransactionManager -> PoSConsensus
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Challenge the proposal to initialize dispute
        vm.prank(bob);
        posConsensus.challengeProposal(proposalId);

        return proposalId;
    }

    function setupChallengedProposal() internal returns (bytes32) {
        // In the new architecture, setupDisputeProposal already creates a challenged proposal
        return setupDisputeProposal();
    }

    function setupVotedProposal(uint256 yesVotes, uint256 noVotes) internal returns (bytes32) {
        bytes32 proposalId = setupChallengedProposal();

        // Submit yes votes - start from validator index 0
        for (uint256 i = 0; i < yesVotes; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i], true, signature);
        }

        // Submit no votes - start AFTER the yes votes to avoid overlap
        for (uint256 i = 0; i < noVotes; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(yesVotes + i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[yesVotes + i], false, signature);
        }

        return proposalId;
    }
}
