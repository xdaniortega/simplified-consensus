// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { PoSConsensus } from "../../src/consensus/PoSConsensus.sol";
import { DisputeManager } from "../../src/consensus/DisputeManager.sol";
import { StakingManager } from "../../src/staking/StakingManager.sol";
import { ERC20TokenMock } from "../mock/ERC20TokenMock.sol";

/**
 * @title DisputeManager Test Suite
 * @notice Comprehensive tests for dispute resolution mechanism
 */
contract DisputeManagerTest is Test {
    PoSConsensus public posConsensus;
    DisputeManager public disputeManager;
    StakingManager public stakingManager;
    ERC20TokenMock public token;

    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);

    string public constant TEST_TRANSACTION = "Transfer test transaction";
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;

    address[] public validators;

    function setUp() public {
        token = new ERC20TokenMock();

        posConsensus = new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        stakingManager = posConsensus.stakingManager();
        disputeManager = posConsensus.disputeManager();

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
        disputeManager.initializeDispute(proposalId, selectedValidators, CHALLENGE_PERIOD);

        (DisputeManager.DisputeState state, uint256 deadline, , ) = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.ChallengePeriod));
        assertEq(deadline, block.number + CHALLENGE_PERIOD);

        assertTrue(disputeManager.canChallengeProposal(proposalId));
    }

    // ==================== CHALLENGE TESTS ====================

    function test_ChallengeProposal() public {
        bytes32 proposalId = setupDisputeProposal();

        vm.prank(address(posConsensus));
        disputeManager.challengeProposal(proposalId, alice);

        (DisputeManager.DisputeState state, , , ) = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Disputed));

        assertTrue(disputeManager.isInVotingPeriod(proposalId));

        (address challenger, ) = disputeManager.getChallengeInfo(proposalId);
        assertEq(challenger, alice);
    }

    function test_RevertWhen_ChallengeAfterPeriod() public {
        bytes32 proposalId = setupDisputeProposal();

        // Move past challenge period
        vm.roll(block.number + CHALLENGE_PERIOD + 1);

        vm.expectRevert(DisputeManager.ChallengePeriodExpired.selector);
        vm.prank(address(posConsensus));
        disputeManager.challengeProposal(proposalId, alice);
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
        bytes32 proposalId = setupVotedProposal(3, 0); // 3 yes, 0 no

        vm.roll(block.number + VOTING_PERIOD + 1);

        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        assertTrue(upheld);

        (DisputeManager.DisputeState state, , , ) = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Upheld));
    }

    function test_ResolveDispute_Overturned() public {
        bytes32 proposalId = setupVotedProposal(0, 3); // 0 yes, 3 no

        vm.roll(block.number + VOTING_PERIOD + 1);

        vm.prank(address(posConsensus));
        bool upheld = disputeManager.resolveDispute(proposalId);

        assertFalse(upheld);

        (DisputeManager.DisputeState state, , , ) = disputeManager.getDisputeState(proposalId);
        assertEq(uint8(state), uint8(DisputeManager.DisputeState.Overturned));
    }

    function test_ResolveDispute_WithSlashing() public {
        bytes32 proposalId = setupVotedProposal(3, 0); // Upheld - false challenge
        uint256 initialStake = stakingManager.getValidatorStake(alice);

        vm.roll(block.number + VOTING_PERIOD + 1);

        vm.expectEmit(true, true, false, false);
        emit DisputeManager.ValidatorSlashed(proposalId, alice, initialStake / 10, false);

        vm.prank(address(posConsensus));
        disputeManager.resolveDispute(proposalId);
    }

    // ==================== HELPER FUNCTIONS ====================

    function setupDisputeProposal() internal returns (bytes32) {
        bytes32 proposalId = keccak256("test");

        // Use all validators to match what PoSConsensus would actually do
        vm.prank(address(posConsensus));
        disputeManager.initializeDispute(proposalId, validators, CHALLENGE_PERIOD);

        return proposalId;
    }

    function setupChallengedProposal() internal returns (bytes32) {
        bytes32 proposalId = setupDisputeProposal();

        vm.prank(address(posConsensus));
        disputeManager.challengeProposal(proposalId, alice);

        return proposalId;
    }

    function setupVotedProposal(uint256 yesVotes, uint256 noVotes) internal returns (bytes32) {
        bytes32 proposalId = setupChallengedProposal();

        // Submit yes votes
        for (uint256 i = 0; i < yesVotes; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 2, voteHash); // Skip alice (index 1)
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i + 1], true, signature);
        }

        // Submit no votes
        for (uint256 i = 0; i < noVotes; i++) {
            bytes32 voteHash = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, false)))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 2, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            vm.prank(address(posConsensus));
            disputeManager.submitVote(proposalId, validators[i + 1], false, signature);
        }

        return proposalId;
    }
}
