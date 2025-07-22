// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { PoSConsensus } from "../../src/consensus/PoSConsensus.sol";
import { DisputeManager } from "../../src/consensus/DisputeManager.sol";
import { StakingManager } from "../../src/staking/StakingManager.sol";
import { ERC20TokenMock } from "../mock/ERC20TokenMock.sol";
import { IConsensus } from "../../src/interfaces/IConsensus.sol";

/**
 * @title PoSConsensus Test Suite
 * @notice Comprehensive tests for Proof of Stake consensus mechanism
 */
contract PoSConsensusTest is Test {
    PoSConsensus public posConsensus;
    DisputeManager public disputeManager;
    StakingManager public stakingManager;
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
        assertEq(posConsensus.REQUIRED_SIGNATURES(), 3);
        assertEq(posConsensus.VALIDATOR_SET_SIZE(), 5);

        assertTrue(posConsensus.supportsDisputes());
        assertEq(posConsensus.getConsensusType(), "PoS");
    }

    // ==================== PROPOSAL MANAGEMENT TESTS ====================

    function test_InitializeConsensus() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));

        bool result = posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);
        assertTrue(result);

        // Check PoS-specific data
        assertTrue(posConsensus.isProposalInitialized(proposalId));
        assertEq(posConsensus.getSignatureCount(proposalId), 0);
        assertEq(uint8(posConsensus.getProposalStatus(proposalId)), uint8(IConsensus.ProposalStatus.Approved));

        // Verify validators are available
        address[] memory currentValidators = posConsensus.getValidators();
        assertEq(currentValidators.length, 5);
    }

    function test_SignProposal() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);

        bytes memory signature = createValidatorSignature(1, proposalId, TEST_TRANSACTION);

        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature);

        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);
        IConsensus.ProposalStatus status = posConsensus.getProposalStatus(proposalId);

        assertEq(signatureCount, 1);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Approved));

        address[] memory signers = posConsensus.getProposalSigners(proposalId);
        assertEq(signers.length, 1);
        assertEq(signers[0], alice);
    }

    function test_AutoFinalization() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);

        // Get 3 signatures for auto-finalization
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);
        IConsensus.ProposalStatus status = posConsensus.getProposalStatus(proposalId);

        assertEq(signatureCount, 3);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Finalized));
    }

    // ==================== CHALLENGE TESTS ====================

    function test_ChallengeProposal() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);

        assertTrue(posConsensus.canChallengeProposal(proposalId));

        // This test contract is the authorized transaction manager since it called initializeConsensus
        posConsensus.challengeProposal(proposalId, bob);

        IConsensus.ProposalStatus status = posConsensus.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Challenged));

        assertFalse(posConsensus.canChallengeProposal(proposalId));
    }

    function test_SubmitVote() public {
        bytes32 proposalId = keccak256(abi.encodePacked("test", block.timestamp));
        posConsensus.initializeConsensus(proposalId, TEST_TRANSACTION, alice);

        // This test contract is the authorized transaction manager
        posConsensus.challengeProposal(proposalId, bob);

        bytes32 voteHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(abi.encodePacked(proposalId, true)))
        );
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(3, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // submitVote doesn't require transaction manager authorization, just valid validator
        vm.prank(charlie);
        posConsensus.submitVote(proposalId, charlie, true, signature);

        (bool hasVoted, bool support) = disputeManager.getValidatorVote(proposalId, charlie);
        assertTrue(hasVoted);
        assertTrue(support);
    }

    // ==================== UTILITY FUNCTIONS ====================

    function createValidatorSignature(
        uint256 privateKey,
        bytes32 proposalId,
        string memory transaction
    ) internal view returns (bytes memory) {
        // Use the same hash method as PoSConsensus._getProposalHash()
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", proposalId));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }
}
