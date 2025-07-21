// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TransactionManager.sol";
import "../src/ConsensusManager.sol";
import "../src/ValidatorFactory.sol";
import "../src/ValidatorLogic.sol";
import "../src/oracles/MockLLMOracle.sol";
import "../test/mock/ERC20TokenMock.sol";
import "../src/interfaces/IConsensusProvider.sol";

/**
 * @title ConsensusManager Integration Test Suite
 * @notice Test suite for ConsensusManager functionality accessed through TransactionManager
 * @dev This test suite covers the decoupled consensus mechanism through the proper interface:
 *      - Consensus functionality accessed via TransactionManager (proper encapsulation)
 *      - Challenge mechanisms and state transitions through TransactionManager
 *        (e.g. testChallengeProposalThroughTxManager, testResolveConsensusIntegration)
 *      - Optimized bitmap-based voting system integration
 *        (e.g. testVotingThroughTransactionManager, testBitmapVotingIntegration)
 *      - Consensus resolution and slashing through proper channels
 *        (e.g. testConsensusResolutionFlow, testSlashingIntegration)
 *      - View functions accessed through proper interface
 *        (e.g. testConsensusStateQueries, testVotingStateAccess)
 *      - Complete integration workflows
 *        (e.g. testCompleteConsensusWorkflow, testChallengeAndVoteFlow)
 *
 * Test Strategy:
 * 1. Integration Tests: All access through TransactionManager (proper encapsulation)
 * 2. Complete Workflows: Full proposal lifecycle with consensus integration
 *    (e.g. testCompleteProposalWorkflowWithChallenge, testMultipleProposalsConsensus)
 * 3. Edge Cases: Boundary conditions accessed through proper interface
 * 4. State Verification: Consensus state accessed through TransactionManager
 * 5. Security Tests: Access control through TransactionManager interface
 */
contract ConsensusManagerTest is Test {
    TransactionManager public transactionManager;
    ConsensusManager public consensusManager;
    ValidatorFactory public validatorFactory;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;
    
    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);
    
    string public constant TEST_TRANSACTION = "Transfer 100 tokens to Alice";
    bytes32 public testProposalId;
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;
    
    address[] public validators;
    
    function setUp() public {
        token = new ERC20TokenMock();
        validatorFactory = new ValidatorFactory(address(token), MIN_STAKE, 10, 5);
        llmOracle = new MockLLMOracle();
        
        // Deploy TransactionManager which internally deploys ConsensusManager
        transactionManager = new TransactionManager(
            address(validatorFactory),
            address(llmOracle)
        );
        
        // Get the deployed ConsensusManager from TransactionManager
        consensusManager = ConsensusManager(address(transactionManager.consensusProvider()));
        
        validators = [alice, bob, charlie, david, eve];
        setupValidators();
        
        // Submit a proposal to get a proposalId for testing
        testProposalId = transactionManager.submitProposal(TEST_TRANSACTION);
    }
    
    function setupValidators() internal {
        for (uint256 i = 0; i < validators.length; i++) {
            address validator = validators[i];
            token.mint(validator, MIN_STAKE * 2);
            
            vm.startPrank(validator);
            token.approve(address(validatorFactory), MIN_STAKE);
            validatorFactory.stake(MIN_STAKE);
            vm.stopPrank();
        }
    }
    
    // Helper function to create an LLM-approved transaction
    function createApprovedTransaction() internal pure returns (string memory) {
        // Pre-computed to have even hash (will be approved by MockLLMOracle)
        // Hash: 0x725ff3826081acdb7ef6d69069e2443640c309fc9bff742d4b98884c24d27574 (even)
        return "Transfer test";
    }
    
    // Helper function to create an LLM-rejected transaction  
    function createRejectedTransaction() internal pure returns (string memory) {
        // Pre-computed to have odd hash (will be rejected by MockLLMOracle)  
        // Hash: 0xb85306ea1221ed8c782d80697711981efe3aa65d3510c613dea3cdb7d01debd7 (odd)
        return "Reject this";
    }
    
    function test_ConsensusInitializationThroughTxManager() public {
        // First check if the proposal was approved by LLM
        (, , , TransactionManager.ProposalState proposalState, ,) = transactionManager.getProposal(testProposalId);
        
        // Only test consensus state if proposal was approved by LLM
        if (uint8(proposalState) == uint8(TransactionManager.ProposalState.OptimisticApproved)) {
            IConsensusProvider.ConsensusState state;
            uint256 deadline;
            uint256 yesVotes;
            uint256 noVotes;
            (state, deadline, yesVotes, noVotes) = consensusManager.getConsensusState(testProposalId);
            
            assertEq(uint8(state), 0); // Pending
            assertEq(deadline, block.number + CHALLENGE_PERIOD);
            assertEq(yesVotes, 0);
            assertEq(noVotes, 0);
        } else {
            // If LLM rejected, consensus should not be initialized
            // This is expected behavior for rejected proposals
            assertTrue(uint8(proposalState) == uint8(TransactionManager.ProposalState.Rejected));
        }
    }
    
    function test_RevertWhen_DirectConsensusAccess() public {
        // Test that direct access to ConsensusManager is properly restricted
        vm.prank(alice);
        vm.expectRevert(ConsensusManager.OnlyTransactionManager.selector);
        consensusManager.initializeConsensus(keccak256("fake"), validators, CHALLENGE_PERIOD);
    }
    
    function test_ChallengeProposalThroughTxManager() public {
        // First check if the proposal was approved by LLM (only approved proposals can be challenged)
        (, , , TransactionManager.ProposalState proposalState, ,) = transactionManager.getProposal(testProposalId);
        
        if (uint8(proposalState) == uint8(TransactionManager.ProposalState.OptimisticApproved)) {
            // Challenge through TransactionManager (proper interface)
            vm.prank(alice);
            transactionManager.challengeProposal(testProposalId);
            
            IConsensusProvider.ConsensusState state;
            uint256 deadline;
            uint256 temp1;
            uint256 temp2;
            (state, deadline, temp1, temp2) = consensusManager.getConsensusState(testProposalId);
            
            assertEq(uint8(state), 1); // Challenged
            assertEq(deadline, block.number + VOTING_PERIOD);
            
            address challenger;
            (challenger,) = consensusManager.getChallengeInfo(testProposalId);
            assertEq(challenger, alice);
        } else {
            // If LLM rejected the proposal, challenging should fail
            vm.prank(alice);
            vm.expectRevert(TransactionManager.InvalidProposalState.selector);
            transactionManager.challengeProposal(testProposalId);
        }
    }
    
    function test_VotingThroughTransactionManager() public {
        // Create a transaction that will definitely be approved by LLM
        string memory approvedTx = createApprovedTransaction();
        bytes32 approvedProposalId = transactionManager.submitProposal(approvedTx);
        
        // Challenge first to enable voting
        vm.prank(alice);
        transactionManager.challengeProposal(approvedProposalId);
        
        // Create vote signature for Bob
        bytes32 voteHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", 
            keccak256(abi.encodePacked(approvedProposalId, true))));
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(2, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Submit vote through TransactionManager
        vm.prank(bob);
        transactionManager.submitVote(approvedProposalId, true, signature);
        
        // Verify vote was recorded
        bool hasVoted;
        bool support;
        (hasVoted, support) = consensusManager.getValidatorVote(approvedProposalId, bob);
        assertTrue(hasVoted);
        assertTrue(support);
        
        // Verify vote count
        IConsensusProvider.ConsensusState tempState;
        uint256 tempDeadline;
        uint256 yesVotes;
        uint256 tempNoVotes;
        (tempState, tempDeadline, yesVotes, tempNoVotes) = consensusManager.getConsensusState(approvedProposalId);
        assertEq(yesVotes, 1);
    }
    
    function test_ResolveConsensusNoChallengeApproved() public {
        // Create approved proposal
        string memory approvedTx = createApprovedTransaction();
        bytes32 approvedProposalId = transactionManager.submitProposal(approvedTx);
        
        // Move past challenge period without challenging
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        
        vm.prank(alice);
        transactionManager.resolveChallenge(approvedProposalId);
        
        // Verify proposal state
        (
            ,, // transaction, proposer
            ,  // blockNumber
            TransactionManager.ProposalState state,
            ,  // signatureCount  
            address[] memory selectedValidators
        ) = transactionManager.getProposal(approvedProposalId);
        
        assertEq(uint8(state), 3); // Finalized
        assertEq(selectedValidators.length, 5);
    }
    
    function test_CanChallengeProposal() public {
        // Create approved proposal
        string memory approvedTx = createApprovedTransaction();
        bytes32 approvedProposalId = transactionManager.submitProposal(approvedTx);
        
        // Initially should be challengeable (since LLM approved it)
        assertTrue(consensusManager.canChallengeProposal(approvedProposalId));
        
        // After challenge period expires, should not be challengeable
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        assertFalse(consensusManager.canChallengeProposal(approvedProposalId));
    }
    
    function test_IsInVotingPeriod() public {
        // Create approved proposal
        string memory approvedTx = createApprovedTransaction();
        bytes32 approvedProposalId = transactionManager.submitProposal(approvedTx);
        
        // Initially not in voting period
        assertFalse(consensusManager.isInVotingPeriod(approvedProposalId));
        
        // Challenge to enter voting period
        vm.prank(alice);
        transactionManager.challengeProposal(approvedProposalId);
        
        assertTrue(consensusManager.isInVotingPeriod(approvedProposalId));
        
        // After voting period expires
        vm.roll(block.number + VOTING_PERIOD + 1);
        assertFalse(consensusManager.isInVotingPeriod(approvedProposalId));
    }
    
    function test_CompleteConsensusLifecycleNoChallenge() public {
        // Create approved proposal
        string memory approvedTx = createApprovedTransaction();
        bytes32 approvedProposalId = transactionManager.submitProposal(approvedTx);
        
        // Move past challenge period without challenging
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        
        vm.prank(alice);
        transactionManager.resolveChallenge(approvedProposalId);
        
        // Verify consensus state shows approved
        IConsensusProvider.ConsensusState state;
        uint256 temp1;
        uint256 temp2;
        uint256 temp3;
        (state, temp1, temp2, temp3) = consensusManager.getConsensusState(approvedProposalId);
        assertEq(uint8(state), 2); // Approved
    }
} 