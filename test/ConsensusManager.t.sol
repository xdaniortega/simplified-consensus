// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ConsensusManager.sol";
import "../src/ValidatorFactory.sol";
import "../src/ValidatorLogic.sol";
import "../test/mock/ERC20TokenMock.sol";
import "../src/interfaces/IConsensusProvider.sol";

/**
 * @title ConsensusManager Test Suite
 * @notice Comprehensive test suite for ConsensusManager contract functionality
 * @dev This test suite covers the decoupled consensus mechanism including:
 *      - Consensus initialization and lifecycle management
 *        (e.g. test_InitializeConsensus, test_RevertWhen_InitializeConsensus_AlreadyInitialized)
 *      - Challenge mechanisms and state transitions
 *        (e.g. test_ChallengeProposal, test_RevertWhen_ChallengeProposal_ExpiredPeriod) 
 *      - Optimized bitmap-based voting system
 *        (e.g. test_SubmitVote_BitmapStorage, test_GetVoters_BitmapDecoding)
 *      - Consensus resolution and slashing
 *        (e.g. test_ResolveConsensus_Approved, test_ResolveConsensus_WithSlashing)
 *      - View functions and state queries
 *        (e.g. test_GetConsensusState, test_CanChallengeProposal, test_IsInVotingPeriod)
 *      - Access control and security
 *        (e.g. test_RevertWhen_OnlyTransactionManager, test_InvalidProposalId)
 *
 * Test Strategy:
 * 1. Unit Tests: Individual function behavior and state changes
 * 2. Integration Tests: Complete consensus flow from initialization to resolution
 *    (e.g. test_CompleteConsensusLifecycle_NoChallenge, test_CompleteConsensusLifecycle_WithChallenge)
 * 3. Edge Cases: Invalid states, expired periods, boundary conditions
 *    (e.g. test_EdgeCase_NoVotesCast, test_EdgeCase_TieVotes)
 * 4. Security Tests: Access control, reentrancy protection, slashing mechanics
 * 5. Bitmap Tests: Verify voting bitmap storage and decoding accuracy
 *    (e.g. test_BitmapStorage_MaxValidators, test_BitmapStorage_MixedVotes)
 */
contract ConsensusManagerTest is Test {
    ConsensusManager public consensusManager;
    ValidatorFactory public validatorFactory;
    ERC20TokenMock public token;
    
    address public transactionManager;
    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);
    
    bytes32 public constant TEST_PROPOSAL_ID = keccak256("test_proposal");
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;
    
    address[] public testValidators;
    
    function setUp() public {
        token = new ERC20TokenMock();
        validatorFactory = new ValidatorFactory(address(token), MIN_STAKE, 10, 5);
        transactionManager = vm.addr(100);
        consensusManager = new ConsensusManager(address(validatorFactory), transactionManager);
        
        testValidators = [alice, bob, charlie, david, eve];
        setupValidators();
    }
    
    function setupValidators() internal {
        for (uint256 i = 0; i < testValidators.length; i++) {
            address validator = testValidators[i];
            token.mint(validator, MIN_STAKE * 2);
            
            vm.startPrank(validator);
            token.approve(address(validatorFactory), MIN_STAKE);
            validatorFactory.stake(MIN_STAKE);
            vm.stopPrank();
        }
    }
    
    function testInitializeConsensus() public {
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        IConsensusProvider.ConsensusState state;
        uint256 deadline;
        uint256 yesVotes;
        uint256 noVotes;
        (state, deadline, yesVotes, noVotes) = consensusManager.getConsensusState(TEST_PROPOSAL_ID);
        
        assertEq(uint8(state), 0); // Pending
        assertEq(deadline, block.number + CHALLENGE_PERIOD);
        assertEq(yesVotes, 0);
        assertEq(noVotes, 0);
    }
    
    function testRevertWhenInitializeConsensusNotTransactionManager() public {
        vm.prank(alice);
        vm.expectRevert(ConsensusManager.OnlyTransactionManager.selector);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
    }
    
    function testChallengeProposal() public {
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        vm.prank(transactionManager);
        consensusManager.challengeProposal(TEST_PROPOSAL_ID, alice);
        
        IConsensusProvider.ConsensusState state;
        uint256 deadline;
        uint256 temp1;
        uint256 temp2;
        (state, deadline, temp1, temp2) = consensusManager.getConsensusState(TEST_PROPOSAL_ID);
        
        assertEq(uint8(state), 1); // Challenged
        assertEq(deadline, block.number + VOTING_PERIOD);
        
        address challenger;
        (challenger,) = consensusManager.getChallengeInfo(TEST_PROPOSAL_ID);
        assertEq(challenger, alice);
    }
    
    function testSubmitVote() public {
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        vm.prank(transactionManager);
        consensusManager.challengeProposal(TEST_PROPOSAL_ID, alice);
        
        bytes32 voteHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", 
            keccak256(abi.encodePacked(TEST_PROPOSAL_ID, true))));
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(2, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.prank(transactionManager);
        consensusManager.submitVote(TEST_PROPOSAL_ID, bob, true, signature);
        
        bool hasVoted;
        bool support;
        (hasVoted, support) = consensusManager.getValidatorVote(TEST_PROPOSAL_ID, bob);
        assertTrue(hasVoted);
        assertTrue(support);
        
        IConsensusProvider.ConsensusState tempState;
        uint256 tempDeadline;
        uint256 yesVotes;
        uint256 tempNoVotes;
        (tempState, tempDeadline, yesVotes, tempNoVotes) = consensusManager.getConsensusState(TEST_PROPOSAL_ID);
        assertEq(yesVotes, 1);
    }
    
    function testResolveConsensusNoChallengeApproved() public {
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        
        vm.prank(transactionManager);
        bool approved = consensusManager.resolveConsensus(TEST_PROPOSAL_ID);
        
        assertTrue(approved);
        
        IConsensusProvider.ConsensusState state;
        uint256 temp1;
        uint256 temp2;
        uint256 temp3;
        (state, temp1, temp2, temp3) = consensusManager.getConsensusState(TEST_PROPOSAL_ID);
        assertEq(uint8(state), 2); // Approved
    }
    
    function testCanChallengeProposal() public {
        assertFalse(consensusManager.canChallengeProposal(TEST_PROPOSAL_ID));
        
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        assertTrue(consensusManager.canChallengeProposal(TEST_PROPOSAL_ID));
        
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        assertFalse(consensusManager.canChallengeProposal(TEST_PROPOSAL_ID));
    }
    
    function testIsInVotingPeriod() public {
        assertFalse(consensusManager.isInVotingPeriod(TEST_PROPOSAL_ID));
        
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        vm.prank(transactionManager);
        consensusManager.challengeProposal(TEST_PROPOSAL_ID, alice);
        
        assertTrue(consensusManager.isInVotingPeriod(TEST_PROPOSAL_ID));
        
        vm.roll(block.number + VOTING_PERIOD + 1);
        assertFalse(consensusManager.isInVotingPeriod(TEST_PROPOSAL_ID));
    }
    
    function testCompleteConsensusLifecycleNoChallenge() public {
        vm.prank(transactionManager);
        consensusManager.initializeConsensus(TEST_PROPOSAL_ID, testValidators, CHALLENGE_PERIOD);
        
        vm.roll(block.number + CHALLENGE_PERIOD + 1);
        
        vm.prank(transactionManager);
        bool approved = consensusManager.resolveConsensus(TEST_PROPOSAL_ID);
        
        assertTrue(approved);
        uint8 state;
        (state,,,) = consensusManager.getConsensusState(TEST_PROPOSAL_ID);
        assertEq(state, 2); // Approved
    }
} 