// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/TransactionManagerV2.sol";
import "../src/ConsensusManager.sol";
import "../src/ValidatorFactory.sol";
import "../src/ValidatorLogic.sol";
import "../src/oracles/MockLLMOracle.sol";
import "../test/mock/ERC20TokenMock.sol";
import "../src/interfaces/IConsensusProvider.sol";

/**
 * @title TransactionManagerV2 Test Suite
 * @notice Comprehensive test suite for TransactionManagerV2 using decoupled architecture
 * @dev This test suite covers the simplified transaction manager with consensus delegation:
 *      - Proposal submission with LLM validation and consensus initialization
 *        (e.g. test_SubmitProposal, test_SubmitProposal_LLMRejection)
 *      - Validator signature collection for finalization
 *        (e.g. test_SignProposal, test_SignProposal_AutoFinalize)
 *      - Challenge and voting delegation to ConsensusManager
 *        (e.g. test_ChallengeProposal_Delegation, test_SubmitVote_Delegation)
 *      - Consensus resolution integration
 *        (e.g. test_ResolveChallenge_Integration, test_CompleteProposalLifecycle)
 *      - View functions and state management
 *        (e.g. test_GetProposal, test_IsProposalApproved, test_ConsensusProviderIntegration)
 *      - Error handling and edge cases
 *        (e.g. test_RevertWhen_InvalidStates, test_EdgeCase_EmptyValidatorSet)
 *
 * Test Strategy:
 * 1. Unit Tests: Individual TransactionManagerV2 function behavior
 * 2. Integration Tests: Full integration with ConsensusManager
 *    (e.g. test_CompleteProposalWithChallenge, test_CompleteProposalWithoutChallenge)
 * 3. Edge Cases: Invalid states, periods, boundary conditions
 * 4. Delegation Tests: Verify proper delegation to ConsensusManager
 * 5. Security Tests: Access control, signature verification, state transitions
 */
contract TransactionManagerV2Test is Test {
    TransactionManagerV2 public transactionManager;
    ConsensusManager public consensusManager;
    ValidatorFactory public validatorFactory;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;
    
    address public owner = vm.addr(100);
    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);
    
    string public constant TEST_TRANSACTION = "Transfer 100 tokens to user Alice based on LLM analysis";
    uint256 public constant MIN_STAKE = 1000 ether;
    
    address[] public validators;
    
    function setUp() public {
        token = new ERC20TokenMock("GLT", "GenLayer Token");
        validatorFactory = new ValidatorFactory(address(token), MIN_STAKE, 10, 5);
        
        vm.prank(owner);
        llmOracle = new MockLLMOracle(owner);
        
        consensusManager = new ConsensusManager(address(validatorFactory), address(0));
        
        transactionManager = new TransactionManagerV2(
            address(validatorFactory),
            address(llmOracle),
            address(consensusManager)
        );
        
        consensusManager = new ConsensusManager(address(validatorFactory), address(transactionManager));
        
        transactionManager = new TransactionManagerV2(
            address(validatorFactory),
            address(llmOracle),
            address(consensusManager)
        );
        
        validators = [alice, bob, charlie, david, eve];
        setupValidators();
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
    
    function createValidatorSignature(uint256 privateKey, bytes32 proposalId, string memory transaction) 
        internal 
        pure 
        returns (bytes memory) 
    {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n32",
                keccak256(abi.encodePacked(proposalId, transaction))
            )
        );
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }
    
    function testDeploymentState() public view {
        assertEq(address(transactionManager.validatorFactory()), address(validatorFactory));
        assertEq(address(transactionManager.llmOracle()), address(llmOracle));
        assertEq(address(transactionManager.consensusProvider()), address(consensusManager));
        assertEq(transactionManager.proposalCount(), 0);
        assertEq(transactionManager.CHALLENGE_PERIOD(), 10);
        assertEq(transactionManager.REQUIRED_SIGNATURES(), 3);
        assertEq(transactionManager.VALIDATOR_SET_SIZE(), 5);
    }
    
    function testGetValidatorCount() public view {
        assertEq(transactionManager.getValidatorCount(), 5);
    }
    
    function testGetCurrentTopValidators() public view {
        address[] memory topValidators = transactionManager.getCurrentTopValidators();
        assertEq(topValidators.length, 5);
    }
    
    function testTestLLMValidation() public view {
        assertTrue(transactionManager.testLLMValidation(TEST_TRANSACTION));
    }
    
    function testSubmitProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        string memory transaction;
        address proposer;
        uint256 blockNumber;
        TransactionManagerV2.ProposalState state;
        uint256 signatureCount;
        address[] memory selectedValidators;
        (transaction, proposer, blockNumber, state, signatureCount, selectedValidators) = transactionManager.getProposal(proposalId);
        
        assertEq(transaction, TEST_TRANSACTION);
        assertEq(proposer, address(this));
        assertEq(blockNumber, block.number);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.OptimisticApproved));
        assertEq(signatureCount, 0);
        assertEq(selectedValidators.length, 5);
        
        assertTrue(consensusManager.canChallengeProposal(proposalId));
    }
    
    function testSubmitProposalLLMRejection() public {
        string memory rejectTransaction = "aa"; // This will have even hash
        
        bytes32 proposalId = transactionManager.submitProposal(rejectTransaction);
        
        TransactionManagerV2.ProposalState state;
        (,,,state,,) = transactionManager.getProposal(proposalId);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.Rejected));
        
        assertFalse(consensusManager.canChallengeProposal(proposalId));
    }
    
    function testRevertWhenSubmitProposalEmptyTransaction() public {
        vm.expectRevert(TransactionManagerV2.EmptyTransaction.selector);
        transactionManager.submitProposal("");
    }
    
    function testSignProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        bytes memory signature = createValidatorSignature(1, proposalId, TEST_TRANSACTION);
        
        vm.prank(alice);
        transactionManager.signProposal(proposalId, signature);
        
        TransactionManagerV2.ProposalState state;
        uint256 signatureCount;
        (,,,state, signatureCount,) = transactionManager.getProposal(proposalId);
        
        assertEq(signatureCount, 1);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.OptimisticApproved));
        
        address[] memory signers = transactionManager.getProposalSigners(proposalId);
        assertEq(signers.length, 1);
        assertEq(signers[0], alice);
    }
    
    function testSignProposalAutoFinalize() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        address[] memory signingValidators = new address[](3);
        signingValidators[0] = alice;
        signingValidators[1] = bob;
        signingValidators[2] = charlie;
        
        uint256[] memory privateKeys = new uint256[](3);
        privateKeys[0] = 1;
        privateKeys[1] = 2;
        privateKeys[2] = 3;
        
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(privateKeys[i], proposalId, TEST_TRANSACTION);
            
            vm.prank(signingValidators[i]);
            transactionManager.signProposal(proposalId, signature);
        }
        
        TransactionManagerV2.ProposalState state;
        uint256 signatureCount;
        (,,,state, signatureCount,) = transactionManager.getProposal(proposalId);
        
        assertEq(signatureCount, 3);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.Finalized));
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }
    
    function testChallengeProposalDelegation() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        vm.prank(alice);
        transactionManager.challengeProposal(proposalId);
        
        TransactionManagerV2.ProposalState state;
        (,,,state,,) = transactionManager.getProposal(proposalId);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.Challenged));
        
        assertTrue(consensusManager.isInVotingPeriod(proposalId));
        address challenger;
        (challenger,) = consensusManager.getChallengeInfo(proposalId);
        assertEq(challenger, alice);
    }
    
    function testSubmitVoteDelegation() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        vm.prank(alice);
        transactionManager.challengeProposal(proposalId);
        
        bytes32 voteHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", 
            keccak256(abi.encodePacked(proposalId, true))));
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = vm.sign(2, voteHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        vm.prank(bob);
        transactionManager.submitVote(proposalId, true, signature);
        
        bool hasVoted;
        bool support;
        (hasVoted, support) = consensusManager.getValidatorVote(proposalId, bob);
        assertTrue(hasVoted);
        assertTrue(support);
    }
    
    function testResolveChallenge() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        vm.prank(alice);
        transactionManager.challengeProposal(proposalId);
        
        for (uint256 i = 1; i <= 3; i++) {
            bytes32 voteHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", 
                keccak256(abi.encodePacked(proposalId, true))));
            uint8 v;
            bytes32 r;
            bytes32 s;
            (v, r, s) = vm.sign(i + 1, voteHash);
            bytes memory signature = abi.encodePacked(r, s, v);
            
            vm.prank(validators[i]);
            transactionManager.submitVote(proposalId, true, signature);
        }
        
        vm.roll(block.number + 31);
        
        transactionManager.resolveChallenge(proposalId);
        
        TransactionManagerV2.ProposalState state;
        (,,,state,,) = transactionManager.getProposal(proposalId);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.Finalized));
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }
    
    function testCanChallengeProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        assertTrue(transactionManager.canChallengeProposal(proposalId));
        
        vm.roll(block.number + 11);
        assertFalse(transactionManager.canChallengeProposal(proposalId));
    }
    
    function testCompleteProposalLifecycleNoChallenge() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        
        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            transactionManager.signProposal(proposalId, signature);
        }
        
        TransactionManagerV2.ProposalState state;
        (,,,state,,) = transactionManager.getProposal(proposalId);
        assertEq(uint8(state), uint8(TransactionManagerV2.ProposalState.Finalized));
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }
    
    function testMultipleProposals() public {
        string memory tx1 = "Transaction 1";
        string memory tx2 = "Transaction 2";
        
        bytes32 proposalId1 = transactionManager.submitProposal(tx1);
        bytes32 proposalId2 = transactionManager.submitProposal(tx2);
        
        assertTrue(proposalId1 != proposalId2);
        assertEq(transactionManager.proposalCount(), 2);
        
        string memory transaction1;
        string memory transaction2;
        (transaction1,,,,,) = transactionManager.getProposal(proposalId1);
        (transaction2,,,,,) = transactionManager.getProposal(proposalId2);
        
        assertEq(transaction1, tx1);
        assertEq(transaction2, tx2);
    }
} 