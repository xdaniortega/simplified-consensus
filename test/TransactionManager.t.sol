// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { TransactionManager } from "../src/TransactionManager.sol";
import { IConsensus } from "../src/interfaces/IConsensus.sol";
import { PoSConsensus } from "../src/consensus/PoSConsensus.sol";
import { DisputeManager } from "../src/consensus/DisputeManager.sol";
import { StakingManager } from "../src/staking/StakingManager.sol";
import { MockLLMOracle } from "../src/oracles/MockLLMOracle.sol";
import { ERC20TokenMock } from "./mock/ERC20TokenMock.sol";

/**
 * @title TransactionManager Test Suite
 * @notice Tests focused on transaction management and LLM integration
 */
contract TransactionManagerTest is Test {
    TransactionManager public transactionManager;
    PoSConsensus public posConsensus;
    DisputeManager public disputeManager;
    StakingManager public stakingManager;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;

    address public alice = vm.addr(1);
    address public bob = vm.addr(2);
    address public charlie = vm.addr(3);
    address public david = vm.addr(4);
    address public eve = vm.addr(5);

    string public constant TEST_TRANSACTION = "Transfer 100 tokens to user Alice based on LLM analysis";
    uint256 public constant MIN_STAKE = 1000 ether;
    uint256 public constant CHALLENGE_PERIOD = 10;
    uint256 public constant VOTING_PERIOD = 30;

    address[] public validators;

    function setUp() public {
        token = new ERC20TokenMock();

        // Create MockLLMOracle without prank
        llmOracle = new MockLLMOracle();

        // Ensure oracle is enabled for tests
        llmOracle.setValidationEnabled(true);

        // Deploy PoS Consensus with all parameters
        posConsensus = new PoSConsensus(address(token), MIN_STAKE, 10, 5, CHALLENGE_PERIOD, 3, 5, VOTING_PERIOD, 10);

        stakingManager = posConsensus.stakingManager();
        disputeManager = posConsensus.disputeManager();

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

    // ==================== DEPLOYMENT TESTS ====================

    function test_DeploymentState() public {
        assertEq(address(transactionManager.getConsensus()), address(posConsensus));
        assertEq(address(transactionManager.llmOracle()), address(llmOracle));
        assertEq(transactionManager.proposalCount(), 0);
        assertEq(transactionManager.getConsensusType(), "PoS");
        assertTrue(transactionManager.supportsDisputes());
    }

    function test_ConstructorDeployment() public {
        assertTrue(address(posConsensus) != address(0));
        assertTrue(address(transactionManager.getConsensus()) == address(posConsensus));

        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        assertTrue(posConsensus.canChallengeProposal(proposalId));
    }

    // ==================== PROPOSAL SUBMISSION TESTS ====================

    function test_SubmitProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        (
            string memory transaction,
            address proposer,
            uint256 blockNumber,
            IConsensus.ProposalStatus status
        ) = transactionManager.getProposal(proposalId);

        assertEq(transaction, TEST_TRANSACTION);
        assertEq(proposer, address(this));
        assertEq(blockNumber, block.number);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.OptimisticApproved));
        assertEq(transactionManager.proposalCount(), 1);
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }

    function test_RevertWhen_SubmitProposal_EmptyTransaction() public {
        vm.expectRevert(TransactionManager.EmptyTransaction.selector);
        transactionManager.submitProposal("");
    }

    // ==================== LLM INTEGRATION TESTS ====================

    function test_LLMValidation() public {
        assertTrue(transactionManager.testLLMValidation(TEST_TRANSACTION));

        llmOracle.setValidationEnabled(false);

        // Test that oracle is disabled
        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        transactionManager.testLLMValidation(TEST_TRANSACTION);

        // Re-enable oracle for other tests
        llmOracle.setValidationEnabled(true);
    }

    // ==================== PROPOSAL STATE TESTS ====================

    function test_GetValidatorCount() public {
        assertEq(transactionManager.getValidatorCount(), 5);
    }

    function test_GetCurrentTopValidators() public {
        address[] memory topValidators = transactionManager.getCurrentTopValidators();
        assertEq(topValidators.length, 5);

        for (uint256 i = 0; i < validators.length; i++) {
            bool found = false;
            for (uint256 j = 0; j < topValidators.length; j++) {
                if (topValidators[j] == validators[i]) {
                    found = true;
                    break;
                }
            }
            assertTrue(found);
        }
    }

    function test_MultipleProposals() public {
        string memory tx1 = "Transaction 1";
        string memory tx2 = "Transaction 2";

        bytes32 proposalId1 = transactionManager.submitProposal(tx1);
        bytes32 proposalId2 = transactionManager.submitProposal(tx2);

        assertTrue(proposalId1 != proposalId2);
        assertEq(transactionManager.proposalCount(), 2);

        string memory transaction1;
        string memory transaction2;
        (transaction1, , , ) = transactionManager.getProposal(proposalId1);
        (transaction2, , , ) = transactionManager.getProposal(proposalId2);

        assertEq(transaction1, tx1);
        assertEq(transaction2, tx2);
    }

    // ==================== SIMPLE CHALLENGE TESTS ====================

    function test_CanChallengeProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        assertTrue(transactionManager.canChallengeProposal(proposalId));

        vm.roll(block.number + 11);
        assertFalse(transactionManager.canChallengeProposal(proposalId));
    }

    function test_ChallengeProposalDelegation() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        vm.prank(alice);
        posConsensus.challengeProposal(proposalId);

        IConsensus.ProposalStatus status;
        (, , , status) = transactionManager.getProposal(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Challenged));

        assertTrue(disputeManager.isInVotingPeriod(proposalId));
        (address challenger, ) = disputeManager.getChallengeInfo(proposalId);
        assertEq(challenger, alice);
    }

    // ==================== SIGNING TESTS ====================

    function test_SignProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        bytes memory signature = createValidatorSignature(1, proposalId, TEST_TRANSACTION);

        vm.prank(alice);
        posConsensus.signProposal(proposalId, signature);

        IConsensus.ProposalStatus status;
        (, , , status) = transactionManager.getProposal(proposalId);
        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);

        assertEq(signatureCount, 1);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.OptimisticApproved));

        address[] memory signers = posConsensus.getProposalSigners(proposalId);
        assertEq(signers.length, 1);
        assertEq(signers[0], alice);
    }

    function test_SignProposalAutoFinalize() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        IConsensus.ProposalStatus status;
        (, , , status) = transactionManager.getProposal(proposalId);
        uint256 signatureCount = posConsensus.getSignatureCount(proposalId);

        assertEq(signatureCount, 3);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Finalized));
        assertTrue(transactionManager.isProposalApproved(proposalId));
    }

    function test_CompleteProposalLifecycleNoChallenge() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        for (uint256 i = 0; i < 3; i++) {
            bytes memory signature = createValidatorSignature(i + 1, proposalId, TEST_TRANSACTION);
            vm.prank(validators[i]);
            posConsensus.signProposal(proposalId, signature);
        }

        IConsensus.ProposalStatus status;
        (, , , status) = transactionManager.getProposal(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Finalized));
        assertTrue(transactionManager.isProposalApproved(proposalId));
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

    // ==================== ADDITIONAL COVERAGE TESTS ====================

    function test_Constructor_InvalidParameters() public {
        // Test invalid consensus contract
        vm.expectRevert(TransactionManager.InvalidConsensus.selector);
        new TransactionManager(address(0), address(llmOracle));

        // Test invalid oracle
        vm.expectRevert(TransactionManager.InvalidLLMOracle.selector);
        new TransactionManager(address(posConsensus), address(0));
    }

    function test_UpdateProposalStatus_OnlyConsensus() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Non-consensus contract should not be able to update status
        vm.expectRevert(TransactionManager.InvalidConsensus.selector);
        vm.prank(alice);
        transactionManager.updateProposalStatus(proposalId, IConsensus.ProposalStatus.Finalized);
    }

    function test_UpdateProposalStatus_ProposalNotFound() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(TransactionManager.ProposalNotFound.selector);
        vm.prank(address(posConsensus));
        transactionManager.updateProposalStatus(nonExistentProposal, IConsensus.ProposalStatus.Finalized);
    }

    function test_GetProposalStatus_NonExistentProposal() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(TransactionManager.ProposalNotFound.selector);
        transactionManager.getProposalStatus(nonExistentProposal);
    }

    function test_GetProposalBlockNumber_NonExistentProposal() public {
        bytes32 nonExistentProposal = keccak256("nonexistent");

        vm.expectRevert(TransactionManager.ProposalNotFound.selector);
        transactionManager.getProposalBlockNumber(nonExistentProposal);
    }

    function test_ProposalLifecycle_AllStatuses() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // After submitProposal, if LLM approves, it's OptimisticApproved
        IConsensus.ProposalStatus status = transactionManager.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.OptimisticApproved));

        // Simulate Challenged
        vm.prank(address(posConsensus));
        transactionManager.updateProposalStatus(proposalId, IConsensus.ProposalStatus.Challenged);
        status = transactionManager.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Challenged));

        // Simulate Rejected
        vm.prank(address(posConsensus));
        transactionManager.updateProposalStatus(proposalId, IConsensus.ProposalStatus.Rejected);
        status = transactionManager.getProposalStatus(proposalId);
        assertEq(uint8(status), uint8(IConsensus.ProposalStatus.Rejected));
    }

    function test_GetProposer() public {
        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Check via proposals mapping
        (, address proposer, , ) = transactionManager.proposals(proposalId);
        assertEq(proposer, alice);
    }

    function test_Events() public {
        // Test ProposalSubmitted event - check event is emitted with any proposalId
        vm.expectEmit(false, false, false, true);
        emit TransactionManager.ProposalSubmitted(bytes32(0), TEST_TRANSACTION, alice);

        vm.prank(alice);
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);

        // Test ProposalStatusUpdated event
        vm.expectEmit(true, false, false, true);
        emit TransactionManager.ProposalStatusUpdated(proposalId, IConsensus.ProposalStatus.Finalized);

        vm.prank(address(posConsensus));
        transactionManager.updateProposalStatus(proposalId, IConsensus.ProposalStatus.Finalized);
    }

    // ==================== FUZZ TESTS ====================

    function testFuzz_ProposalSubmission(string calldata transaction) public {
        vm.assume(bytes(transaction).length > 0);
        vm.assume(bytes(transaction).length < 1000); // Reasonable limit

        bytes32 proposalId = transactionManager.submitProposal(transaction);

        (string memory storedTransaction, , , ) = transactionManager.getProposal(proposalId);
        assertEq(storedTransaction, transaction);
    }
}
