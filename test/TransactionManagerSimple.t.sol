// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { Test, console } from "forge-std/Test.sol";
import { TransactionManager } from "../src/TransactionManager.sol";
import { PoSConsensus } from "../src/consensus/PoSConsensus.sol";
import { DisputeManager } from "../src/consensus/DisputeManager.sol";
import { StakingManager } from "../src/staking/StakingManager.sol";
import { MockLLMOracle } from "../src/oracles/MockLLMOracle.sol";
import { ERC20TokenMock } from "./mock/ERC20TokenMock.sol";

/**
 * @title Simple TransactionManager Test
 * @notice Simplified tests for TransactionManager without complex setup
 */
contract TransactionManagerSimpleTest is Test {
    TransactionManager public transactionManager;
    PoSConsensus public posConsensus;
    MockLLMOracle public llmOracle;
    ERC20TokenMock public token;

    string public constant TEST_TRANSACTION = "Transfer 100 tokens";
    uint256 public constant MIN_STAKE = 1000 ether;

    function setUp() public {
        token = new ERC20TokenMock();
        llmOracle = new MockLLMOracle();

        // Enable LLM Oracle validation
        llmOracle.setValidationEnabled(true);

        // Deploy PoS Consensus
        posConsensus = new PoSConsensus(address(token), MIN_STAKE, 10, 1, 10, 1, 1, 30, 10);

        // Deploy TransactionManager
        transactionManager = new TransactionManager(address(posConsensus), address(llmOracle));

        // Add a validator to meet minimum requirements
        address validator = vm.addr(1);
        vm.deal(validator, 100 ether);

        // Mint tokens as the owner (this contract)
        token.mint(validator, MIN_STAKE);

        // Now let the validator approve and stake
        vm.startPrank(validator);
        token.approve(address(posConsensus.stakingManager()), MIN_STAKE);
        posConsensus.stakingManager().stake(MIN_STAKE);
        vm.stopPrank();
    }

    function test_BasicDeployment() public {
        assertTrue(address(transactionManager) != address(0));
        assertTrue(address(posConsensus) != address(0));
        assertEq(transactionManager.proposalCount(), 0);
    }

    function test_SubmitSimpleProposal() public {
        bytes32 proposalId = transactionManager.submitProposal(TEST_TRANSACTION);
        assertTrue(proposalId != bytes32(0));
        assertEq(transactionManager.proposalCount(), 1);

        (string memory transaction, , , , , ) = transactionManager.getProposal(proposalId);
        assertEq(transaction, TEST_TRANSACTION);
    }

    function test_RevertEmptyTransaction() public {
        vm.expectRevert(TransactionManager.EmptyTransaction.selector);
        transactionManager.submitProposal("");
    }

    function test_LLMIntegration() public {
        assertTrue(transactionManager.testLLMValidation(TEST_TRANSACTION));

        llmOracle.setValidationEnabled(false);

        // Test that oracle is disabled
        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        transactionManager.testLLMValidation(TEST_TRANSACTION);

        // Re-enable oracle for other tests
        llmOracle.setValidationEnabled(true);
    }

    function test_ConsensusIntegration() public {
        assertEq(transactionManager.getConsensusType(), "PoS");
        assertTrue(transactionManager.supportsDisputes());
    }
}
