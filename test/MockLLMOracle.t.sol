// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/oracles/MockLLMOracle.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockLLMOracle Test Suite
 * @notice Test suite for MockLLMOracle contract used in optimistic consensus
 * @dev This test suite covers the mock LLM validation functionality including:
 *      - Transaction validation using deterministic hash-based logic
 *        (e.g. test_ValidateTransaction, test_ValidateTransactionWithEvent)
 *      - Oracle enablement/disablement controls
 *        (e.g. test_SetValidationEnabled, test_DisabledOracle)
 *      - Ownership management and access control
 *        (e.g. test_TransferOwnership, test_RevertWhen_TransferOwnership_NotOwner)
 *      - Event emission for validation results
 *        (e.g. test_ValidateTransactionWithEvent with proper event testing)
 *      - Batch validation capabilities
 *        (e.g. test_Statistics showing multiple validations)
 *      - Statistical tracking and consistency verification
 *        (e.g. test_ConsistentResults, test_Statistics with counters)
 *
 * Key Test Categories:
 * - Core Validation: test_ValidateTransaction, test_RevertWhen_ValidateTransaction_EmptyString
 * - Access Control: test_RevertWhen_SetValidationEnabled_NotOwner, test_RevertWhen_TransferOwnership_InvalidAddress
 * - State Management: test_SetValidationEnabled, test_DisabledOracle
 * - Consistency: test_ConsistentResults, test_Statistics
 */
contract MockLLMOracleTest is Test {
    MockLLMOracle public oracle;

    address public owner = vm.addr(1);
    address public user = vm.addr(2);

    function setUp() public {
        vm.prank(owner);
        oracle = new MockLLMOracle();
    }

    function test_ValidateTransaction() public {
        bool result1 = oracle.validateTransaction("Test transaction 1");
        bool result2 = oracle.validateTransaction("Test transaction 2");

        // Results should be deterministic based on hash
        bytes32 hash1 = keccak256(abi.encodePacked("Test transaction 1"));
        bytes32 hash2 = keccak256(abi.encodePacked("Test transaction 2"));

        assertEq(result1, (uint256(hash1) % 2 == 0));
        assertEq(result2, (uint256(hash2) % 2 == 0));
    }

    function test_ValidateTransactionWithEvent() public {
        vm.expectEmit(true, true, true, true);
        string memory transaction = "Test transaction with event";
        bytes32 hash = keccak256(abi.encodePacked(transaction));
        bool expectedResult = (uint256(hash) % 2 == 0);
        emit MockLLMOracle.TransactionValidated(transaction, hash, expectedResult);

        bool result = oracle.validateTransactionWithEvent(transaction);
        assertEq(result, expectedResult);

        assertEq(oracle.totalValidations(), 1);
        if (expectedResult) {
            assertEq(oracle.validTransactions(), 1);
            assertEq(oracle.invalidTransactions(), 0);
        } else {
            assertEq(oracle.validTransactions(), 0);
            assertEq(oracle.invalidTransactions(), 1);
        }
    }

    function test_GetOracleType() public {
        string memory oracleType = oracle.getOracleType();
        assertEq(oracleType, "MockLLMOracle_v1.0_HashBased");
    }

    function test_SetValidationEnabled() public {
        assertTrue(oracle.validationEnabled());

        vm.prank(owner);
        oracle.setValidationEnabled(false);
        assertFalse(oracle.validationEnabled());

        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        oracle.validateTransaction("Test");
    }

    function test_RevertWhen_SetValidationEnabled_NotOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        oracle.setValidationEnabled(false);
    }

    function test_TransferOwnership() public {
        assertEq(oracle.owner(), owner);

        vm.prank(owner);
        oracle.transferOwnership(user);
        assertEq(oracle.owner(), user);
    }

    function test_RevertWhen_TransferOwnership_InvalidAddress() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableInvalidOwner.selector, address(0)));
        oracle.transferOwnership(address(0));
    }

    function test_RevertWhen_TransferOwnership_NotOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        oracle.transferOwnership(address(0x2));
    }

    function test_RevertWhen_ValidateTransaction_EmptyString() public {
        vm.expectRevert(MockLLMOracle.EmptyTransaction.selector);
        oracle.validateTransaction("");
    }

    function test_RevertWhen_ValidateTransactionWithEvent_EmptyString() public {
        vm.expectRevert(MockLLMOracle.EmptyTransaction.selector);
        oracle.validateTransactionWithEvent("");
    }

    function test_Statistics() public {
        // Start with zero statistics
        assertEq(oracle.totalValidations(), 0);
        assertEq(oracle.validTransactions(), 0);
        assertEq(oracle.invalidTransactions(), 0);

        // Test multiple validations
        oracle.validateTransactionWithEvent("Valid test");
        oracle.validateTransactionWithEvent("Invalid test");
        oracle.validateTransactionWithEvent("Another test");

        assertEq(oracle.totalValidations(), 3);
        assertGt(oracle.validTransactions() + oracle.invalidTransactions(), 0);
        assertEq(oracle.validTransactions() + oracle.invalidTransactions(), 3);
    }

    function test_ConsistentResults() public {
        string memory transaction = "Consistent test transaction";

        bool result1 = oracle.validateTransaction(transaction);
        bool result2 = oracle.validateTransaction(transaction);

        assertEq(result1, result2); // Should be consistent
    }

    function test_DisabledOracle() public {
        vm.prank(owner);
        oracle.setValidationEnabled(false);

        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        oracle.validateTransaction("Test");

        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        oracle.validateTransactionWithEvent("Test");

        vm.expectRevert(MockLLMOracle.OracleDisabled.selector);
        oracle.validateTransaction("Test");
    }
}
