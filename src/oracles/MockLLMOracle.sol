// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ILLMOracle} from "../interfaces/ILLMOracle.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockLLMOracle
 * @dev Mock implementation of LLM Oracle for testing and demonstration
 * Uses deterministic hash-based validation (even hash = valid, odd hash = invalid)
 */
contract MockLLMOracle is ILLMOracle, Ownable {
    // Events
    event TransactionValidated(string indexed transaction, bytes32 hash, bool isValid);

    error OracleDisabled();
    error EmptyTransaction();
    error InvalidTransaction();

    // State variables for customization
    bool public validationEnabled;

    // Statistics
    uint256 public totalValidations;
    uint256 public validTransactions;
    uint256 public invalidTransactions;

    constructor() Ownable(msg.sender) {
        validationEnabled = true;
    }

    /**
     * @dev Validate a transaction string using deterministic hash-based logic
     * @param transaction The transaction string to validate
     * @return isValid True if hash is even (valid), false if odd (invalid)
     */
    function validateTransaction(string calldata transaction) external view override returns (bool isValid) {
        if (!validationEnabled) {
            revert OracleDisabled();
        }
        if (bytes(transaction).length == 0) {
            revert EmptyTransaction();
        }

        // Generate hash of the transaction
        bytes32 hash = keccak256(abi.encodePacked(transaction));

        // Deterministic validation: even hash = valid, odd hash = invalid
        isValid = (uint256(hash) % 2 == 0);

        return isValid;
    }

    /**
     * @dev Validate and emit event (for external tracking)
     * @param transaction The transaction string to validate
     * @return isValid Whether the transaction is valid
     */
    function validateTransactionWithEvent(string calldata transaction) external returns (bool isValid) {
        if (!validationEnabled) {
            revert OracleDisabled();
        }

        if (bytes(transaction).length == 0) {
            revert EmptyTransaction();
        }

        bytes32 hash = keccak256(abi.encodePacked(transaction));
        isValid = (uint256(hash) % 2 == 0);

        // Update statistics
        totalValidations++;
        if (isValid) {
            validTransactions++;
        } else {
            invalidTransactions++;
        }

        emit TransactionValidated(transaction, hash, isValid);

        return isValid;
    }

    /**
     * @dev Get oracle type identifier
     * @return version String identifying this as a mock oracle
     */
    function getOracleType() external pure override returns (string memory) {
        return "MockLLMOracle_v1.0_HashBased";
    }

    /**
     * @dev Enable or disable validation (for testing)
     * @param enabled Whether validation should be enabled
     */
    function setValidationEnabled(bool enabled) external onlyOwner {
        validationEnabled = enabled;
    }
}
