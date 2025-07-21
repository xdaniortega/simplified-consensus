// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ILLMOracle
 * @dev Interface for LLM Oracle implementations
 */
interface ILLMOracle {
    /**
     * @dev Validate a transaction string using LLM analysis
     * @param transaction The transaction string to validate
     * @return isValid Whether the transaction is valid according to LLM analysis
     */
    function validateTransaction(string calldata transaction) external view returns (bool isValid);

    /**
     * @dev Get the oracle version/type for identification
     * @return version A string identifying the oracle implementation
     */
    function getOracleType() external pure returns (string memory version);
}
