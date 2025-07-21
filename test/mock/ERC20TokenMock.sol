// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ERC20TokenMock
 * @dev Mock ERC20 token for GenLayer consensus mechanism staking
 */
contract ERC20TokenMock is ERC20, Ownable {
    constructor() ERC20("Mock Token", "MTK") Ownable(msg.sender) {
        // Mint initial supply to deployer
        _mint(msg.sender, 1000000 * 10**decimals());
    }

    /**
     * @dev Mint tokens (for testing purposes)
     * @param to Address to mint tokens to
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
} 