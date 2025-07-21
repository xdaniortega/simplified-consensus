# GenLayer-Inspired Optimistic Consensus Mechanism

This project implements a simplified optimistic consensus mechanism inspired by GenLayer's architecture for Intelligent Contracts powered by Large Language Models (LLMs). The system provides a staking mechanism for ValidatorLogics, optimistic transaction execution, and dispute resolution with fallback to consensus voting.

## Architecture Overview

The system consists of three main components:

1. **ERC20TokenMock (GLT)**: Mock ERC20 token used for ValidatorLogic staking
2. **ValidatorLogicBeacon**: Manages ValidatorLogic registration, proxy creation, and selection
3. **GenLayerConsensus**: Handles transaction proposals, optimistic execution, and dispute resolution

### Key Features

- **ValidatorLogic Staking**: Users can stake GLT tokens to become ValidatorLogics (minimum 1000 GLT)
- **Beacon Proxy Pattern**: Each ValidatorLogic gets a unique proxy contract to hold their stake
- **Optimistic Execution**: Transactions are optimistically approved with 3/5 ValidatorLogic signatures
- **Dispute Resolution**: Any ValidatorLogic can challenge proposals within a 10-block window
- **Mock LLM Validation**: Simulates LLM-based transaction validation
- **Slashing Mechanism**: False challenges result in 10% stake slashing

## Contract Structure

### ERC20TokenMock.sol
- Standard ERC20 token with minting capability
- Used for ValidatorLogic staking and economic incentives

### ValidatorLogicProxy.sol
- Beacon proxy contract for individual ValidatorLogics
- Holds ValidatorLogic stake and metadata
- Implements slashing functionality

### ValidatorLogicBeacon.sol
- Manages ValidatorLogic registration and proxy creation
- Implements dPoS-like ValidatorLogic selection
- Handles bonding periods and unstaking

### GenLayerConsensus.sol
- Main consensus contract for transaction processing
- Implements optimistic approval with signature verification
- Handles dispute resolution and voting mechanisms

## Installation and Setup

### Prerequisites
- Foundry (recommended) or Hardhat
- Node.js and npm

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd simplified-consensus

# Install dependencies
forge install

# Build contracts
forge build
```

### Environment Setup
Create a `.env` file with your private key:
```bash
PRIVATE_KEY=your_private_key_here
```

## Usage

### Deployment
```bash
# Deploy all contracts
forge script script/Deploy.s.sol --rpc-url <your_rpc_url> --broadcast
```

### Testing
```bash
# Run all tests
forge test

# Run specific test file
forge test --match-contract GenLayerConsensusTest

# Run fuzz tests
forge test --match-contract GenLayerConsensusFuzzTest

# Run invariant tests
forge test --match-contract GenLayerConsensusInvariantTest

# Generate coverage report
forge coverage
```

### Key Operations

#### 1. Register as ValidatorLogic
```solidity
// Approve tokens first
token.approve(address(beacon), stakeAmount);
beacon.registerValidatorLogic(stakeAmount);
```

#### 2. Submit Transaction Proposal
```solidity
bytes32 proposalId = consensus.submitProposal("Approve loan for user X based on LLM analysis");
```

#### 3. Sign Proposal for Optimistic Approval
```solidity
bytes32 messageHash = keccak256(abi.encodePacked(proposalId, "SIGN"));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
bytes memory signature = abi.encodePacked(r, s, v);
consensus.signProposal(proposalId, signature);
```

#### 4. Challenge Proposal
```solidity
consensus.challengeProposal(proposalId);
```

#### 5. Vote on Challenged Proposal
```solidity
bytes32 messageHash = keccak256(abi.encodePacked(proposalId, vote, "VOTE"));
bytes32 ethSignedMessageHash = messageHash.toEthSignedMessageHash();
(uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedMessageHash);
bytes memory signature = abi.encodePacked(r, s, v);
consensus.voteOnProposal(proposalId, vote, signature);
```

## Testing Strategy

### Unit Tests
- ValidatorLogic registration and unstaking
- Proposal submission and state transitions
- Optimistic approval flow
- Dispute resolution mechanisms
- Error handling and edge cases

### Fuzz Tests
- Random proposal messages
- Various stake amounts
- Signature verification with different private keys
- Array operations with different sizes

### Invariant Tests
- Total stake never decreases unexpectedly
- ValidatorLogic count consistency
- Token supply consistency
- Proposal state consistency

## Security Considerations

### Implemented Safeguards
1. **Minimum Stake Requirement**: Prevents spam ValidatorLogics
2. **Bonding Period**: Prevents rapid ValidatorLogic churn
3. **Signature Verification**: Ensures only ValidatorLogics can sign/vote
4. **Challenge Window**: Limits dispute timeframe
5. **Slashing Mechanism**: Deters false challenges
6. **Majority Voting**: Ensures fair dispute resolution

### Potential Vulnerabilities and Mitigations
1. **Sybil Attacks**: Mitigated by minimum stake requirement
2. **Signature Replay**: Prevented by unique proposal IDs
3. **Front-running**: Limited by challenge window
4. **ValidatorLogic Collusion**: Addressed by slashing mechanism

## Design Choices and Extensions

### Current Implementation
- **Mock LLM**: Simple hash-based validation for demonstration
- **Fixed Parameters**: Challenge window, required signatures, etc.
- **Simple Selection**: Basic ValidatorLogic selection based on registration order

### Potential Extensions for GenLayer
1. **Oracle Integration**: Replace mock LLM with real oracle calls
2. **Dynamic Parameters**: Adjustable challenge windows and thresholds
3. **Advanced Selection**: Weighted ValidatorLogic selection based on performance
4. **Cross-chain Support**: Extend to multi-chain environments
5. **Layer 2 Integration**: Optimize for L2 scaling solutions

### LLM Integration Points
- **Transaction Validation**: Replace `mockLLMValidation()` with oracle calls
- **Risk Assessment**: Add LLM-based risk scoring for proposals
- **Content Moderation**: Use LLMs for content filtering
- **Automated Responses**: LLM-generated challenge responses

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the BUSL License - see the LICENSE file for details.

## Acknowledgments

This implementation is inspired by GenLayer's architecture for AI-powered blockchain consensus mechanisms. The design demonstrates how LLMs can be integrated into blockchain systems for intelligent contract execution and validation.
