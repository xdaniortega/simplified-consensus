// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ValidatorLogic.sol";

/**
 * @title ValidatorFactory
 * @notice Responsible for deploying BeaconProxy contracts for validators and managing their lifecycle.
 * @dev Acts as a trusted operator to slash or reward validators based on consensus decisions.
 *      Holds a reference to a ConsensusModule (e.g., PoSConsensus) to interact with logic layer without tight coupling.
 *      Supports CREATE2 for predictable addresses and pre-funding capabilities.
 *      Manages staking positions for granular stake tracking.
 */
contract ValidatorFactory is ReentrancyGuard {
    using SafeERC20 for IERC20;
    // Events
    event ValidatorCreated(address indexed validator, address indexed proxy, uint256 stake);
    event ValidatorRemoved(address indexed validator);
    event ConsensusModuleUpdated(address indexed oldModule, address indexed newModule);
    event StakeUpdated(address indexed validator, uint256 oldStake, uint256 newStake);
    event ProxyPreFunded(address indexed validator, address indexed proxy, uint256 amount);
    event Unstaked(address indexed validator, uint256 amount);
    event ValidatorSlashed(address indexed validator, uint256 amount, string reason);
    event StakingPositionCreated(address indexed validator, uint256 positionId, uint256 amount);
    event StakingPositionClosed(address indexed validator, uint256 positionId, uint256 amount);

    // State variables
    UpgradeableBeacon public beacon;
    IERC20 public stakingToken;
    uint256 public constant WITHDRAW_COOLDOWN_PERIOD = 1 days;
    uint256 public constant TOKEN_DECIMALS = 18;
    uint256 public constant BONDING_PERIOD = 1; // 1 block bonding period
    uint256 public minimumStake;
    uint16 public maxValidators;  
    uint16 public validatorThreshold;
    
    mapping(address => address) public validatorToProxy; // user to proxy
    mapping(address => bool) public isValidator;
    address[] public validators;

    // Custom errors
    error SenderNotValidator();
    error InsufficientStakeAmount();
    error AlreadyValidator();
    error MaxValidatorsReached();
    error TransferFailed();
    error AmountExceedsTotalStake();
    error PositionNotFound();
    error PositionNotActive();

    modifier onlyValidator() {
        if(!isValidator[msg.sender]) { revert SenderNotValidator();}
        _;
    }

    constructor(address _stakingToken, uint256 _minimumStake, uint16 _maxValidators, uint16 _validatorThreshold) {
        stakingToken = IERC20(_stakingToken);
        minimumStake = _minimumStake;
        maxValidators = _maxValidators;
        validatorThreshold = _validatorThreshold;
        ValidatorLogic validatorLogic = new ValidatorLogic();
        beacon = new UpgradeableBeacon(address(validatorLogic), address(this));
    }

    /**
     * @dev Stake tokens as a validator. Deploys proxy if not already present.
     */
    function stake(uint256 amount) external nonReentrant {
        require(amount >= minimumStake, "Stake below minimum");
        require(!isValidator[msg.sender], "Already validator");
        require(validators.length < maxValidators, "Max validators reached");

        // Compute proxy address
        address proxy = computeProxyAddress(msg.sender, amount);
        // Pre-fund the proxy
        require(stakingToken.transferFrom(msg.sender, proxy, amount), "Transfer failed");

        // Deploy proxy with CREATE2
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            msg.sender,
            address(stakingToken),
            amount
        );
        bytes32 salt = keccak256(abi.encodePacked(msg.sender));
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(address(beacon), data)
        );
        assembly {
            let deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(deployed) { revert(0, 0) }
        }
        validatorToProxy[msg.sender] = proxy;
        isValidator[msg.sender] = true;
        validators.push(msg.sender);
        emit ValidatorCreated(msg.sender, proxy, amount);
    }

    /**
     * @dev Unstake tokens as a validator. If the remaining stake is below minimum, remove validator and recursively unstake the rest.
     */
    function unstake(uint256 amount) external nonReentrant onlyValidator {
        address proxy = validatorToProxy[msg.sender];
        uint256 unstaked = ValidatorLogic(proxy).unstake(amount);
        require(stakingToken.transfer(msg.sender, unstaked), "Transfer failed");
        emit Unstaked(msg.sender, unstaked);

        uint256 remainingStake = ValidatorLogic(proxy).getStakeAmount();
        if (remainingStake < minimumStake && remainingStake > 0) {
            // Unstake the residual below minimum
            uint256 residual = remainingStake;
            uint256 unstakedResidual = ValidatorLogic(proxy).unstake(residual);
            require(stakingToken.transfer(msg.sender, unstakedResidual), "Transfer failed");
            emit Unstaked(msg.sender, unstakedResidual);
            remainingStake = 0;
        }
        if (remainingStake == 0) {
            _removeValidatorFromArray(msg.sender);
            isValidator[msg.sender] = false;
            emit ValidatorRemoved(msg.sender);
        }
    }

    /**
     * @dev Get top N validators by stake using optimized QuickSelect algorithm
     * @param count Number of validators to return
     * @return topValidators Array of validator addresses sorted by stake (descending)
     * @return topStakes Array of corresponding stake amounts
     */
    function getTopNValidators(uint256 count) external view returns (address[] memory topValidators, uint256[] memory topStakes) {
        uint256 totalValidators = validators.length;
        if (totalValidators == 0) {
            return (new address[](0), new uint256[](0));
        }
        
        uint256 actualCount = count > totalValidators ? totalValidators : count;
        topValidators = new address[](actualCount);
        topStakes = new uint256[](actualCount);
        
        // Create temporary arrays for sorting
        address[] memory tempValidators = new address[](totalValidators);
        uint256[] memory tempStakes = new uint256[](totalValidators);
        
        // Load all validators and their stakes
        for (uint256 i = 0; i < totalValidators; i++) {
            address validator = validators[i];
            tempValidators[i] = validator;
            tempStakes[i] = getValidatorStake(validator);
        }
        
        // Use QuickSelect to find top N validators
        _quickSelectTopN(tempValidators, tempStakes, 0, totalValidators - 1, actualCount);
        
        // Copy top N validators to result arrays
        for (uint256 i = 0; i < actualCount; i++) {
            topValidators[i] = tempValidators[i];
            topStakes[i] = tempStakes[i];
        }
    }

    /**
     * @dev Optimized QuickSelect algorithm to find top N validators by stake
     * Time complexity: O(n) average case, O(n²) worst case
     * Space complexity: O(1) in-place sorting
     */
    function _quickSelectTopN(
        address[] memory validators,
        uint256[] memory stakes,
        uint256 left,
        uint256 right,
        uint256 k
    ) internal pure {
        if (left == right) return;
        
        uint256 pivotIndex = _partition(validators, stakes, left, right);
        
        if (k == pivotIndex) {
            return;
        } else if (k < pivotIndex) {
            _quickSelectTopN(validators, stakes, left, pivotIndex - 1, k);
        } else {
            _quickSelectTopN(validators, stakes, pivotIndex + 1, right, k);
        }
    }

    /**
     * @dev Partition function for QuickSelect - sorts in descending order (highest stakes first)
     */
    function _partition(
        address[] memory validators,
        uint256[] memory stakes,
        uint256 left,
        uint256 right
    ) internal pure returns (uint256) {
        uint256 pivot = stakes[right];
        uint256 i = left;
        
        for (uint256 j = left; j < right; j++) {
            if (stakes[j] >= pivot) {
                // Swap validators
                address tempValidator = validators[i];
                validators[i] = validators[j];
                validators[j] = tempValidator;
                
                // Swap stakes
                uint256 tempStake = stakes[i];
                stakes[i] = stakes[j];
                stakes[j] = tempStake;
                
                i++;
            }
        }
        
        // Swap pivot
        address tempValidator = validators[i];
        validators[i] = validators[right];
        validators[right] = tempValidator;
        
        uint256 tempStake = stakes[i];
        stakes[i] = stakes[right];
        stakes[right] = tempStake;
        
        return i;
    }

    /**
     * @dev Get all validators
     * @return allValidators Array of all validator addresses
     */
    function getAllValidators() external view returns (address[] memory) {
        return validators;
    }

    /**
     * @dev Get validator count
     * @return count Number of validators
     */
    function getValidatorCount() external view returns (uint256) {
        return validators.length;
    }

    /**
     * @dev Check if address is validator
     * @param validator Address to check
     * @return isActive Whether the address is an active validator
     */
    function isActiveValidator(address validator) external view returns (bool) {
        return isValidator[validator];
    }

    /**
     * @dev Get validator stake
     * @param validator Validator address
     * @return stakeAmount Stake amount
     */
    function getValidatorStake(address validator) public view returns (uint256) {
        if (!isValidator[validator]) return 0;
        address proxy = validatorToProxy[validator];
        return ValidatorLogic(proxy).getStakeAmount();
    }

    /**
     * @dev Check if validator can unstake (bonding period expired)
     * @param validator Validator address
     * @return canUnstake Whether validator can unstake
     */
    function canUnstake(address validator) external view returns (bool) {
        if (!isValidator[validator]) return false;
        address proxy = validatorToProxy[validator];
        uint256 bondingBlock = ValidatorLogic(proxy).getBondingBlock();
        return block.number > bondingBlock;
    }

    /**
     * @dev Compute proxy address
     * @param validator Validator address
     * @param amount Amount to stake
     * @return predicted Predicted proxy address
     */
    function computeProxyAddress(address validator, uint256 amount) public view returns (address predicted) {
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            validator,
            address(stakingToken),
            amount
        );
        bytes32 salt = keccak256(abi.encodePacked(validator));
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(address(beacon), data)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(bytecode)
            )
        );
        predicted = address(uint160(uint256(hash)));
    }


    // ---------------------------------- INTERNAL FUNCTIONS ----------------------------------
    /**
     * @notice Registers a new validator by deploying a BeaconProxy using CREATE2.
     * @dev Computes the proxy address, pre-funds it, and deploys the proxy with CREATE2. Only one proxy per validator is allowed.
     * @param _amount The amount to stake for the validator.
     * @return proxy The address of the deployed BeaconProxy.
     */
    function _registerValidator(uint256 _amount) internal returns (address proxy) {
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            msg.sender,
            address(stakingToken),
            _amount
        );
        bytes32 salt = keccak256(abi.encodePacked(msg.sender)); // unique proxy per validator
        bytes memory bytecode = abi.encodePacked(
            type(BeaconProxy).creationCode,
            abi.encode(address(beacon), data)
        );

        address predicted = computeProxyAddress(msg.sender, _amount);
        stakingToken.safeTransferFrom(msg.sender, predicted, _amount);

        assembly {
            proxy := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(proxy) { revert(0, 0) }
        }

        validatorToProxy[msg.sender] = proxy;
        isValidator[msg.sender] = true;
        validators.push(msg.sender);
    }

    /**
     * @dev Internal function to remove validator from array
     * @param validator Validator to remove
     */
    function _removeValidatorFromArray(address validator) internal {
        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) {
                validators[i] = validators[validators.length - 1];
                validators.pop();
                break;
            }
        }
    }
} 