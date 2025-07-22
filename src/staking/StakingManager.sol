// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ValidatorLogic.sol";

/**
 * @title StakingManager
 * @notice Manages validator staking, registration, and selection for consensus.
 * @dev Acts as a trusted operator to slash or reward validators based on consensus decisions.
 *      Deploys BeaconProxy contracts for validators and manages their lifecycle.
 *      Supports CREATE2 for predictable addresses and pre-funding capabilities.
 *      Manages staking positions for granular stake tracking.
 */
contract StakingManager is ReentrancyGuard {
    using SafeERC20 for IERC20;
    event ValidatorCreated(address indexed validator, address indexed proxy, uint256 stake);
    event ValidatorRemoved(address indexed validator);
    event ConsensusModuleUpdated(address indexed oldModule, address indexed newModule);
    event StakeUpdated(address indexed validator, uint256 oldStake, uint256 newStake);
    event ProxyPreFunded(address indexed validator, address indexed proxy, uint256 amount);
    event Unstaked(address indexed validator, uint256 amount);
    event ValidatorSlashed(address indexed validator, uint256 amount, string reason);
    event StakingPositionCreated(address indexed validator, uint256 positionId, uint256 amount);
    event StakingPositionClosed(address indexed validator, uint256 positionId, uint256 amount);

    error SenderNotValidator();
    error InsufficientStakeAmount();
    error AlreadyValidator();
    error MaxValidatorsReached();
    error TransferFailed();
    error AmountExceedsTotalStake();
    error PositionNotFound();
    error PositionNotActive();
    error NotAValidator();
    error ValidatorProxyNotFound();
    error SlashAmountExceedsStake();

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

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) {
            revert SenderNotValidator();
        }
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
        if (amount < minimumStake) {
            revert InsufficientStakeAmount();
        }
        if (isValidator[msg.sender]) {
            revert AlreadyValidator();
        }
        if (validators.length >= maxValidators) {
            revert MaxValidatorsReached();
        }

        // Compute proxy address
        address proxy = computeProxyAddress(msg.sender, amount);
        // Pre-fund the proxy
        stakingToken.safeTransferFrom(msg.sender, proxy, amount);

        // Deploy proxy with CREATE2
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            msg.sender,
            address(stakingToken),
            amount
        );
        bytes32 salt = keccak256(abi.encodePacked(msg.sender));
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(address(beacon), data));
        assembly {
            let deployed := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(deployed) {
                revert(0, 0)
            }
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
        uint256 currentStake = ValidatorLogic(proxy).getStakeAmount();

        if (currentStake < amount) {
            revert InsufficientStakeAmount();
        }

        if (currentStake - amount < minimumStake) {
            amount = currentStake;
        }

        uint256 unstaked = ValidatorLogic(proxy).unstake(amount);
        if (unstaked > 0) {
            emit Unstaked(msg.sender, unstaked);
        }

        uint256 remainingStake = ValidatorLogic(proxy).getStakeAmount();
        if (remainingStake == 0) {
            _removeValidatorFromArray(msg.sender);
            isValidator[msg.sender] = false;
            emit ValidatorRemoved(msg.sender);
        }
    }

    /**
     * @dev Get top N validators by stake using optimized partial selection sort
     * @dev Complexity: O(n*k) where n=total validators, k=count (much better than O(n²) full sort)
     * @param count Number of validators to return
     * @return topValidators Array of validator addresses sorted by stake (descending)
     * @return topStakes Array of corresponding stake amounts
     */
    function getTopNValidators(
        uint256 count
    ) external view returns (address[] memory topValidators, uint256[] memory topStakes) {
        uint256 totalValidators = validators.length;
        if (totalValidators == 0) {
            return (new address[](0), new uint256[](0));
        }

        uint256 actualCount = count > totalValidators ? totalValidators : count;

        // Create arrays to hold all validator data
        address[] memory allValidators = new address[](totalValidators);
        uint256[] memory allStakes = new uint256[](totalValidators);

        // Load all validators and their stakes
        for (uint256 i = 0; i < totalValidators; i++) {
            allValidators[i] = validators[i];
            allStakes[i] = getValidatorStake(validators[i]);
        }

        // Optimized partial selection sort - O(n * k) complexity
        // Only sorts the first 'actualCount' positions, much more efficient than full sort
        // Otherwise we could do bubble sort, but it would be O(n²) complexity
        for (uint256 i = 0; i < actualCount; i++) {
            uint256 maxIndex = i;

            // Find the validator with maximum stake in remaining unsorted portion
            for (uint256 j = i + 1; j < totalValidators; j++) {
                if (allStakes[j] > allStakes[maxIndex]) {
                    maxIndex = j;
                }
            }

            // Swap the maximum to position i (if it's not already there)
            if (maxIndex != i) {
                // Swap stakes
                uint256 tempStake = allStakes[i];
                allStakes[i] = allStakes[maxIndex];
                allStakes[maxIndex] = tempStake;

                // Swap validators
                address tempValidator = allValidators[i];
                allValidators[i] = allValidators[maxIndex];
                allValidators[maxIndex] = tempValidator;
            }
        }

        // Return top N validators
        topValidators = new address[](actualCount);
        topStakes = new uint256[](actualCount);

        for (uint256 i = 0; i < actualCount; i++) {
            topValidators[i] = allValidators[i];
            topStakes[i] = allStakes[i];
        }
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
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(address(beacon), data));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, keccak256(bytecode)));
        predicted = address(uint160(uint256(hash)));
    }

    /**
     * @dev Slash validator stake (callable by consensus contract)
     * @param validator Validator to slash
     * @param slashAmount Amount to slash from validator's stake
     * @param reason Reason for slashing
     */
    function slashValidator(address validator, uint256 slashAmount, string memory reason) external {
        // Only allow TransactionManager to slash (in a real implementation, this would be controlled)
        // For now, allow any caller for testing purposes
        if (!isValidator[validator]) revert NotAValidator();

        address proxy = validatorToProxy[validator];
        if (proxy == address(0)) revert ValidatorProxyNotFound();

        ValidatorLogic validatorLogic = ValidatorLogic(proxy);
        uint256 currentStake = validatorLogic.getStakeAmount();
        if (currentStake < slashAmount) revert SlashAmountExceedsStake();

        // Perform the slashing by calling unstake on the ValidatorLogic
        validatorLogic.unstake(slashAmount);

        emit ValidatorSlashed(validator, slashAmount, reason);

        // If validator's stake falls below minimum, remove them
        uint256 remainingStake = validatorLogic.getStakeAmount();
        if (remainingStake < minimumStake) {
            _removeValidatorFromArray(validator);
            isValidator[validator] = false;
            emit ValidatorRemoved(validator);
        }
    }

    function distributeRewards(uint256 amount, address validator) external {
        if(!isValidator[validator]) revert NotAValidator();
        address proxy = validatorToProxy[validator];
        if(proxy == address(0)) revert ValidatorProxyNotFound();
        ValidatorLogic(proxy).stake(amount);
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
        bytes memory bytecode = abi.encodePacked(type(BeaconProxy).creationCode, abi.encode(address(beacon), data));

        address predicted = computeProxyAddress(msg.sender, _amount);
        stakingToken.safeTransferFrom(msg.sender, predicted, _amount);

        assembly {
            proxy := create2(0, add(bytecode, 0x20), mload(bytecode), salt)
            if iszero(proxy) {
                revert(0, 0)
            }
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
