// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "./ValidatorLogic.sol";

/**
 * @title StakingManager
 * @notice Manages validator staking, registration, and selection for consensus.
 * @dev Acts as a trusted operator to slash or reward validators based on consensus decisions.
 *      Deploys BeaconProxy contracts for validators and manages their lifecycle.
 *      Supports CREATE2 for predictable addresses and pre-funding capabilities.
 *      Manages staking positions for granular stake tracking.
 *      Uses EnumerableSet for O(1) validator addition/removal operations.
 */
contract StakingManager is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using EnumerableSet for EnumerableSet.AddressSet;
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
    error ZeroAddress();
    error SlashingAmountMismatch();
    error RewardDistributionAmountMismatch();
    error ValidatorAlreadyInSet();
    error ValidatorNotInSet();

    UpgradeableBeacon public immutable beacon;
    IERC20 public immutable stakingToken;
    uint256 public constant WITHDRAW_COOLDOWN_PERIOD = 1 days;
    uint256 public constant TOKEN_DECIMALS = 18;
    uint256 public constant BONDING_PERIOD = 1; // 1 block bonding period
    uint256 public immutable minimumStake;
    uint16 public immutable maxValidators;
    uint16 public immutable validatorThreshold;

    mapping(address => address) public validatorToProxy; // user to proxy
    mapping(address => bool) public isValidator;
    EnumerableSet.AddressSet private _validators;

    modifier onlyValidator() {
        if (!isValidator[msg.sender]) {
            revert SenderNotValidator();
        }
        _;
    }

    constructor(address _stakingToken, uint256 _minimumStake, uint16 _maxValidators, uint16 _validatorThreshold) {
        if (_stakingToken == address(0)) revert ZeroAddress();
        if (_minimumStake == 0) revert InsufficientStakeAmount();
        if (_maxValidators == 0) revert MaxValidatorsReached();
        if (_validatorThreshold == 0) revert InsufficientStakeAmount();

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
        if (_validators.length() >= maxValidators) {
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

        // Handle return value from EnumerableSet.add()
        bool added = _validators.add(msg.sender);
        if (!added) revert ValidatorAlreadyInSet();

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

        // CHECKS-EFFECTS-INTERACTIONS: Update state BEFORE external call
        bool willRemoveValidator = (currentStake - amount) == 0;
        if (willRemoveValidator) {
            _removeValidatorFromArray(msg.sender);
            isValidator[msg.sender] = false;
        }

        uint256 unstaked = ValidatorLogic(proxy).unstake(amount);
        if (unstaked > 0) {
            emit Unstaked(msg.sender, unstaked);
        }

        if (willRemoveValidator) {
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
        uint256 totalValidators = _validators.length();
        if (totalValidators == 0) {
            return (new address[](0), new uint256[](0));
        }

        uint256 actualCount = count > totalValidators ? totalValidators : count;

        // Create arrays to hold all validator data
        address[] memory allValidators = new address[](totalValidators);
        uint256[] memory allStakes = new uint256[](totalValidators);

        // Load all validators and their stakes
        for (uint256 i = 0; i < totalValidators; i++) {
            allValidators[i] = _validators.at(i);
            allStakes[i] = getValidatorStake(_validators.at(i));
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
        return _validators.values();
    }

    /**
     * @dev Get validator count
     * @return count Number of validators
     */
    function getValidatorCount() external view returns (uint256) {
        return _validators.length();
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

        // CHECKS-EFFECTS-INTERACTIONS: Update state BEFORE external call
        bool willRemoveValidator = (currentStake - slashAmount) < minimumStake;
        if (willRemoveValidator) {
            // Remove validator before external call to prevent reentrancy
            _removeValidatorFromArray(validator);
            isValidator[validator] = false;
        }

        // Perform the slashing by calling unstake on the ValidatorLogic
        uint256 actualSlashed = validatorLogic.unstake(slashAmount);
        if (actualSlashed != slashAmount) revert SlashingAmountMismatch();

        emit ValidatorSlashed(validator, actualSlashed, reason);

        if (willRemoveValidator) {
            emit ValidatorRemoved(validator);
        }
    }

    function distributeRewards(uint256 amount, address validator) external {
        if (!isValidator[validator]) revert NotAValidator();
        address proxy = validatorToProxy[validator];
        if (proxy == address(0)) revert ValidatorProxyNotFound();

        uint256 actualStaked = ValidatorLogic(proxy).stake(amount);
        if (actualStaked != amount) revert RewardDistributionAmountMismatch();
    }

    // ---------------------------------- INTERNAL FUNCTIONS ----------------------------------
    /**
     * @dev Internal function to remove validator from set - O(1) operation
     * @param validator Validator to remove
     */
    function _removeValidatorFromArray(address validator) internal {
        // Handle return value from EnumerableSet.remove()
        bool removed = _validators.remove(validator);
        if (!removed) revert ValidatorNotInSet();
    }
}
