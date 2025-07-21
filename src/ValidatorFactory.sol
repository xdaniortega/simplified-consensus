// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
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
     * @dev Create a new validator
     * @return proxy Address of the created proxy
     */
    function registerValidator(uint256 amount) external nonReentrant returns (address proxy) {
        if(amount < minimumStake) {
            revert InsufficientStakeAmount();
        }
        if(isValidator[msg.sender]) {
            revert AlreadyValidator();
        }
        if(validators.length >= maxValidators) {
            revert MaxValidatorsReached();
        }
        if(!stakingToken.safeTransferFrom(msg.sender, address(this), amount)) { //TODO: CREATE2
            revert TransferFailed();
        }

        proxy = _registerValidator(amount);

        emit ValidatorCreated(msg.sender, proxy, amount);
    }

    /**
     * @dev Create a new staking position for a validator
     * @param amount Amount to stake
     * @param description Description for the position
     * @return positionId ID of the created position
     */
    function createStakingPosition(uint256 amount, string memory description) external nonReentrant onlyValidator returns (uint256 positionId) {
        if(amount == 0) {
            revert InsufficientStakeAmount();
        }
        
        address proxy = validatorToProxy[msg.sender];
        
        // Transfer tokens to factory first
        if(!stakingToken.safeTransferFrom(msg.sender, address(this), amount)) {
            revert TransferFailed();
        }
        
        // Transfer to proxy
        stakingToken.safeTransfer(proxy, amount);
        
        // Create position
        positionId = ValidatorLogic(proxy).createStakingPosition(amount, description);
        
        emit StakingPositionCreated(msg.sender, positionId, amount, description);
        return positionId;
    }

    /**
     * @dev Increase stake in an existing position
     * @param positionId ID of the position to increase
     * @param amount Amount to add
     * @return newAmount New total amount in the position
     */
    function increasePositionStake(uint256 positionId, uint256 amount) external nonReentrant onlyValidator returns (uint256 newAmount) {
        if(amount == 0) {
            revert InsufficientStakeAmount();
        }
        
        address proxy = validatorToProxy[msg.sender];
        
        // Transfer tokens to factory first
        if(!stakingToken.safeTransferFrom(msg.sender, address(this), amount)) {
            revert TransferFailed();
        }
        
        // Transfer to proxy
        stakingToken.safeTransfer(proxy, amount);
        
        // Increase position stake
        newAmount = ValidatorLogic(proxy).increasePositionStake(positionId, amount);
        
        uint256 totalStake = getValidatorStake(msg.sender);
        emit StakeUpdated(msg.sender, totalStake - amount, totalStake);
        
        return newAmount;
    }

    /**
     * @dev Close a staking position (partial unstake)
     * @param positionId ID of the position to close
     * @return amount Amount that was in the position
     */
    function closeStakingPosition(uint256 positionId) external nonReentrant onlyValidator returns (uint256 amount) {
        address proxy = validatorToProxy[msg.sender];
        
        // Close position
        amount = ValidatorLogic(proxy).closeStakingPosition(positionId);
        
        // Transfer tokens back to validator
        stakingToken.safeTransfer(msg.sender, amount);
        
        emit StakingPositionClosed(msg.sender, positionId, amount);
        emit Unstaked(msg.sender, amount);
        
        return amount;
    }

    /**
     * @dev Get all active positions for a validator
     * @param validator Validator address
     * @return positions Array of active position IDs
     */
    function getValidatorActivePositions(address validator) external view returns (uint256[] memory positions) {
        if(!isValidator[validator]) {
            return new uint256[](0);
        }
        
        address proxy = validatorToProxy[validator];
        return ValidatorLogic(proxy).getValidatorActivePositions(validator);
    }

    /**
     * @dev Get position details
     * @param validator Validator address
     * @param positionId ID of the position
     * @return position StakingPosition struct
     */
    function getStakingPosition(address validator, uint256 positionId) external view returns (ValidatorLogic.StakingPosition memory position) {
        if(!isValidator[validator]) {
            revert PositionNotFound();
        }
        
        address proxy = validatorToProxy[validator];
        return ValidatorLogic(proxy).getStakingPosition(positionId);
    }

    function increaseStake(uint256 amount) external nonReentrant onlyValidator {
        uint256 totalStake = getValidatorStake(msg.sender);
        address proxy = validatorToProxy[msg.sender];
        
        uint256 stakedAmount = ValidatorLogic(proxy).stake(amount);

        emit StakeUpdated(msg.sender, totalStake, totalStake + stakedAmount);
    }

    function decreaseStake(uint256 amount) external nonReentrant onlyValidator {
        uint256 totalStake = getValidatorStake(msg.sender);
        address proxy = validatorToProxy[msg.sender];

        if(amount > totalStake) {
            revert AmountExceedsTotalStake();
        }

        (uint256 unstakedAmount, bool shouldRemove) = ValidatorLogic(proxy).unstake(amount);

        if(shouldRemove) {
            _removeValidatorFromArray(msg.sender);
            isValidator[msg.sender] = false;
            emit ValidatorRemoved(msg.sender);
        }
        emit Unstaked(msg.sender, unstakedAmount);
    }

    /**
     * @dev Slash validator stake (for malicious behavior)
     * @param validator Validator to slash
     * @param amount Amount to slash
     * @param reason Reason for slashing
     */
    function slashValidator(address validator, uint256 amount, string memory reason) external onlyConsensusModule {
        if (!isValidator[validator]) {
            revert SenderNotValidator();
        }
        
        address proxy = validatorToProxy[validator];
        uint256 currentStake = getValidatorStake(validator);
        
        if (amount > currentStake) {
            amount = currentStake; // Slash entire stake if amount exceeds
        }
        
        ValidatorLogic(proxy).slashStake(amount);
        
        // Transfer slashed tokens to consensus module
        stakingToken.safeTransfer(consensusModule, amount);
        
        emit ValidatorSlashed(validator, amount, reason);
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
     * @dev Get top N validators by stake (simplified version for backward compatibility)
     * @param count Number of validators to return
     * @return topValidators Array of validator addresses
     */
    function getTopNValidatorsSimple(uint256 count) external view returns (address[] memory topValidators) {
        (topValidators, ) = getTopNValidators(count);
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
    function getValidatorStake(address validator) external view returns (uint256) {
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

        address predicted = computeProxyAddress(msg.sender);
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