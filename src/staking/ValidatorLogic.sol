// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "forge-std/console.sol";

/**
 * @title ValidatorLogic
 * @notice Logic contract behind each validator's BeaconProxy; stores validator-specific stake and metadata.
 * @dev Supports multiple staking positions per validator with individual tracking.
 */
contract ValidatorLogic {
    using StorageSlot for bytes32;
    using SafeERC20 for IERC20;

    event ValidatorInitialized(address indexed owner, address indexed token, uint256 stake);
    event StakeIncreased(address indexed owner, uint256 amount, uint256 newTotal);
    event StakeDecreased(address indexed owner, uint256 amount, uint256 newTotal);
    event ValidatorDeactivated(address indexed owner);
    event StakingPositionCreated(address indexed owner, uint256 positionId, uint256 amount);
    event StakingPositionClosed(address indexed owner, uint256 positionId, uint256 amount);
    event StakingPositionDecreased(address indexed owner, uint256 positionId, uint256 amount, uint256 newAmount);

    error ValidatorNotActive();
    error NotValidatorOwner();
    error NotFactory();
    error AlreadyInitialized();
    error InvalidOwner();
    error InsufficientStakeAmount();
    error InvalidAmount();

    bytes32 private constant VALIDATOR_OWNER_SLOT = keccak256("validator.owner"); // address
    bytes32 private constant TOKEN_SLOT = keccak256("token"); // address
    bytes32 private constant VALIDATOR_FACTORY_SLOT = keccak256("validator.factory.address"); // address
    bytes32 private constant STAKE_AMOUNT_SLOT = keccak256("validator.stake.amount"); // uint256
    bytes32 private constant STAKING_POSITIONS_SLOT = keccak256("validator.stakingPositions"); // mapping(uint256 => StakingPosition)
    bytes32 private constant TOTAL_POSITIONS_SLOT = keccak256("validator.totalPositions"); //uint256

    struct StakingPosition {
        uint256 id;
        uint256 amount;
        uint256 timestamp;
        uint256 bondingBlock;
        uint256 lastWithdrawalTimestamp;
        string description;
    }

    modifier onlyOwner() {
        if (msg.sender != StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value) {
            revert NotValidatorOwner();
        }
        _;
    }

    modifier onlyFactory() {
        if (msg.sender != StorageSlot.getAddressSlot(VALIDATOR_FACTORY_SLOT).value) {
            revert NotFactory();
        }
        _;
    }

    /**
     * @notice Initialize validator proxy with owner and stake
     * @dev Only can be initialized if proxy is pre-funded
     * @param _owner Validator owner address
     * @param _token Staking token address
     * @param _stakeAmount Stake amount
     */
    function initialize(address _owner, address _token, uint256 _stakeAmount) external {
        if (StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value != address(0)) {
            revert AlreadyInitialized();
        }
        if (_owner == address(0)) {
            revert InvalidOwner();
        }
        if (_stakeAmount < IERC20(_token).balanceOf(address(this))) {
            revert InsufficientStakeAmount();
        }

        StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value = _owner;
        StorageSlot.getAddressSlot(TOKEN_SLOT).value = _token;
        StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value = _stakeAmount;
        StorageSlot.getAddressSlot(VALIDATOR_FACTORY_SLOT).value = msg.sender;

        // Create initial staking position for the owner (not address(this))
        _createStakingPosition(_owner, _stakeAmount, "Initial validator stake");

        emit ValidatorInitialized(_owner, _token, _stakeAmount);
    }

    /**
     * @dev Increase validator stake
     * @param amount Amount to stake
     * @return stakedAmount Amount actually staked
     */
    function stake(uint256 amount) external onlyFactory returns (uint256 stakedAmount) {
        if (amount == 0) revert InvalidAmount();

        // Create new position
        uint256 positionId =
            _createStakingPosition(StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value, amount, "Legacy stake");

        uint256 currentStake = StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value;
        uint256 newStake = currentStake + amount;

        StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value = newStake;

        emit StakeIncreased(StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value, amount, newStake);
        return amount;
    }

    /**
     * @notice Unstake a given amount for the validator, using LIFO order.
     * @dev Calls the internal _unstake function which handles slot-based logic.
     * @param amount The total amount to unstake.
     * @return totalUnstaked The actual amount unstaked.
     */
    function unstake(uint256 amount) external onlyFactory returns (uint256 totalUnstaked) {
        uint256 stakeSlot = StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value;
        console.log("stakeSlot before unstake", stakeSlot);
        console.log("positions length", getValidatorPositionsLength(getValidatorOwner()));
        if (amount > stakeSlot) revert InsufficientStakeAmount();

        totalUnstaked = _unstake(getValidatorOwner(), amount, stakeSlot);
        // Update total stake
        StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value = stakeSlot - totalUnstaked;

        IERC20(StorageSlot.getAddressSlot(TOKEN_SLOT).value).safeTransfer(getValidatorOwner(), totalUnstaked);

        return totalUnstaked;
    }

    // ---------------------------------- GETTERS & SETTERS FOR SLOTS ----------------------------------

    // Slot helpers y funciones de acceso a posiciones de validador
    function _validatorPositionsLengthSlot(address validator) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(validator, ".validator.positions.length"));
    }

    function _validatorPositionSlot(address validator, uint256 index) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(validator, ".validator.positions.", index));
    }

    function getValidatorPositionsLength(address validator) public view returns (uint256) {
        return StorageSlot.getUint256Slot(_validatorPositionsLengthSlot(validator)).value;
    }

    function getValidatorPosition(address validator, uint256 index) public view returns (uint256 positionId) {
        if (index < getValidatorPositionsLength(validator)) {
            return StorageSlot.getUint256Slot(_validatorPositionSlot(validator, index)).value;
        }
        return 0;
    }

    function pushValidatorPosition(address validator, uint256 positionId) internal {
        uint256 len = getValidatorPositionsLength(validator);
        StorageSlot.getUint256Slot(_validatorPositionSlot(validator, len)).value = positionId;
        StorageSlot.getUint256Slot(_validatorPositionsLengthSlot(validator)).value = len + 1;
    }

    function setValidatorPosition(address validator, uint256 index, uint256 positionId) internal {
        require(index < getValidatorPositionsLength(validator), "Index out of bounds");
        StorageSlot.getUint256Slot(_validatorPositionSlot(validator, index)).value = positionId;
    }

    function deleteValidatorPosition(address validator, uint256 index) internal {
        uint256 len = getValidatorPositionsLength(validator);
        if (index < len) {
            if (index != len - 1) {
                // Move last element to the deleted slot
                uint256 lastPosId = getValidatorPosition(validator, len - 1);
                StorageSlot.getUint256Slot(_validatorPositionSlot(validator, index)).value = lastPosId;
            }
            // Delete last slot
            StorageSlot.getUint256Slot(_validatorPositionSlot(validator, len - 1)).value = 0;
            // Decrement length
            StorageSlot.getUint256Slot(_validatorPositionsLengthSlot(validator)).value = len - 1;
        }
    }

    /**
     * @notice Set staking position
     * @param id Position ID
     * @param position Staking position
     */
    function setStakingPosition(uint256 id, StakingPosition memory position) internal {
        bytes32 baseSlot = keccak256(abi.encodePacked(id, STAKING_POSITIONS_SLOT));

        assembly {
            sstore(baseSlot, mload(position)) // id
            sstore(add(baseSlot, 1), mload(add(position, 32))) // amount
            sstore(add(baseSlot, 2), mload(add(position, 64))) // timestamp
            sstore(add(baseSlot, 3), mload(add(position, 96))) // bondingBlock
            sstore(add(baseSlot, 4), mload(add(position, 128))) // lastWithdrawalTimestamp
            sstore(add(baseSlot, 5), mload(add(position, 160))) // description
        }
    }

    /**
     * @notice Set total positions
     * @param newTotal New total positions
     */
    function setTotalPositions(uint256 newTotal) internal {
        StorageSlot.getUint256Slot(TOTAL_POSITIONS_SLOT).value = newTotal;
    }

    /**
     * @notice Get staking position
     * @param id Position ID
     * @return position Staking position
     */
    function getStakingPosition(uint256 id) public view returns (StakingPosition memory position) {
        bytes32 baseSlot = keccak256(abi.encodePacked(id, STAKING_POSITIONS_SLOT));

        // Load each field individually using StorageSlot
        position.id = StorageSlot.getUint256Slot(baseSlot).value;
        position.amount = StorageSlot.getUint256Slot(bytes32(uint256(baseSlot) + 1)).value;
        position.timestamp = StorageSlot.getUint256Slot(bytes32(uint256(baseSlot) + 2)).value;
        position.bondingBlock = StorageSlot.getUint256Slot(bytes32(uint256(baseSlot) + 3)).value;
        position.lastWithdrawalTimestamp = StorageSlot.getUint256Slot(bytes32(uint256(baseSlot) + 4)).value;
        bytes32 descriptionBytes = StorageSlot.getBytes32Slot(bytes32(uint256(baseSlot) + 5)).value;
        position.description = string(abi.encodePacked(descriptionBytes));
    }

    /**
     * @notice Get total positions
     * @return total Total positions
     */
    function getTotalPositions() public view returns (uint256 total) {
        total = StorageSlot.getUint256Slot(TOTAL_POSITIONS_SLOT).value;
    }

    /**
     * @dev Get validator information
     * @return owner Validator owner address
     * @return stakeAmount Current stake amount
     */
    function getValidatorInfo() external view returns (address owner, uint256 stakeAmount) {
        owner = StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value;
        stakeAmount = StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value;
    }

    /**
     * @dev Get validator owner
     * @return owner Validator owner address
     */
    function getValidatorOwner() public view returns (address) {
        return StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value;
    }

    /**
     * @dev Get stake amount
     * @return stake Current stake amount
     */
    function getStakeAmount() external view returns (uint256) {
        return StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value;
    }

    // ---------------------------------- INTERNAL FUNCTIONS ----------------------------------

    /**
     * @dev Internal function to create a new staking position
     * @param owner Position owner
     * @param amount Stake amount
     * @param description Position description
     * @return positionId ID of the created position
     */
    function _createStakingPosition(address owner, uint256 amount, string memory description)
        internal
        returns (uint256 positionId)
    {
        uint256 total = getTotalPositions();
        positionId = total + 1;
        setTotalPositions(positionId);

        StakingPosition memory position = StakingPosition({
            id: positionId,
            amount: amount,
            timestamp: block.timestamp,
            bondingBlock: block.number,
            lastWithdrawalTimestamp: block.timestamp,
            description: description
        });

        setStakingPosition(positionId, position);
        pushValidatorPosition(owner, positionId);
        console.log("create posId", positionId, "amount", amount);
        emit StakingPositionCreated(owner, positionId, amount);
        return positionId;
    }

    /**
     * @dev Unstake from all positions in LIFO order until the requested amount is reached.
     *      If a position is fully unstaked, it is deleted.
     * @param validator The address of the validator (owner)
     * @param amount The total amount to unstake
     * @return totalUnstaked The actual amount unstaked
     */
    function _unstake(address validator, uint256 amount, uint256 stakeSlot) internal returns (uint256 totalUnstaked) {
        uint256 totalPositions = getValidatorPositionsLength(validator);
        uint256 remaining = amount;
        uint256 unstaked = 0;
        console.log("totalPositions", totalPositions);

        // LIFO: start from the last position
        for (uint256 i = totalPositions; i > 0 && remaining > 0;) {
            uint256 posId = getValidatorPosition(validator, i - 1);
            console.log("index", i - 1);
            console.log("posId", posId);
            if (posId == 0) {
                unchecked {
                    i--;
                }
                continue;
            }
            StakingPosition memory pos = getStakingPosition(posId);
            console.log("pos.amount before", pos.amount);
            if (pos.amount == 0) {
                // Remove this position from the array to avoid stale posIds
                deleteValidatorPosition(validator, i - 1);
                unchecked {
                    i--;
                }
                continue;
            }

            uint256 toUnstake = pos.amount > remaining ? remaining : pos.amount;
            console.log("toUnstake", toUnstake);
            pos.amount -= toUnstake;
            remaining -= toUnstake;
            unstaked += toUnstake;
            console.log("pos.amount after", pos.amount);
            console.log("remaining", remaining);

            if (pos.amount == 0) {
                _deleteStakingPosition(posId);
                deleteValidatorPosition(validator, i - 1);
                emit StakingPositionClosed(validator, posId, toUnstake);
            } else {
                pos.lastWithdrawalTimestamp = block.timestamp;
                setStakingPosition(posId, pos);
                emit StakingPositionDecreased(validator, posId, toUnstake, pos.amount);
            }

            emit StakeDecreased(validator, toUnstake, stakeSlot - unstaked);
            unchecked {
                i--;
            }
        }

        return unstaked;
    }

    /**
     * @dev Delete a staking position from storage (sets all fields to zero)
     */
    function _deleteStakingPosition(uint256 posId) internal {
        setStakingPosition(posId, StakingPosition(0, 0, 0, 0, 0, ""));
    }
}
