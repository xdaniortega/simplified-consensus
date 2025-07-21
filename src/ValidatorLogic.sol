// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

/**
 * @title ValidatorLogic
 * @notice Logic contract behind each validator's BeaconProxy; stores validator-specific stake and metadata.
 * @dev Supports multiple staking positions per validator with individual tracking.
 */
contract ValidatorLogic {
    using StorageSlot for bytes32;

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
    bytes32 private constant STAKE_AMOUNT_SLOT = keccak256("stake.amount"); // uint256
    bytes32 private constant IS_ACTIVE_SLOT = keccak256("is.active"); // bool
    bytes32 private constant BONDING_BLOCK_SLOT = keccak256("bonding.block"); // uint256
    bytes32 private constant POSITION_COUNTER_SLOT = keccak256("position.counter"); // uint256
    bytes32 private constant STAKING_POSITIONS_SLOT = keccak256("validator.stakingPositions"); // mapping(uint256 => StakingPosition)
    bytes32 private constant VALIDATOR_POSITIONS_SLOT = keccak256("validator.validatorPositions"); // mapping(address => uint256[])
    bytes32 private constant TOTAL_POSITIONS_SLOT = keccak256("validator.totalPositions"); //uint256

    struct StakingPosition {
        uint256 id;
        uint256 amount;
        uint256 timestamp;
        uint256 bondingBlock;
        uint256 lastWithdrawalTimestamp;
    }

    modifier onlyOwner() {
        if(msg.sender != StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value) {
            revert NotValidatorOwner();
        }
        _;
    }

    modifier onlyFactory() {
        if(msg.sender != StorageSlot.getAddressSlot(keccak256("genlayer.factory.address")).value) {
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
        if(StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value != address(0)) {
            revert AlreadyInitialized();
        }
        if(_owner == address(0)) {
            revert InvalidOwner();
        }
        if(_stakeAmount < IERC20(_token).balanceOf(address(this))) {
            revert InsufficientStakeAmount();
        }

        StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value = _owner;
        StorageSlot.getAddressSlot(TOKEN_SLOT).value = _token;
        StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value = _stakeAmount;
        StorageSlot.getBooleanSlot(IS_ACTIVE_SLOT).value = true;
        StorageSlot.getUint256Slot(BONDING_BLOCK_SLOT).value = block.number;
        StorageSlot.getAddressSlot(keccak256("genlayer.factory.address")).value = msg.sender;

        // Create initial staking position
        _createStakingPosition(_owner, _stakeAmount, "Initial validator stake");

        emit ValidatorInitialized(_owner, _token, _stakeAmount);
    }


    /**
     * @dev Increase validator stake
     * @param amount Amount to stake
     * @return stakedAmount Amount actually staked
     */
    function stake(uint256 amount) external onlyFactory returns (uint256 stakedAmount) {
        if(amount == 0) revert InvalidAmount();
        if(!StorageSlot.getBooleanSlot(IS_ACTIVE_SLOT).value) revert ValidatorNotActive();
        
        // Create new position
        uint256 positionId = _createStakingPosition(StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value, amount, "Legacy stake");
        
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

        if (amount > stakeSlot) revert InsufficientStakeAmount();

        totalUnstaked = _unstake(getValidatorOwner(), amount, stakeSlot);
        // Update total stake
        StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value = stakeSlot - totalUnstaked;

        return totalUnstaked;
    }

    // ---------------------------------- SETTERS FOR SLOTS ----------------------------------

    /**
     * @dev Deactivate validator (only factory can call)
     */
    function deactivate() external onlyFactory {
        StorageSlot.getBooleanSlot(IS_ACTIVE_SLOT).value = false;
        emit ValidatorDeactivated(StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value);
    }

    /**
     * @notice Set staking position
     * @param id Position ID
     * @param position Staking position
     */
    function setStakingPosition(uint256 id, StakingPosition memory position) internal {
        bytes32 baseSlot = keccak256(abi.encodePacked(id, STAKING_POSITIONS_SLOT));

        assembly {
            sstore(baseSlot, mload(position))                      // id
            sstore(add(baseSlot, 1), mload(add(position, 32)))     // amount
            sstore(add(baseSlot, 2), mload(add(position, 64)))     // timestamp
            sstore(add(baseSlot, 3), mload(add(position, 96)))     // bondingBlock
            sstore(add(baseSlot, 4), mload(add(position, 128)))    // lastWithdrawalTimestamp
        }
    }

    /**
     * @notice Set validator position
     * @param validator Validator address
     * @param index Index of the position
     * @param positionId Position ID
     */
    function setValidatorPosition(address validator, uint256 index, uint256 positionId) internal {
        bytes32 baseSlot = keccak256(abi.encodePacked(validator, VALIDATOR_POSITIONS_SLOT));
        bytes32 indexSlot = keccak256(abi.encodePacked(baseSlot));
        indexSlot = bytes32(uint256(indexSlot) + index);
        assembly {
            sstore(indexSlot, positionId)
        }
    }

    /**
     * @notice Set total positions
     * @param newTotal New total positions
     */
    function setTotalPositions(uint256 newTotal) internal {
        StorageSlot.getUint256Slot(TOTAL_POSITIONS_SLOT).value = newTotal;
    }

    // ---------------------------------- GETTERS FOR SLOTS ----------------------------------

    /**
     * @notice Get staking position
     * @param id Position ID
     * @return position Staking position
     */
    function getStakingPosition(uint256 id) public view returns (StakingPosition memory position) {
        bytes32 slot = keccak256(abi.encodePacked(id, STAKING_POSITIONS_SLOT));
        assembly {
            position := sload(slot)
        }
    }

    /**
     * @notice Get validator position
     * @param validator Validator address
     * @param index Index of the position
     * @return positionId Position ID
     */
    function getValidatorPosition(address validator, uint256 index) public view returns (uint256 positionId) {
        // Step 1: Find storage slot of the array's length
        bytes32 baseSlot = keccak256(abi.encodePacked(validator, VALIDATOR_POSITIONS_SLOT));
        // Step 2: Use dynamic array layout
        bytes32 indexSlot = keccak256(abi.encodePacked(baseSlot));
        indexSlot = bytes32(uint256(indexSlot) + index); // array[index]

        assembly {
            positionId := sload(indexSlot)
        }
    }

    /**
     * @notice Get total positions
     * @return total Total positions
     */
    function getTotalPositions() public view returns (uint256 total) {
        total = StorageSlot.getUint256Slot(TOTAL_POSITIONS_SLOT).value;
    }

    /**
     * @dev Get bonding block
     * @return bondingBlock Block when validator was bonded
     */
    function getBondingBlock() external view returns (uint256) {
        return StorageSlot.getUint256Slot(BONDING_BLOCK_SLOT).value;
    }

        /**
     * @dev Get validator information
     * @return owner Validator owner address
     * @return stake Current stake amount
     * @return isActive Whether validator is active
     * @return bondingBlock Block when validator was bonded
     */
    function getValidatorInfo() external view returns (
        address owner,
        uint256 stake,
        bool isActive,
        uint256 bondingBlock
    ) {
        owner = StorageSlot.getAddressSlot(VALIDATOR_OWNER_SLOT).value;
        stake = StorageSlot.getUint256Slot(STAKE_AMOUNT_SLOT).value;
        isActive = StorageSlot.getBooleanSlot(IS_ACTIVE_SLOT).value;
        bondingBlock = StorageSlot.getUint256Slot(BONDING_BLOCK_SLOT).value;
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

    /**
     * @dev Check if validator is active
     * @return isActive Whether validator is active
     */
    function isActive() external view returns (bool) {
        return StorageSlot.getBooleanSlot(IS_ACTIVE_SLOT).value;
    }

    // ---------------------------------- INTERNAL FUNCTIONS ----------------------------------

    /**
     * @dev Internal function to create a new staking position
     * @param owner Position owner
     * @param amount Stake amount
     * @param description Position description
     * @return positionId ID of the created position
     */
    function _createStakingPosition(address owner, uint256 amount) internal returns (uint256 positionId) {
        uint256 total = getTotalPositions();
        positionId = total + 1;
        setTotalPositions(positionId);

        StakingPosition memory position = StakingPosition({
            id: positionId,
            amount: amount,
            timestamp: block.timestamp,
            bondingBlock: block.number,
            lastWithdrawalTimestamp: block.timestamp
        });

        setStakingPosition(positionId, position);

        uint256 index = 0;
        while (true) {
            if (getValidatorPosition(owner, index) == 0) {
                break;
            }
            index++;
        }
        setValidatorPosition(owner, index, positionId);

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
        uint256 totalPositions = getTotalPositions();
        uint256 remaining = amount;
        uint256 unstaked = 0;

        // LIFO: start from the last position
        for (uint256 i = totalPositions; i > 0 && remaining > 0;) {
            uint256 posId = getValidatorPosition(validator, i - 1);
            if (posId == 0) {
                unchecked { i--; }
                continue;
            }
            StakingPosition memory pos = getStakingPosition(posId);
            if (pos.amount == 0) {
                unchecked { i--; }
                continue;
            }

            uint256 toUnstake = pos.amount > remaining ? remaining : pos.amount;
            pos.amount -= toUnstake;
            remaining -= toUnstake;
            unstaked += toUnstake;

            if (pos.amount == 0) {
                _deleteStakingPosition(posId);
                _deleteValidatorPosition(validator, i - 1);
                emit StakingPositionClosed(validator, posId, toUnstake);
            } else {
                pos.lastWithdrawalTimestamp = block.timestamp;
                setStakingPosition(posId, pos);
                emit StakingPositionDecreased(validator, posId, toUnstake, pos.amount);
            }

            emit StakeDecreased(validator, toUnstake, stakeSlot - unstaked);
            unchecked { i--; }
        }

        return unstaked;
    }

    /**
     * @dev Delete a staking position from storage (sets all fields to zero)
     */
    function _deleteStakingPosition(uint256 posId) internal {
        setStakingPosition(posId, StakingPosition(0,0,0,0,0));
    }

    /**
     * @dev Delete a validator position from the validator's array (sets to zero)
     */
    function _deleteValidatorPosition(address validator, uint256 index) internal {
        setValidatorPosition(validator, index, 0);
    }
}
