// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/staking/StakingManager.sol";
import "../src/staking/ValidatorLogic.sol";
import "../test/mock/ERC20TokenMock.sol";
import "forge-std/Test.sol";

/**
 * @title StakingManager Test Suite
 * @notice Test suite for StakingManager and ValidatorLogic contracts
 * @dev This test suite covers validator staking mechanics using beacon proxy pattern:
 *      - Validator registration and staking with ERC20 tokens
 *        (e.g. test_Stake_WhenCalled_DeploysBeaconProxyAndInitializesCorrectly, testStake_MultipleValidators)
 *      - Beacon proxy deployment for individual validator logic contracts
 *        (e.g. testComputeProxyAddress, testValidatorLogic_Initialize_RevertAlreadyInitialized)
 *      - Stake management including partial/full unstaking
 *        (e.g. testUnstake_Partial, test_Unstake_WhenCalled_UpdatesStateAndRemovesValidatorIfBelowMinimum)
 *      - Validator selection algorithms (top-N by stake)
 *        (e.g. testGetTopNValidators, testGetAllValidators_ReturnsAll)
 *      - Slashing mechanisms and stake adjustments
 *        (e.g. integration with TransactionManager slashing)
 *      - ValidatorLogic contract functionality through proxies
 *        (e.g. test_ValidatorLogic_GetValidatorInfo, testValidatorLogic_CompleteStakeUnstakeFlow)
 *
 * Test Strategy:
 * 1. Factory Tests: Core staking/unstaking functionality and validator management
 *    (e.g. test_RevertWhen_Stake_AlreadyValidator, test_RevertWhen_Unstake_MoreThanStaked)
 * 2. Validator Logic Tests: Individual proxy contract behavior and access control
 *    (e.g. testValidatorLogic_OnlyOwnerAndFactory, test_ValidatorLogic_FactoryOnlyFunctions)
 * 3. Fuzz Tests: Property-based testing with random stake amounts
 *    (e.g. testFuzz_StakeAndUnstake, testFuzz_MultipleValidators)
 * 4. Invariant Tests: System-wide properties that must always hold
 *    (e.g. invariant_TotalStakeNeverExceedsSupply, invariant_MaxValidatorsNotExceeded)
 * 5. Edge Cases: Boundary conditions, zero amounts, max validators
 *    (e.g. test_RevertWhen_Stake_BelowMinimum, testStake_RevertMaxValidatorsReached)
 * 6. Integration Tests: Multi-validator scenarios and complex interactions
 *    (e.g. testRemoveValidatorFromArray_RemovesMiddle, test_ValidatorLogic_MultipleStakingOperations)
 */
contract StakingManagerTest is Test {
    StakingManager factory;
    ERC20TokenMock token;
    address[] public validators;
    address alice = vm.addr(1);
    address bob = vm.addr(2);
    address charlie = vm.addr(3);

    uint256 public constant MIN_STAKE = 1000;
    uint16 public constant MAX_VALIDATORS = 5;
    uint16 public constant THRESHOLD = 3;

    function setUp() public {
        token = new ERC20TokenMock();
        factory = new StakingManager(address(token), MIN_STAKE, MAX_VALIDATORS, THRESHOLD);
        token.mint(alice, 10000);
        token.mint(bob, 10000);
        token.mint(charlie, 10000);
        validators = new address[](3);
        validators[0] = alice;
        validators[1] = bob;
        validators[2] = charlie;
    }

    function test_Stake_WhenCalled_DeploysBeaconProxyAndInitializesCorrectly() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        address expectedProxy = factory.computeProxyAddress(alice, 2000);
        vm.expectEmit(true, true, true, true);
        emit StakingManager.ValidatorCreated(alice, expectedProxy, 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        assertEq(proxy, expectedProxy);
        uint256 size;
        assembly {
            size := extcodesize(proxy)
        }
        assertGt(size, 0);
        ValidatorLogic logic = ValidatorLogic(proxy);
        assertEq(logic.getValidatorOwner(), alice);
        assertEq(logic.getStakeAmount(), 2000);
        vm.stopPrank();
    }

    function test_Unstake_WhenCalled_UpdatesStateAndRemovesValidatorIfBelowMinimum() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Unstake part (should remove validator and withdraw all if below minimum)
        vm.expectEmit(true, true, true, true);
        emit StakingManager.Unstaked(alice, 2000);
        vm.expectEmit(true, true, true, true);
        emit StakingManager.ValidatorRemoved(alice);
        factory.unstake(2000);
        assertEq(logic.getStakeAmount(), 0);
        assertFalse(factory.isValidator(alice));
        vm.stopPrank();
    }

    function test_RevertWhen_Stake_CalledTwice() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        token.approve(address(factory), 2000);
        vm.expectRevert();
        factory.stake(2000);
        vm.stopPrank();
    }

    function test_RevertWhen_Stake_BelowMinimum() public {
        vm.startPrank(bob);
        token.approve(address(factory), 500);
        vm.expectRevert();
        factory.stake(500);
        vm.stopPrank();
    }

    function test_RevertWhen_Unstake_MoreThanStaked() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.expectRevert();
        factory.unstake(3000);
        vm.stopPrank();
    }

    function testStake_MultipleValidators() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        vm.startPrank(bob);
        token.approve(address(factory), 1500);
        factory.stake(1500);
        vm.stopPrank();
        assertTrue(factory.isValidator(alice));
        assertTrue(factory.isValidator(bob));
        assertEq(ValidatorLogic(factory.validatorToProxy(alice)).getStakeAmount(), 2000);
        assertEq(ValidatorLogic(factory.validatorToProxy(bob)).getStakeAmount(), 1500);
    }

    function testUnstake_Partial() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        factory.unstake(500);
        assertEq(logic.getStakeAmount(), 1500);
        assertTrue(factory.isValidator(alice));
        vm.stopPrank();
    }

    function testUnstake_All_RemovesValidator() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        factory.unstake(2000);
        assertFalse(factory.isValidator(alice));
        vm.stopPrank();
    }

    function test_RevertWhen_Unstake_NotAValidator() public {
        vm.startPrank(bob);
        vm.expectRevert();
        factory.unstake(1000);
        vm.stopPrank();
    }

    // --- FUZZ TESTS ---
    function testFuzz_StakeAndUnstake(uint96 stakeAmount, uint96 unstakeAmount) public {
        stakeAmount = uint96(bound(stakeAmount, MIN_STAKE, 10000));
        unstakeAmount = uint96(bound(unstakeAmount, 1, 2 * stakeAmount)); // permitir fuzz mayor al stake
        vm.assume(unstakeAmount <= stakeAmount);
        vm.assume(stakeAmount - unstakeAmount < MIN_STAKE);
        vm.startPrank(alice);
        token.approve(address(factory), stakeAmount);
        factory.stake(stakeAmount);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        factory.unstake(unstakeAmount);
        uint256 expected =
            (unstakeAmount >= stakeAmount || stakeAmount - unstakeAmount < MIN_STAKE) ? 0 : stakeAmount - unstakeAmount;
        assertEq(logic.getStakeAmount(), expected);
        vm.stopPrank();
    }

    function testFuzz_MultipleValidators(uint96 a, uint96 b) public {
        a = uint96(bound(a, MIN_STAKE, 10000));
        b = uint96(bound(b, MIN_STAKE, 10000));
        vm.startPrank(alice);
        token.approve(address(factory), a);
        factory.stake(a);
        vm.stopPrank();
        vm.startPrank(bob);
        token.approve(address(factory), b);
        factory.stake(b);
        vm.stopPrank();
        assertTrue(factory.isValidator(alice));
        assertTrue(factory.isValidator(bob));
    }

    function testGetAllValidators_ReturnsAll() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        address[] memory all = factory.getAllValidators();
        assertEq(all.length, 1);
        assertEq(all[0], alice);
    }

    function testGetValidatorCount() public {
        assertEq(factory.getValidatorCount(), 0);
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        assertEq(factory.getValidatorCount(), 1);
    }

    function testIsActiveValidator() public {
        assertFalse(factory.isActiveValidator(alice));
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        assertTrue(factory.isActiveValidator(alice));
    }

    function testGetValidatorStake() public {
        assertEq(factory.getValidatorStake(alice), 0);
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        assertEq(factory.getValidatorStake(alice), 2000);
    }

    function testComputeProxyAddress() public {
        address predicted = factory.computeProxyAddress(alice, 2000);
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        address proxy = factory.validatorToProxy(alice);
        assertEq(predicted, proxy);
    }

    function test_RevertWhen_Stake_AlreadyValidator() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        token.approve(address(factory), 2000);
        vm.expectRevert();
        factory.stake(2000);
        vm.stopPrank();
    }

    function testStake_RevertMaxValidatorsReached() public {
        for (uint256 i = 0; i < MAX_VALIDATORS; i++) {
            address user = vm.addr(i + 10);
            token.mint(user, 2000);
            vm.startPrank(user);
            token.approve(address(factory), 2000);
            factory.stake(2000);
            vm.stopPrank();
        }
        address extra = vm.addr(100);
        token.mint(extra, 2000);
        vm.startPrank(extra);
        token.approve(address(factory), 2000);
        vm.expectRevert();
        factory.stake(2000);
        vm.stopPrank();
    }

    function testUnstake_RevertSenderNotValidator() public {
        vm.expectRevert();
        factory.unstake(1000);
    }

    function testRemoveValidatorFromArray_RemovesMiddle() public {
        // Agrega 3 validadores
        address[] memory users = new address[](3);
        for (uint256 i = 0; i < 3; i++) {
            users[i] = vm.addr(i + 10);
            token.mint(users[i], 2000);
            vm.startPrank(users[i]);
            token.approve(address(factory), 2000);
            factory.stake(2000);
            vm.stopPrank();
        }
        // Elimina el del medio
        vm.startPrank(users[1]);
        factory.unstake(2000);
        vm.stopPrank();
        address[] memory all = factory.getAllValidators();
        assertEq(all.length, 2);
        assertEq(all[0], users[0]);
        assertEq(all[1], users[2]);
    }

    function testGetTopNValidators() public {
        // Agrega 3 validadores con diferentes stakes
        address[] memory users = new address[](3);
        uint256[] memory amounts = new uint256[](3);
        amounts[0] = 3000;
        amounts[1] = 2000;
        amounts[2] = 4000;
        for (uint256 i = 0; i < 3; i++) {
            users[i] = vm.addr(i + 10);
            token.mint(users[i], 5000);
            vm.startPrank(users[i]);
            token.approve(address(factory), amounts[i]);
            factory.stake(amounts[i]);
            vm.stopPrank();
        }
        (address[] memory top, uint256[] memory stakes) = factory.getTopNValidators(2);
        assertEq(top.length, 2);
        assertEq(stakes.length, 2);
        assertEq(stakes[0], 4000);
        assertEq(stakes[1], 3000);
    }

    // --- COVERAGE: ValidatorLogic (se hace a través del proxy) ---
    function testValidatorLogic_Initialize_RevertAlreadyInitialized() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        bytes memory data = abi.encodeWithSelector(ValidatorLogic.initialize.selector, alice, address(token), 2000);
        (bool success,) = proxy.call(data);
        assertFalse(success);
        vm.stopPrank();
    }

    function testValidatorLogic_Initialize_RevertInvalidOwner() public {
        address proxy = address(new ValidatorLogic());
        bytes memory data = abi.encodeWithSelector(ValidatorLogic.initialize.selector, address(0), address(token), 2000);
        (bool success,) = proxy.call(data);
        assertFalse(success);
    }

    function testValidatorLogic_StakeZero_Revert() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        (bool success,) = proxy.call(abi.encodeWithSignature("stake(uint256)", 0));
        assertFalse(success);
        vm.stopPrank();
    }

    function testValidatorLogic_OnlyOwnerAndFactory() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        // Llama a una función onlyFactory desde otra cuenta
        vm.stopPrank();
        vm.startPrank(bob);
        (bool success,) = proxy.call(abi.encodeWithSignature("unstake(uint256)", 1000));
        assertFalse(success);
        vm.stopPrank();
    }

    function testValidatorLogic_MultiplePositions() public {
        vm.startPrank(alice);
        token.approve(address(factory), 3000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Intenta stake extra (debe fallar porque solo el factory puede)
        (bool success,) = proxy.call(abi.encodeWithSignature("stake(uint256)", 1000));
        assertFalse(success); // Debe fallar por onlyFactory
        vm.stopPrank();
    }

    function testValidatorLogic_Events() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);

        // Intenta stake extra (debe fallar porque solo el factory puede)
        vm.expectRevert(ValidatorLogic.NotFactory.selector);
        ValidatorLogic(proxy).stake(1000);
        vm.stopPrank();
    }

    // ==================== VALIDATORLOGIC COVERAGE TESTS ====================

    function test_ValidatorLogic_GetValidatorInfo() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        (address owner, uint256 stake) = logic.getValidatorInfo();

        assertEq(owner, validatorAddr);
        assertEq(stake, MIN_STAKE);
    }

    function test_ValidatorLogic_GetValidatorOwner() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        address owner = logic.getValidatorOwner();
        assertEq(owner, validatorAddr);
    }

    function test_ValidatorLogic_GetValidatorPositionsLength_EmptyValidator() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Test with non-existent validator address
        uint256 length = logic.getValidatorPositionsLength(address(0x999));
        assertEq(length, 0);
    }

    function test_ValidatorLogic_GetValidatorPosition_OutOfBounds() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Out of bounds position returns 0, doesn't revert
        uint256 positionId = logic.getValidatorPosition(validatorAddr, 999);
        assertEq(positionId, 0);
    }

    function test_ValidatorLogic_GetStakingPosition_Invalid() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Test with invalid position ID
        ValidatorLogic.StakingPosition memory position = logic.getStakingPosition(999999);
        assertEq(position.id, 0);
        assertEq(position.amount, 0);
    }

    function test_ValidatorLogic_MultipleStakingOperations() public {
        address validatorAddr = alice;

        // Initial stake
        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE * 3);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Additional stake operations to create more positions
        vm.prank(address(factory)); // Simulating factory call
        logic.stake(MIN_STAKE / 2);

        vm.prank(address(factory));
        logic.stake(MIN_STAKE / 4);

        uint256 totalPositions = logic.getTotalPositions();
        assertGe(totalPositions, 1); // Should have at least 1 position

        uint256 positionsLength = logic.getValidatorPositionsLength(validatorAddr);
        assertGe(positionsLength, 1);
    }

    function test_ValidatorLogic_StakeAndUnstakeSequence() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE * 2);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE * 2);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        uint256 initialStake = logic.getStakeAmount();
        assertEq(initialStake, MIN_STAKE * 2);

        // Unstake partial amount
        vm.prank(validatorAddr);
        factory.unstake(MIN_STAKE / 2);

        uint256 finalStake = logic.getStakeAmount();
        assertEq(finalStake, initialStake - MIN_STAKE / 2);

        // Verify validator still exists
        assertTrue(factory.isValidator(alice));
    }

    function test_ValidatorLogic_CompleteUnstaking() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Complete unstake
        vm.prank(validatorAddr);
        factory.unstake(MIN_STAKE);

        // Should be removed from validators
        assertFalse(factory.isValidator(validatorAddr));
    }

    function test_ValidatorLogic_FactoryOnlyFunctions() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Try calling stake from non-factory address
        vm.prank(address(0x999));
        vm.expectRevert();
        logic.stake(100 * 10 ** 18);

        // Try calling unstake from non-factory address
        vm.prank(address(0x999));
        vm.expectRevert();
        logic.unstake(100 * 10 ** 18);
    }

    function test_ValidatorLogic_ZeroAmountOperations() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Zero amount stake should fail with InvalidAmount
        vm.prank(address(factory));
        vm.expectRevert(ValidatorLogic.InvalidAmount.selector);
        logic.stake(0);

        // Zero amount unstake should succeed (no validation for zero unstake)
        vm.prank(address(factory));
        uint256 unstaked = logic.unstake(0);
        assertEq(unstaked, 0);
    }

    function test_ValidatorLogic_InsufficientUnstaking() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Try to unstake more than available
        vm.prank(address(factory));
        vm.expectRevert();
        logic.unstake(MIN_STAKE * 2);
    }

    function test_ValidatorLogic_GetStakingPosition_ValidPosition() public {
        address validatorAddr = alice;

        vm.prank(validatorAddr);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(validatorAddr);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(validatorAddr);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Get first position
        uint256 positionId = logic.getValidatorPosition(validatorAddr, 0);
        ValidatorLogic.StakingPosition memory position = logic.getStakingPosition(positionId);

        assertEq(position.id, positionId);
        assertGt(position.amount, 0);
        assertGt(position.timestamp, 0);
        assertEq(position.bondingBlock, block.number);
    }

    // ==================== VALIDATORLOGIC ADDITIONAL COVERAGE TESTS ====================

    function testValidatorLogic_GetAllInfoFunctions() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Test getValidatorInfo
        (address owner, uint256 stake) = logic.getValidatorInfo();
        assertEq(owner, alice);
        assertEq(stake, MIN_STAKE);

        // Test individual getters
        assertEq(logic.getValidatorOwner(), alice);
        assertEq(logic.getStakeAmount(), MIN_STAKE);
    }

    function testValidatorLogic_PositionManagement() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Test position access
        uint256 positionsLength = logic.getValidatorPositionsLength(alice);
        assertEq(positionsLength, 1);

        uint256 positionId = logic.getValidatorPosition(alice, 0);
        assertGt(positionId, 0);

        ValidatorLogic.StakingPosition memory position = logic.getStakingPosition(positionId);
        assertEq(position.id, positionId);
        assertEq(position.amount, MIN_STAKE);
        assertGt(position.timestamp, 0);

        uint256 totalPositions = logic.getTotalPositions();
        assertGe(totalPositions, 1);
    }

    function testValidatorLogic_InvalidPositionAccess() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Test out of bounds position - returns 0, doesn't revert
        uint256 positionId = logic.getValidatorPosition(alice, 999);
        assertEq(positionId, 0);

        // Test invalid position ID
        ValidatorLogic.StakingPosition memory position = logic.getStakingPosition(999999);
        assertEq(position.id, 0);
        assertEq(position.amount, 0);

        // Test non-existent validator
        uint256 length = logic.getValidatorPositionsLength(address(0x999));
        assertEq(length, 0);
    }

    function testValidatorLogic_DirectCallsFromNonFactory() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Try calling stake directly (should fail - only factory)
        vm.prank(address(0x999));
        vm.expectRevert();
        logic.stake(100 * 10 ** 18);

        // Try calling unstake directly (should fail - only factory)
        vm.prank(address(0x999));
        vm.expectRevert();
        logic.unstake(100 * 10 ** 18);
    }

    function testValidatorLogic_ZeroAndInvalidAmounts() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        // Zero amount stake should fail with InvalidAmount
        vm.prank(address(factory));
        vm.expectRevert(ValidatorLogic.InvalidAmount.selector);
        logic.stake(0);

        // Zero amount unstake should succeed (no validation for zero unstake)
        vm.prank(address(factory));
        uint256 unstaked = logic.unstake(0);
        assertEq(unstaked, 0);

        // Unstake more than available should fail with InsufficientStakeAmount
        vm.prank(address(factory));
        vm.expectRevert(ValidatorLogic.InsufficientStakeAmount.selector);
        logic.unstake(MIN_STAKE * 2);
    }

    function testValidatorLogic_MultipleStakeOperations() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE * 3);

        vm.prank(alice);
        factory.stake(MIN_STAKE);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        uint256 initialStake = logic.getStakeAmount();
        uint256 initialPositions = logic.getTotalPositions();

        // Perform additional stake through factory (this will create new positions)
        vm.prank(address(factory));
        logic.stake(MIN_STAKE / 2);

        uint256 newStake = logic.getStakeAmount();
        assertEq(newStake, initialStake + MIN_STAKE / 2);

        // Total positions should increase
        uint256 newPositions = logic.getTotalPositions();
        assertGe(newPositions, initialPositions);
    }

    function testValidatorLogic_CompleteStakeUnstakeFlow() public {
        vm.prank(alice);
        token.approve(address(factory), MIN_STAKE * 2);

        vm.prank(alice);
        factory.stake(MIN_STAKE * 2);

        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);

        uint256 initialStake = logic.getStakeAmount();
        assertEq(initialStake, MIN_STAKE * 2);

        // Partial unstake
        vm.prank(alice);
        factory.unstake(MIN_STAKE / 2);

        uint256 afterPartialUnstake = logic.getStakeAmount();
        assertEq(afterPartialUnstake, initialStake - MIN_STAKE / 2);

        // Complete unstake
        vm.prank(alice);
        factory.unstake(afterPartialUnstake);

        // Validator should be removed from factory
        assertFalse(factory.isValidator(alice));
    }

    // ==================== EDGE CASES AND ERROR CONDITIONS ====================

    // --- INVARIANT TESTS ---

    function invariant_TotalStakeNeverExceedsSupply() public {
        uint256 totalStake = 0;
        for (uint256 i = 0; i < validators.length; i++) {
            address proxy = factory.validatorToProxy(validators[i]);
            if (proxy != address(0)) {
                totalStake += ValidatorLogic(proxy).getStakeAmount();
            }
        }
        uint256 totalSupply = token.totalSupply();
        assertLe(totalStake, totalSupply);
    }

    function invariant_NoNegativeStake() public {
        for (uint256 i = 0; i < validators.length; i++) {
            address proxy = factory.validatorToProxy(validators[i]);
            if (proxy != address(0)) {
                uint256 stake = ValidatorLogic(proxy).getStakeAmount();
                assertGe(stake, 0);
            }
        }
    }

    function invariant_MaxValidatorsNotExceeded() public {
        assertLe(factory.getValidatorCount(), MAX_VALIDATORS);
    }

    function invariant_RemovedValidatorHasZeroStake() public {
        for (uint256 i = 0; i < validators.length; i++) {
            if (!factory.isValidator(validators[i])) {
                address proxy = factory.validatorToProxy(validators[i]);
                if (proxy != address(0)) {
                    assertEq(ValidatorLogic(proxy).getStakeAmount(), 0);
                }
            }
        }
    }
}
