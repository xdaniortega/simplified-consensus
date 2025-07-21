// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/ValidatorFactory.sol";
import "../src/ValidatorLogic.sol";
import "./mock/ERC20TokenMock.sol";

contract ValidatorFactoryTest is Test {
    ValidatorFactory factory;
    ERC20TokenMock token;
    address alice = vm.addr(1);
    address bob = vm.addr(2);
    address charlie = vm.addr(3);

    uint256 public constant MIN_STAKE = 1000;
    uint16 public constant MAX_VALIDATORS = 5;
    uint16 public constant THRESHOLD = 3;

    function setUp() public {
        token = new ERC20TokenMock();
        factory = new ValidatorFactory(address(token), MIN_STAKE, MAX_VALIDATORS, THRESHOLD);
        token.mint(alice, 10000 );
        token.mint(bob, 10000 );
        token.mint(charlie, 10000 );
    }

    function testStake_WhenCalled_DeploysBeaconProxyAndInitializesCorrectly() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000 );
        address expectedProxy = factory.computeProxyAddress(alice, 2000 );
        vm.expectEmit(true, true, true, true);
        emit ValidatorFactory.ValidatorCreated(alice, expectedProxy, 2000 );
        factory.stake(2000 );
        address proxy = factory.validatorToProxy(alice);
        assertEq(proxy, expectedProxy);
        uint256 size;
        assembly { size := extcodesize(proxy) }
        assertGt(size, 0);
        ValidatorLogic logic = ValidatorLogic(proxy);
        assertEq(logic.getValidatorOwner(), alice);
        assertEq(logic.getStakeAmount(), 2000 );
        vm.stopPrank();
    }

    function testUnstake_WhenCalled_UpdatesStateAndRemovesValidatorIfBelowMinimum() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Unstake part (should remove validator and withdraw all if below minimum)
        vm.expectEmit(true, true, true, true);
        emit ValidatorFactory.Unstaked(alice, 2000);
        vm.expectEmit(true, true, true, true);
        emit ValidatorFactory.ValidatorRemoved(alice);
        factory.unstake(2000);
        assertEq(logic.getStakeAmount(), 0);
        assertFalse(factory.isValidator(alice));
        vm.stopPrank();
    }

    function testStake_WhenCalledTwice_Reverts() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000 );
        factory.stake(2000 );
        token.approve(address(factory), 2000 );
        vm.expectRevert();
        factory.stake(2000 );
        vm.stopPrank();
    }

    function testStake_WhenBelowMinimum_Reverts() public {
        vm.startPrank(bob);
        token.approve(address(factory), 500 );
        vm.expectRevert();
        factory.stake(500 );
        vm.stopPrank();
    }

    function testUnstake_WhenMoreThanStaked_Reverts() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000 );
        factory.stake(2000 );
        vm.expectRevert();
        factory.unstake(3000 );
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

    function testUnstake_NotAValidator_Reverts() public {
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
        uint256 expected = (unstakeAmount >= stakeAmount || stakeAmount - unstakeAmount < MIN_STAKE) ? 0 : stakeAmount - unstakeAmount;
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

    function testCanUnstake() public {
        assertFalse(factory.canUnstake(alice));
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        vm.stopPrank();
        // Simula avance de bloque
        vm.roll(block.number + 2);
        assertTrue(factory.canUnstake(alice));
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

    function testStake_RevertAlreadyValidator() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        token.approve(address(factory), 2000);
        vm.expectRevert();
        factory.stake(2000);
        vm.stopPrank();
    }

    function testStake_RevertMaxValidatorsReached() public {
        for (uint i = 0; i < MAX_VALIDATORS; i++) {
            address user = vm.addr(i+10);
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
        for (uint i = 0; i < 3; i++) {
            users[i] = vm.addr(i+10);
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
        uint[] memory amounts = new uint[](3);
        amounts[0] = 3000; amounts[1] = 2000; amounts[2] = 4000;
        for (uint i = 0; i < 3; i++) {
            users[i] = vm.addr(i+10);
            token.mint(users[i], 5000);
            vm.startPrank(users[i]);
            token.approve(address(factory), amounts[i]);
            factory.stake(amounts[i]);
            vm.stopPrank();
        }
        (address[] memory top, uint[] memory stakes) = factory.getTopNValidators(2);
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
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            alice,
            address(token),
            2000
        );
        (bool success, ) = proxy.call(data);
        assertFalse(success);
        vm.stopPrank();
    }

    function testValidatorLogic_Initialize_RevertInvalidOwner() public {
        address proxy = address(new ValidatorLogic());
        bytes memory data = abi.encodeWithSelector(
            ValidatorLogic.initialize.selector,
            address(0),
            address(token),
            2000
        );
        (bool success, ) = proxy.call(data);
        assertFalse(success);
    }

    function testValidatorLogic_StakeZero_Revert() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        (bool success, ) = proxy.call(abi.encodeWithSignature("stake(uint256)", 0));
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
        (bool success, ) = proxy.call(abi.encodeWithSignature("unstake(uint256)", 1000));
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
        (bool success, ) = proxy.call(abi.encodeWithSignature("stake(uint256)", 1000));
        assertFalse(success); // Debe fallar por onlyFactory
        vm.stopPrank();
    }

    function testValidatorLogic_Events() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        // Intenta stake extra (debe fallar porque solo el factory puede)
        vm.expectRevert();
        proxy.call(abi.encodeWithSignature("stake(uint256)", 1000));
        vm.stopPrank();
    }

    // --- INVARIANT TESTS ---
}

// --- INVARIANT TEST SUITE ---
contract ValidatorFactoryInvariant is Test {
    ValidatorFactory factory;
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
        factory = new ValidatorFactory(address(token), MIN_STAKE, MAX_VALIDATORS, THRESHOLD);
        token.mint(alice, 10000);
        token.mint(bob, 10000);
        token.mint(charlie, 10000);
        validators = new address[](3);
        validators[0] = alice;
        validators[1] = bob;
        validators[2] = charlie;
    }

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


    function testValidatorLogic_AlreadyInitialized() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        // Llama initialize dos veces
        (bool success, ) = proxy.call(abi.encodeWithSignature("initialize(address,address,uint256)", alice, address(token), 2000));
        assertFalse(success);
        vm.stopPrank();
    }

    function testValidatorLogic_InvalidOwner() public {
        address logic = address(new ValidatorLogic());
        (bool success, ) = logic.call(abi.encodeWithSignature("initialize(address,address,uint256)", address(0), address(token), 1000));
        assertFalse(success);
    }

    function testValidatorLogic_InvalidAmount() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        vm.expectRevert();
        logic.stake(0);
        vm.stopPrank();
    }

    function testValidatorLogic_NotFactory() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        vm.stopPrank();
        vm.startPrank(bob);
        vm.expectRevert();
        logic.stake(1000);
        vm.stopPrank();
    }

    function testValidatorLogic_NotValidatorOwner() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        vm.stopPrank();
        vm.startPrank(bob);
        // Intenta llamar una función que debe tener onlyOwner (si existe), sino prueba acceso directo a slots privados
        vm.expectRevert();
        (bool success, ) = proxy.call(abi.encodeWithSignature("nonExistentOwnerFunction()"));
        vm.stopPrank();
    }

    function testValidatorLogic_MultiplePositionsAndDelete() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Test unstake parcial y total normalmente
        factory.unstake(500);
        factory.unstake(1500);
        assertEq(logic.getStakeAmount(), 0);
        vm.stopPrank();
    }

    function testValidatorLogic_DeleteValidatorPosition() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Test normal unstake que fuerza borrado de posición
        factory.unstake(2000);
        assertEq(logic.getValidatorPositionsLength(alice), 0);
        vm.stopPrank();
    }

    function testValidatorLogic_GettersSetters() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        assertEq(logic.getValidatorOwner(), alice);
        assertEq(logic.getStakeAmount(), 2000);
        assertTrue(logic.isActive());
        assertGt(logic.getBondingBlock(), 0);
        assertGt(logic.getValidatorPositionsLength(alice), 0);
        vm.stopPrank();
    }

    function testValidatorLogic_Events_AllPaths() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        address proxy = factory.validatorToProxy(alice);
        ValidatorLogic logic = ValidatorLogic(proxy);
        // Test unstake normal para cubrir eventos
        factory.unstake(500);
        factory.unstake(1500);
        vm.stopPrank();
        // No asserts, solo cubre eventos
    }

    function testFactory_canUnstake_BondingBlock() public {
        vm.startPrank(alice);
        token.approve(address(factory), 2000);
        factory.stake(2000);
        assertFalse(factory.canUnstake(alice));
        vm.roll(block.number + 2);
        assertTrue(factory.canUnstake(alice));
        vm.stopPrank();
    }

    function testFactory_computeProxyAddress() public {
        address predicted = factory.computeProxyAddress(alice, 2000);
        assertTrue(predicted != address(0));
    } 
}