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
} 