// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {IArbitratorV2} from "../src/interfaces/IArbitratorV2.sol";
import {IArbitrableV2} from "../src/interfaces/IArbitrableV2.sol";
import {IdentityEscrowArbitrable} from "../src/IdentityEscrowArbitrable.sol";

contract MockArbitrator is IArbitratorV2 {
    uint256 private nextDisputeId;
    uint256 public constant COST = 0.01 ether;

    function arbitrationCost(bytes calldata) external pure override returns (uint256 cost) {
        return COST;
    }

    function createDispute(uint256, bytes calldata) external payable override returns (uint256 disputeID) {
        disputeID = nextDisputeId++;
    }

    function rule(address arbitrable, uint256 disputeId, uint256 ruling) external {
        IArbitrableV2(arbitrable).rule(disputeId, ruling);
    }
}

contract IdentityEscrowArbitrableTest is Test {
    IdentityEscrowArbitrable public escrowContract;
    MockArbitrator public mockArbitrator;

    address holder = makeAddr("holder");
    address disputant = makeAddr("disputant");
    address bystander = makeAddr("bystander");

    bytes32 proofHash = keccak256("proof");
    bytes32 escrowDigest = keccak256("escrow");
    string litCipherRef = "lit://encrypted/abc123";

    function setUp() public {
        mockArbitrator = new MockArbitrator();
        escrowContract = new IdentityEscrowArbitrable(
            IArbitratorV2(address(mockArbitrator)),
            ""
        );
    }

    function test_registerEscrow() public {
        vm.prank(holder);
        uint256 id = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        assertEq(id, 0);
        (
            address creator,
            address _disputant,
            bytes32 _proofHash,
            bytes32 _escrowDigest,
            uint256 _disputeId,
            uint256 _ruling,
            IdentityEscrowArbitrable.Status status
        ) = escrowContract.escrows(id);

        assertEq(creator, holder);
        assertEq(_disputant, address(0));
        assertEq(_proofHash, proofHash);
        assertEq(_escrowDigest, escrowDigest);
        assertEq(_disputeId, 0);
        assertEq(_ruling, 0);
        assertEq(uint256(status), uint256(IdentityEscrowArbitrable.Status.Created));
        assertEq(escrowContract.getLitCipherRef(id), litCipherRef);
        assertEq(escrowContract.escrowCount(), 1);
    }

    function test_createDispute() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        (
            ,
            address _disputant,
            ,
            ,
            ,
            ,
            IdentityEscrowArbitrable.Status status
        ) = escrowContract.escrows(escrowId);

        assertEq(_disputant, disputant);
        assertEq(uint256(status), uint256(IdentityEscrowArbitrable.Status.Disputed));
    }

    function test_rule_reveal() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        // Ruling 2 = reveal
        mockArbitrator.rule(address(escrowContract), 0, 2);

        (
            ,
            ,
            ,
            ,
            ,
            uint256 ruling,
            IdentityEscrowArbitrable.Status status
        ) = escrowContract.escrows(escrowId);

        assertEq(ruling, 2);
        assertEq(uint256(status), uint256(IdentityEscrowArbitrable.Status.Resolved));
    }

    function test_canDecrypt_after_reveal() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        mockArbitrator.rule(address(escrowContract), 0, 2);

        assertTrue(escrowContract.canDecrypt(disputant, escrowId));
        assertFalse(escrowContract.canDecrypt(bystander, escrowId));
        assertFalse(escrowContract.canDecrypt(holder, escrowId));
    }

    function test_canDecrypt_false_before_ruling() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        // No ruling yet
        assertFalse(escrowContract.canDecrypt(disputant, escrowId));
    }

    function test_canDecrypt_false_if_sealed() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        // Ruling 1 = sealed (no reveal)
        mockArbitrator.rule(address(escrowContract), 0, 1);

        assertFalse(escrowContract.canDecrypt(disputant, escrowId));
    }

    function test_createDispute_revert_already_disputed() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        vm.deal(bystander, 1 ether);
        vm.prank(bystander);
        vm.expectRevert(IdentityEscrowArbitrable.AlreadyDisputed.selector);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);
    }

    function test_rule_revert_not_arbitrator() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.01 ether}(escrowId);

        vm.prank(bystander);
        vm.expectRevert(IdentityEscrowArbitrable.ArbitratorOnly.selector);
        escrowContract.rule(0, 2);
    }

    function test_rule_revert_unknown_dispute() public {
        // Ruling for a dispute ID that was never created should revert, not corrupt escrow 0
        vm.prank(address(mockArbitrator));
        vm.expectRevert(IdentityEscrowArbitrable.DisputeNotFound.selector);
        escrowContract.rule(999, 2);
    }

    function test_createDispute_revert_insufficient_fee() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        vm.prank(disputant);
        vm.expectRevert(IdentityEscrowArbitrable.InsufficientFee.selector);
        escrowContract.createDispute{value: 0.001 ether}(escrowId);
    }

    function test_createDispute_refunds_excess() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.deal(disputant, 1 ether);
        uint256 balBefore = disputant.balance;
        vm.prank(disputant);
        escrowContract.createDispute{value: 0.05 ether}(escrowId);
        uint256 balAfter = disputant.balance;

        // Should have paid exactly 0.01 ether (the arbitration cost)
        assertEq(balBefore - balAfter, 0.01 ether);
    }

    function test_updateLitCipherRef() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, "old_ref");

        vm.prank(holder);
        escrowContract.updateLitCipherRef(escrowId, "new_ref");

        assertEq(escrowContract.getLitCipherRef(escrowId), "new_ref");
    }

    function test_updateLitCipherRef_revert_not_creator() public {
        vm.prank(holder);
        uint256 escrowId = escrowContract.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.prank(bystander);
        vm.expectRevert(IdentityEscrowArbitrable.EscrowNotFound.selector);
        escrowContract.updateLitCipherRef(escrowId, "hacked");
    }
}
