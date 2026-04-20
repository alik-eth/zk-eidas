// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {IArbitrableV2} from "../src/interfaces/IArbitrableV2.sol";
import {IArbitratorV2} from "../src/interfaces/IArbitratorV2.sol";
import {IdentityEscrowArbitrable} from "../src/IdentityEscrowArbitrable.sol";
import {MockArbitrator} from "../src/MockArbitrator.sol";

/// @notice End-to-end test simulating the full demo flow:
///   Holder registers escrow → Disputant files dispute → Arbitrator rules →
///   Disputant can decrypt (or not, depending on ruling)
contract E2ETest is Test {
    MockArbitrator arbitrator;
    IdentityEscrowArbitrable escrow;

    address holder = makeAddr("holder");
    address disputant = makeAddr("disputant");
    address otherParty = makeAddr("otherParty");

    // Simulate real-ish data
    bytes32 proofHash = keccak256("compound-proof-with-escrow-json-blob");
    bytes32 escrowDigest = keccak256("sha256-of-packed-8x32-escrow-fields");
    string litCipherRef = '{"ciphertext":"eyJpZGVudGl0eV9lc2Nyb3ciOnsi","dataToEncryptHash":"abc123"}';

    function setUp() public {
        arbitrator = new MockArbitrator();
        bytes memory extraData = abi.encodePacked(
            uint256(0),  // General Court
            uint256(3),  // 3 jurors
            uint256(1)   // DisputeKitClassic
        );
        escrow = new IdentityEscrowArbitrable(
            IArbitratorV2(address(arbitrator)),
            extraData
        );
        vm.deal(holder, 10 ether);
        vm.deal(disputant, 10 ether);
        vm.deal(otherParty, 10 ether);
    }

    /// @notice Happy path: register → dispute → reveal ruling → disputant can decrypt
    function test_e2e_happy_path_reveal() public {
        // === Step 1: Holder registers escrow ===
        vm.prank(holder);
        uint256 escrowId = escrow.registerEscrow(proofHash, escrowDigest, litCipherRef);
        assertEq(escrowId, 0);
        assertEq(escrow.escrowCount(), 1);
        assertEq(escrow.getLitCipherRef(escrowId), litCipherRef);

        // Verify initial state
        (address creator,,,,, uint256 ruling, IdentityEscrowArbitrable.Status status)
            = escrow.escrows(escrowId);
        assertEq(creator, holder);
        assertEq(ruling, 0);
        assertEq(uint8(status), uint8(IdentityEscrowArbitrable.Status.Created));

        // Nobody can decrypt yet
        assertFalse(escrow.canDecrypt(holder, escrowId));
        assertFalse(escrow.canDecrypt(disputant, escrowId));

        // === Step 2: Disputant files a dispute ===
        uint256 cost = escrow.arbitrationCost();
        assertEq(cost, 0.01 ether);

        vm.prank(disputant);
        escrow.createDispute{value: cost}(escrowId);

        (,address storedDisputant,,,uint256 disputeId,, IdentityEscrowArbitrable.Status status2)
            = escrow.escrows(escrowId);
        assertEq(storedDisputant, disputant);
        assertEq(uint8(status2), uint8(IdentityEscrowArbitrable.Status.Disputed));

        // Still nobody can decrypt
        assertFalse(escrow.canDecrypt(disputant, escrowId));

        // === Step 3: Arbitrator delivers ruling = 2 (Reveal Identity) ===
        arbitrator.rule(address(escrow), disputeId, 2);

        (,,,,, uint256 finalRuling, IdentityEscrowArbitrable.Status status3)
            = escrow.escrows(escrowId);
        assertEq(finalRuling, 2);
        assertEq(uint8(status3), uint8(IdentityEscrowArbitrable.Status.Resolved));

        // === Step 4: Disputant can decrypt, nobody else can ===
        assertTrue(escrow.canDecrypt(disputant, escrowId));
        assertFalse(escrow.canDecrypt(holder, escrowId));
        assertFalse(escrow.canDecrypt(otherParty, escrowId));

        // Lit cipher ref is still readable
        assertEq(escrow.getLitCipherRef(escrowId), litCipherRef);
    }

    /// @notice Ruling = 1 (Keep Sealed): nobody can decrypt
    function test_e2e_sealed_ruling() public {
        vm.prank(holder);
        uint256 escrowId = escrow.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.prank(disputant);
        escrow.createDispute{value: 0.01 ether}(escrowId);

        (,,,,uint256 disputeId,,) = escrow.escrows(escrowId);
        arbitrator.rule(address(escrow), disputeId, 1); // Keep Sealed

        (,,,,, uint256 ruling,) = escrow.escrows(escrowId);
        assertEq(ruling, 1);

        // Nobody can decrypt when sealed
        assertFalse(escrow.canDecrypt(disputant, escrowId));
        assertFalse(escrow.canDecrypt(holder, escrowId));
        assertFalse(escrow.canDecrypt(otherParty, escrowId));
    }

    /// @notice Ruling = 0 (Refused to arbitrate): nobody can decrypt
    function test_e2e_refused_ruling() public {
        vm.prank(holder);
        uint256 escrowId = escrow.registerEscrow(proofHash, escrowDigest, litCipherRef);

        vm.prank(disputant);
        escrow.createDispute{value: 0.01 ether}(escrowId);

        (,,,,uint256 disputeId,,) = escrow.escrows(escrowId);
        arbitrator.rule(address(escrow), disputeId, 0); // Refused

        assertFalse(escrow.canDecrypt(disputant, escrowId));
    }

    /// @notice Multiple escrows: disputes are isolated
    function test_e2e_multiple_escrows_isolated() public {
        // Holder registers two escrows
        vm.startPrank(holder);
        uint256 id0 = escrow.registerEscrow(keccak256("proof0"), keccak256("digest0"), "ref0");
        uint256 id1 = escrow.registerEscrow(keccak256("proof1"), keccak256("digest1"), "ref1");
        vm.stopPrank();

        assertEq(id0, 0);
        assertEq(id1, 1);

        // Disputant disputes escrow 0, otherParty disputes escrow 1
        vm.prank(disputant);
        escrow.createDispute{value: 0.01 ether}(id0);

        vm.prank(otherParty);
        escrow.createDispute{value: 0.01 ether}(id1);

        // Reveal escrow 0, seal escrow 1
        (,,,,uint256 disputeId0,,) = escrow.escrows(id0);
        (,,,,uint256 disputeId1,,) = escrow.escrows(id1);
        arbitrator.rule(address(escrow), disputeId0, 2); // Reveal
        arbitrator.rule(address(escrow), disputeId1, 1); // Sealed

        // Disputant can decrypt escrow 0 only
        assertTrue(escrow.canDecrypt(disputant, id0));
        assertFalse(escrow.canDecrypt(disputant, id1)); // not their dispute AND sealed

        // OtherParty can NOT decrypt escrow 1 (sealed) or escrow 0 (not their dispute)
        assertFalse(escrow.canDecrypt(otherParty, id0));
        assertFalse(escrow.canDecrypt(otherParty, id1));
    }

    /// @notice Two-step registration: register with placeholder, then update litCipherRef
    function test_e2e_two_step_registration() public {
        // Step 1: Register with empty ref (get the real escrow ID)
        vm.prank(holder);
        uint256 escrowId = escrow.registerEscrow(proofHash, escrowDigest, "");
        assertEq(escrow.getLitCipherRef(escrowId), "");

        // Step 2: Encrypt to Lit using the confirmed ID, then update ref
        string memory realRef = '{"ciphertext":"real-encrypted-data","dataToEncryptHash":"real-hash"}';
        vm.prank(holder);
        escrow.updateLitCipherRef(escrowId, realRef);
        assertEq(escrow.getLitCipherRef(escrowId), realRef);

        // Only creator can update
        vm.prank(disputant);
        vm.expectRevert(IdentityEscrowArbitrable.EscrowNotFound.selector);
        escrow.updateLitCipherRef(escrowId, "hacked");

        // After dispute, can't update
        vm.prank(disputant);
        escrow.createDispute{value: 0.01 ether}(escrowId);

        vm.prank(holder);
        vm.expectRevert(IdentityEscrowArbitrable.AlreadyDisputed.selector);
        escrow.updateLitCipherRef(escrowId, "too-late");
    }

    /// @notice Full flow with excess ETH refund
    function test_e2e_excess_refund() public {
        vm.prank(holder);
        uint256 escrowId = escrow.registerEscrow(proofHash, escrowDigest, litCipherRef);

        uint256 balBefore = disputant.balance;
        vm.prank(disputant);
        escrow.createDispute{value: 1 ether}(escrowId); // way more than 0.01
        uint256 balAfter = disputant.balance;

        // Should only have spent 0.01 ETH
        assertEq(balBefore - balAfter, 0.01 ether);
    }

    /// @notice Events are emitted correctly throughout the flow
    function test_e2e_events() public {
        // Register emits EscrowRegistered
        vm.prank(holder);
        vm.expectEmit(true, true, false, false);
        emit IdentityEscrowArbitrable.EscrowRegistered(0, holder);
        escrow.registerEscrow(proofHash, escrowDigest, litCipherRef);

        // Dispute emits DisputeRequest
        vm.prank(disputant);
        vm.expectEmit(true, true, false, false);
        emit IArbitrableV2.DisputeRequest(IArbitratorV2(address(arbitrator)), 0, 0);
        escrow.createDispute{value: 0.01 ether}(0);

        // Rule emits Ruling
        vm.expectEmit(true, true, false, false);
        emit IArbitrableV2.Ruling(IArbitratorV2(address(arbitrator)), 0, 2);
        arbitrator.rule(address(escrow), 0, 2);
    }
}
