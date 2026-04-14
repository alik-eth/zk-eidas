// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IArbitrableV2} from "./interfaces/IArbitrableV2.sol";
import {IArbitratorV2} from "./interfaces/IArbitratorV2.sol";

contract IdentityEscrowArbitrable is IArbitrableV2 {
    enum Status { Created, Disputed, Resolved }

    struct Escrow {
        address creator;
        address disputant;
        bytes32 proofHash;
        bytes32 escrowDigest;
        uint256 disputeId;
        uint256 ruling;
        Status status;
    }

    IArbitratorV2 public immutable arbitrator;
    bytes public arbitratorExtraData;
    Escrow[] public escrows;
    mapping(uint256 => uint256) public disputeToEscrow;
    string[] public litCipherRefs;

    error ArbitratorOnly();
    error NotDisputed();
    error AlreadyDisputed();
    error AlreadyResolved();
    error EscrowNotFound();
    error InsufficientFee();

    constructor(IArbitratorV2 _arbitrator, bytes memory _extraData) {
        arbitrator = _arbitrator;
        arbitratorExtraData = _extraData;
    }

    function registerEscrow(
        bytes32 proofHash,
        bytes32 escrowDigest,
        string calldata litCipherRef
    ) external returns (uint256 escrowId) {
        escrowId = escrows.length;
        escrows.push(Escrow({
            creator: msg.sender,
            disputant: address(0),
            proofHash: proofHash,
            escrowDigest: escrowDigest,
            disputeId: 0,
            ruling: 0,
            status: Status.Created
        }));
        litCipherRefs.push(litCipherRef);
    }

    function createDispute(uint256 escrowId) external payable {
        if (escrowId >= escrows.length) revert EscrowNotFound();
        Escrow storage e = escrows[escrowId];
        if (e.status == Status.Disputed) revert AlreadyDisputed();
        if (e.status == Status.Resolved) revert AlreadyResolved();

        uint256 cost = arbitrator.arbitrationCost(arbitratorExtraData);
        if (msg.value < cost) revert InsufficientFee();

        uint256 disputeId = arbitrator.createDispute{value: msg.value}(2, arbitratorExtraData);
        e.disputant = msg.sender;
        e.disputeId = disputeId;
        e.status = Status.Disputed;
        disputeToEscrow[disputeId] = escrowId;

        emit DisputeRequest(arbitrator, disputeId, 0);
    }

    function rule(uint256 _disputeID, uint256 _ruling) external override {
        if (msg.sender != address(arbitrator)) revert ArbitratorOnly();
        uint256 escrowId = disputeToEscrow[_disputeID];
        Escrow storage e = escrows[escrowId];
        if (e.status != Status.Disputed) revert NotDisputed();

        e.ruling = _ruling;
        e.status = Status.Resolved;
        emit Ruling(IArbitratorV2(msg.sender), _disputeID, _ruling);
    }

    function canDecrypt(address caller, uint256 escrowId) external view returns (bool) {
        if (escrowId >= escrows.length) return false;
        Escrow storage e = escrows[escrowId];
        return e.ruling == 2 && caller == e.disputant;
    }

    function arbitrationCost() external view returns (uint256) {
        return arbitrator.arbitrationCost(arbitratorExtraData);
    }

    function getLitCipherRef(uint256 escrowId) external view returns (string memory) {
        return litCipherRefs[escrowId];
    }

    function escrowCount() external view returns (uint256) {
        return escrows.length;
    }
}
