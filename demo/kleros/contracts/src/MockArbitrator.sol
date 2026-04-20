// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IArbitratorV2} from "./interfaces/IArbitratorV2.sol";
import {IArbitrableV2} from "./interfaces/IArbitrableV2.sol";

/// @notice Mock arbitrator for local testing. Allows anyone to trigger rulings.
contract MockArbitrator is IArbitratorV2 {
    uint256 private nextDisputeId;
    uint256 public constant COST = 0.01 ether;

    function arbitrationCost(bytes calldata) external pure override returns (uint256 cost) {
        return COST;
    }

    function createDispute(uint256, bytes calldata) external payable override returns (uint256 disputeID) {
        disputeID = nextDisputeId++;
    }

    /// @notice Trigger a ruling on an arbitrable contract. Only for testing.
    function rule(address arbitrable, uint256 disputeId, uint256 ruling) external {
        IArbitrableV2(arbitrable).rule(disputeId, ruling);
    }
}
