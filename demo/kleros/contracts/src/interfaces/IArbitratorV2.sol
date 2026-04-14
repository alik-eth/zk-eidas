// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

interface IArbitratorV2 {
    function createDispute(uint256 _numberOfChoices, bytes calldata _extraData) external payable returns (uint256 disputeID);
    function arbitrationCost(bytes calldata _extraData) external view returns (uint256 cost);
}
