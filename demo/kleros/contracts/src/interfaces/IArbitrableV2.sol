// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {IArbitratorV2} from "./IArbitratorV2.sol";

interface IArbitrableV2 {
    event DisputeRequest(IArbitratorV2 indexed _arbitrator, uint256 indexed _arbitratorDisputeID, uint256 _templateId);
    event Ruling(IArbitratorV2 indexed _arbitrator, uint256 indexed _disputeID, uint256 _ruling);
    function rule(uint256 _disputeID, uint256 _ruling) external;
}
