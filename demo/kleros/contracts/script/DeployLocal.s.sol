// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/MockArbitrator.sol";
import "../src/IdentityEscrowArbitrable.sol";

/// @notice Deploy MockArbitrator + IdentityEscrowArbitrable to Anvil for local testing.
contract DeployLocalScript is Script {
    function run() external {
        vm.startBroadcast();

        MockArbitrator arbitrator = new MockArbitrator();
        bytes memory extraData = abi.encodePacked(
            uint256(0),  // General Court
            uint256(3),  // 3 jurors
            uint256(1)   // DisputeKitClassic
        );
        IdentityEscrowArbitrable escrow = new IdentityEscrowArbitrable(
            IArbitratorV2(address(arbitrator)),
            extraData
        );

        vm.stopBroadcast();

        console.log("MockArbitrator:", address(arbitrator));
        console.log("IdentityEscrowArbitrable:", address(escrow));
    }
}
