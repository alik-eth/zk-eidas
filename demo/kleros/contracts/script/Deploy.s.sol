// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Script.sol";
import "../src/IdentityEscrowArbitrable.sol";

contract DeployScript is Script {
    // KlerosCore on Arbitrum Sepolia
    address constant KLEROS_CORE = 0xE8442307d36e9bf6aB27F1A009F95CE8E11C3479;

    function run() external {
        vm.startBroadcast();
        bytes memory extraData = abi.encodePacked(
            uint256(0),  // General Court
            uint256(3),  // 3 jurors
            uint256(1)   // DisputeKitClassic
        );
        new IdentityEscrowArbitrable(
            IArbitratorV2(KLEROS_CORE),
            extraData
        );
        vm.stopBroadcast();
    }
}
