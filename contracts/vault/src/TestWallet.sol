// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// TEST ONLY. A contract wallet in the EIP-1271 sense: it holds tokens and
/// says whether a signature speaks for it. This one accepts exactly the
/// signature bytes it was constructed with, for any digest, or nothing.
contract TestWallet {
    bytes32 public immutable accepted;

    constructor(bytes memory signature) {
        accepted = keccak256(signature);
    }

    function isValidSignature(bytes32, bytes calldata signature) external view returns (bytes4) {
        return keccak256(signature) == accepted ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}
