// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// TEST ONLY. Not a verifier. It accepts one publicly computable value per
/// program and journal digest and refuses anything else, so the vault's
/// behaviour can be tested without producing a proof. An order that names
/// this contract has no proof-governed acceptance at all.
contract TestVerifier {
    error Refused();

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external pure {
        if (seal.length != 32 || bytes32(seal) != keccak256(abi.encode(imageId, journalDigest))) revert Refused();
    }

    function isTestStandIn() external pure returns (bool) {
        return true;
    }
}
