// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// A base registry with no entries and no way to add one. A vault that names
/// it pays no royalty to anyone, ever. It stands in until a registry exists
/// that admits a base only on a proof that the base was checked; a vault that
/// should pay royalties must be a later deployment naming that registry.
contract EmptyRegistry {
    function entryOf(bytes32) external pure returns (address payee, uint16 bps) {
        return (address(0), 0);
    }

    /// No entry, so no rate: a third vault reads this at construction.
    function maximumBps() external pure returns (uint16) {
        return 0;
    }
}
