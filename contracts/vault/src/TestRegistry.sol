// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// TEST ONLY. A base registry whose entries anyone can set and which
/// misbehaves on request, to drive the vault's defences red. A vault that
/// names it has no royalty rule worth the name.
contract TestRegistry {
    enum Mode {
        Honest,
        Revert, // entryOf reverts
        Burn, // entryOf loops until it runs out of gas
        Short, // entryOf returns one word
        Long, // entryOf returns three words
        DirtyPayee, // payee word has bits above 160
        HugeBps, // bps word above 10000
        RevertWithEntry // reverts, with a well-formed entry as the revert data
    }

    struct Entry {
        address payee;
        uint16 bps;
    }

    Mode public mode;
    mapping(bytes32 => Entry) public entries;

    function set(bytes32 base, address payee, uint16 bps) external {
        entries[base] = Entry(payee, bps);
    }

    function setMode(Mode m) external {
        mode = m;
    }

    fallback() external {
        // entryOf(bytes32) by hand, so the reply can be malformed.
        bytes32 base;
        assembly {
            base := calldataload(4)
        }
        Entry memory e = entries[base];
        Mode m = mode;
        if (m == Mode.Revert) revert("registry");
        if (m == Mode.Burn) {
            uint256 x;
            while (true) x++;
        }
        uint256 first = uint256(uint160(e.payee));
        uint256 second = e.bps;
        if (m == Mode.DirtyPayee) first |= 1 << 200;
        if (m == Mode.HugeBps) second = 10001;
        uint256 size = m == Mode.Short ? 32 : m == Mode.Long ? 96 : 64;
        bool fail = m == Mode.RevertWithEntry;
        assembly {
            let out := mload(0x40)
            mstore(out, first)
            mstore(add(out, 32), second)
            mstore(add(out, 64), 0)
            if fail { revert(out, size) }
            return(out, size)
        }
    }
}
