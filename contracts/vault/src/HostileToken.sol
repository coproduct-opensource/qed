// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// TEST ONLY. A payment token that misbehaves on request, to drive the
/// vault's own defences red. It checks no signature: whoever names it in an
/// order has no protection from it, which is the point of the tests.
contract HostileToken {
    enum Mode {
        Honest,
        SkimDeposit, // credits one unit less than it was asked to move in
        ReenterOnDeposit, // calls back into the vault while a deposit is in flight
        FalseOnTransfer, // transfer returns false and moves nothing
        SilentOnTransfer, // transfer returns true and moves nothing
        ReenterOnTransfer, // calls back into the vault while a payout is in flight
        FalseAfterMoving // transfer moves the tokens and then returns false
    }

    Mode public mode;
    bytes public reentry;
    mapping(address => uint256) public balanceOf;

    function set(Mode m, bytes calldata callback) external {
        mode = m;
        reentry = callback;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function reenter() private {
        (bool ok, bytes memory result) = msg.sender.call(reentry);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256,
        uint256,
        bytes32,
        uint8,
        bytes32,
        bytes32
    ) external {
        if (mode == Mode.ReenterOnDeposit) reenter();
        balanceOf[from] -= value;
        balanceOf[to] += mode == Mode.SkimDeposit ? value - 1 : value;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        if (mode == Mode.ReenterOnTransfer) reenter();
        if (mode == Mode.FalseOnTransfer) return false;
        if (mode == Mode.SilentOnTransfer) return true;
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return mode != Mode.FalseAfterMoving;
    }
}
