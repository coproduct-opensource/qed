// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// Task board for one vault. Model: proofs/commerce/Board.lean.
///
/// A notice board and nothing else. A buyer posts what it wants proved and on
/// what terms; sellers read the posts from the chain and answer the buyer
/// directly. Orders are funded and settled by the vault this board names.
///
/// No owner, no upgrade, no funds: nothing here is payable and nothing here
/// calls a token. A post costs gas only, so a post is a notice, not a
/// commitment: the poster may hold no funds, the statement may be
/// unfetchable or unprovable, and the node may be unreachable.
contract NucleusBoard {
    struct Task {
        /// SHA-256 of the statement, as the policy pins it.
        bytes32 statementSha256;
        /// BLAKE3 of the same bytes: the hash they are fetched by.
        bytes32 statementBlake3;
        bytes32 policyHash;
        address asset;
        /// The most the buyer will pay, in the asset's smallest unit.
        uint256 maximumAmount;
        address verifier;
        bytes32 program;
        /// Latest funding deadline the buyer will sign for.
        uint64 fundBy;
        /// Latest delivery deadline the buyer will sign for.
        uint64 deliverBy;
        /// The buyer's iroh node ID.
        bytes32 buyerNode;
        /// Thumbprint of the buyer's proof-of-possession key.
        bytes32 buyerKeyBinding;
        bytes32 salt;
        /// A hint for reaching the node, such as "203.0.113.7:4460". Not
        /// authenticated: the node ID is what a seller checks.
        string buyerAddress;
    }

    /// The one vault this board's tasks settle through.
    address public immutable vault;

    /// Who posted each task; zero if it was never posted.
    mapping(bytes32 => address) public posterOf;
    mapping(bytes32 => bool) public withdrawn;

    event Posted(bytes32 indexed id, address indexed poster, address vault, Task task);
    event Withdrawn(bytes32 indexed id);

    error InvalidDeployment();
    error InvalidTask();
    error FundingExpired();
    error AlreadyPosted();
    error NotPoster();
    error AlreadyWithdrawn();

    constructor(address vault_) {
        if (vault_ == address(0)) revert InvalidDeployment();
        vault = vault_;
    }

    /// The ID a task would have if `poster` posted it here.
    function idOf(address poster, Task calldata task) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), poster, task));
    }

    function post(Task calldata task) external returns (bytes32 id) {
        if (
            task.statementSha256 == bytes32(0) || task.statementBlake3 == bytes32(0) || task.policyHash == bytes32(0)
                || task.asset == address(0) || task.maximumAmount == 0 || task.verifier == address(0)
                || task.program == bytes32(0) || task.buyerNode == bytes32(0) || task.buyerKeyBinding == bytes32(0)
                || task.fundBy >= task.deliverBy || bytes(task.buyerAddress).length > 128
        ) revert InvalidTask();
        if (block.timestamp > task.fundBy) revert FundingExpired();
        id = idOf(msg.sender, task);
        if (posterOf[id] != address(0)) revert AlreadyPosted();
        posterOf[id] = msg.sender;
        emit Posted(id, msg.sender, vault, task);
    }

    /// The poster says the task is no longer wanted. Orders already signed
    /// are unaffected: they live in the vault.
    function withdraw(bytes32 id) external {
        if (posterOf[id] != msg.sender) revert NotPoster();
        if (withdrawn[id]) revert AlreadyWithdrawn();
        withdrawn[id] = true;
        emit Withdrawn(id);
    }
}
