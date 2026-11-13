// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// The proof verifier (RISC Zero's interface). It must revert unless `seal`
/// proves that program `imageId` committed a journal with this SHA-256 digest.
interface IBaseProofVerifier {
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/// Registry of checked base libraries. Model: proofs/commerce/Registry.lean.
///
/// A base is a complete Lean export, named by the SHA-256 of its bytes. An
/// entry says who is paid when an order builds on that base, and at what
/// rate. An entry is made only on a proof by the base program that those
/// bytes type-checked, and that proof commits the payee and the rate, so
/// whoever submits it can register nobody but the payee the prover named.
///
/// No owner, no upgrade. An entry never changes and is never removed: the
/// first valid proof for a base decides it. Anyone may call `register`.
contract BaseRegistry {
    bytes32 private constant BASE_TAG = keccak256("NucleusBaseV1");
    uint16 private constant SCALE = 10000;

    address public immutable verifier;
    /// Image ID of the base program whose proofs are accepted.
    bytes32 public immutable baseProgram;
    /// Largest rate an entry may carry, in basis points of an order.
    uint16 public immutable maximumBps;

    struct Entry {
        address payee;
        uint16 bps;
    }

    mapping(bytes32 => Entry) private entries;
    /// Hash of the permitted-axioms list the registered proof checked the
    /// base under. For readers only: an order's proof program itself requires
    /// a base commitment under the order's own axioms.
    mapping(bytes32 => bytes32) public axiomsOf;

    event Registered(bytes32 indexed base, bytes32 axiomsHash, address indexed payee, uint16 bps);

    error InvalidDeployment();
    error InvalidEntry();
    error AlreadyRegistered();

    constructor(address verifier_, bytes32 baseProgram_, uint16 maximumBps_) {
        if (verifier_ == address(0) || baseProgram_ == bytes32(0) || maximumBps_ > SCALE) revert InvalidDeployment();
        verifier = verifier_;
        baseProgram = baseProgram_;
        maximumBps = maximumBps_;
    }

    /// Register a base on the base program's proof for exactly this base,
    /// axioms hash, payee and rate.
    function register(bytes32 base, bytes32 axiomsHash, address payee, uint16 bps, bytes calldata seal) external {
        if (base == bytes32(0) || payee == address(0) || bps > maximumBps) revert InvalidEntry();
        if (entries[base].payee != address(0)) revert AlreadyRegistered();
        bytes32 journalDigest = sha256(abi.encode(BASE_TAG, base, axiomsHash, payee, bps));
        IBaseProofVerifier(verifier).verify(seal, baseProgram, journalDigest);
        entries[base] = Entry(payee, bps);
        axiomsOf[base] = axiomsHash;
        emit Registered(base, axiomsHash, payee, bps);
    }

    /// The payee and rate for a base; zero for a base nobody registered.
    function entryOf(bytes32 base) external view returns (address payee, uint16 bps) {
        Entry storage e = entries[base];
        return (e.payee, e.bps);
    }
}
