// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// The token an order pays in: ERC-20 with EIP-3009 receive authorizations.
interface IPaymentToken {
    function balanceOf(address owner) external view returns (uint256);
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;
}

/// The proof verifier an order names (RISC Zero's interface). It must revert
/// unless `seal` proves that program `imageId` committed a journal with this
/// SHA-256 digest. Declared `view`, so the call cannot change any state.
interface IProofVerifier {
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/// Thin vault, second form. Model: proofs/commerce/VaultPull.lean. Reference:
/// crates/nucleus-proof-commerce/src/vault.rs (order digest, fee, journal).
///
/// It differs from NucleusVault in one respect: `settle` pays only the seller
/// and books the fee; `sweep`, open to any caller, sends a token's booked fees
/// to the treasury. A treasury the token refuses to pay therefore delays the
/// protocol's own revenue and blocks no order.
///
/// Holds a buyer's payment for one order and obeys three rules. It takes the
/// deposit only under the buyer's own token authorization for exactly this
/// order. It pays the seller, less a fixed protocol fee, only when the verifier
/// the order names accepts a proof for the delivered artifact. After the
/// delivery deadline it returns the whole deposit to the buyer.
///
/// No owner, no upgrade, no pause. Fee rate and treasury are fixed at
/// deployment. Callers carry no authority: anyone may submit any call.
contract NucleusVault2 {
    struct Order {
        address buyer;
        address seller;
        address asset;
        uint256 amount;
        address verifier;
        bytes32 program;
        bytes32 policyHash;
        uint64 fundBy;
        uint64 deliverBy;
        bytes32 salt;
        bytes32 context;
    }

    enum Phase {
        Empty,
        Funded,
        Settled,
        Refunded
    }

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ORDER_TYPEHASH = keccak256(
        "Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)"
    );
    bytes32 private constant ACCEPTANCE_TAG = keccak256("NucleusAcceptanceV1");
    uint256 private constant SCALE = 10000;

    address public immutable treasury;
    uint16 public immutable feeBps;
    uint16 public immutable maximumFeeBps;

    /// Phase of each order, by digest.
    mapping(bytes32 => Phase) public phase;
    /// Keccak-256 of the artifact a settled order was paid for.
    mapping(bytes32 => bytes32) public artifactOf;
    /// Fees booked by settlements and not yet swept, per token.
    mapping(address => uint256) public accrued;

    bool private entered;

    event Funded(bytes32 indexed digest, address indexed buyer, address indexed seller, address asset, uint256 amount);
    event Settled(bytes32 indexed digest, bytes32 artifactHash, uint256 sellerPaid, uint256 feeBooked);
    event Swept(address indexed asset, uint256 amount);
    event Refunded(bytes32 indexed digest, address indexed buyer, uint256 amount);

    error InvalidDeployment();
    error InvalidOrder();
    error FundingExpired();
    error FeeExceedsCap();
    error NotEmpty();
    error NotFunded();
    error BadSignatureLength();
    error InexactDeposit();
    error DeliveryExpired();
    error DeadlineNotReached();
    error InexactPayout();
    error Reentered();
    error NothingAccrued();

    modifier once() {
        if (entered) revert Reentered();
        entered = true;
        _;
        entered = false;
    }

    constructor(address treasury_, uint16 feeBps_, uint16 maximumFeeBps_) {
        if (
            treasury_ == address(0) || treasury_ == address(this) || feeBps_ == 0 || feeBps_ > maximumFeeBps_
                || maximumFeeBps_ > SCALE
        ) revert InvalidDeployment();
        treasury = treasury_;
        feeBps = feeBps_;
        maximumFeeBps = maximumFeeBps_;
    }

    /// EIP-712 digest of an order under this vault on this chain. It is the
    /// nonce of the token authorization that funds the order.
    function digest(Order calldata o) public view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("NucleusVault"), keccak256("1"), block.chainid, address(this))
        );
        bytes32 message = keccak256(
            abi.encode(
                ORDER_TYPEHASH,
                o.buyer,
                o.seller,
                o.asset,
                o.amount,
                o.verifier,
                o.program,
                o.policyHash,
                o.fundBy,
                o.deliverBy,
                o.salt,
                o.context
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, message));
    }

    /// `rate` basis points of `amount`, rounded up when `roundUp`, without
    /// forming the full-width product.
    function scaled(uint256 amount, uint256 rate, bool roundUp) private pure returns (uint256) {
        return (amount / SCALE) * rate + ((amount % SCALE) * rate + (roundUp ? SCALE - 1 : 0)) / SCALE;
    }

    /// Protocol fee on a settled order of this amount: rounded up, so never zero.
    function feeOf(uint256 amount) public view returns (uint256) {
        return scaled(amount, feeBps, true);
    }

    /// Take the buyer's deposit for an order. `authorization` is the buyer's
    /// 65-byte signature (r, s, v) over the EIP-3009 receive authorization this
    /// order fixes: to this vault, for the exact amount, valid through
    /// `fundBy`, with the order digest as nonce. The token checks it.
    function fund(Order calldata o, bytes calldata authorization) external once returns (bytes32 d) {
        if (
            o.buyer == address(0) || o.seller == address(0) || o.asset == address(0) || o.verifier == address(0)
                || o.amount == 0 || o.program == bytes32(0) || o.policyHash == bytes32(0) || o.buyer == address(this)
                || o.seller == address(this) || o.fundBy >= o.deliverBy
        ) revert InvalidOrder();
        if (block.timestamp > o.fundBy) revert FundingExpired();
        if (feeOf(o.amount) > scaled(o.amount, maximumFeeBps, false)) revert FeeExceedsCap();
        d = digest(o);
        if (phase[d] != Phase.Empty) revert NotEmpty();
        if (authorization.length != 65) revert BadSignatureLength();
        phase[d] = Phase.Funded;

        IPaymentToken token = IPaymentToken(o.asset);
        uint256 beforeBalance = token.balanceOf(address(this));
        token.receiveWithAuthorization(
            o.buyer,
            address(this),
            o.amount,
            0,
            uint256(o.fundBy) + 1,
            d,
            uint8(authorization[64]),
            bytes32(authorization[0:32]),
            bytes32(authorization[32:64])
        );
        if (token.balanceOf(address(this)) - beforeBalance != o.amount) revert InexactDeposit();
        emit Funded(d, o.buyer, o.seller, o.asset, o.amount);
    }

    /// Pay the seller for a delivered artifact and book the protocol fee. The artifact travels in
    /// calldata, so the buyer can always read what was paid for.
    function settle(Order calldata o, bytes calldata artifact, bytes calldata seal) external once {
        bytes32 d = digest(o);
        if (phase[d] != Phase.Funded) revert NotFunded();
        if (block.timestamp > o.deliverBy) revert DeliveryExpired();
        bytes32 artifactHash = keccak256(artifact);
        bytes32 journalDigest = sha256(abi.encode(ACCEPTANCE_TAG, block.chainid, address(this), d, artifactHash));
        IProofVerifier(o.verifier).verify(seal, o.program, journalDigest);

        phase[d] = Phase.Settled;
        artifactOf[d] = artifactHash;
        uint256 fee = feeOf(o.amount);
        accrued[o.asset] += fee;
        pay(o.asset, o.seller, o.amount - fee);
        emit Settled(d, artifactHash, o.amount - fee, fee);
    }

    /// Return the whole deposit to the buyer once the delivery deadline has passed.
    function refund(Order calldata o) external once {
        bytes32 d = digest(o);
        if (phase[d] != Phase.Funded) revert NotFunded();
        if (block.timestamp <= o.deliverBy) revert DeadlineNotReached();
        phase[d] = Phase.Refunded;
        pay(o.asset, o.buyer, o.amount);
        emit Refunded(d, o.buyer, o.amount);
    }

    /// Send every fee booked in one token to the treasury. Any caller.
    function sweep(address asset) external once {
        uint256 amount = accrued[asset];
        if (amount == 0) revert NothingAccrued();
        accrued[asset] = 0;
        pay(asset, treasury, amount);
        emit Swept(asset, amount);
    }

    /// Transfer and require that the vault was debited and the recipient
    /// credited by exactly `amount`. Tokens that return nothing are accepted;
    /// a `false` return is not.
    function pay(address asset, address to, uint256 amount) private {
        if (amount == 0) return;
        IPaymentToken token = IPaymentToken(asset);
        uint256 vaultBefore = token.balanceOf(address(this));
        uint256 recipientBefore = token.balanceOf(to);
        (bool ok, bytes memory result) = asset.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!ok || (result.length != 0 && !abi.decode(result, (bool)))) revert InexactPayout();
        if (
            vaultBefore - token.balanceOf(address(this)) != amount || token.balanceOf(to) - recipientBefore != amount
        ) revert InexactPayout();
    }
}
