// SPDX-License-Identifier: MIT
pragma solidity 0.8.38;

/// The token an order pays in: ERC-20 with EIP-3009 receive authorizations.
/// The second overload takes the signature as bytes, which FiatToken v2.2
/// checks with EIP-1271 when the payer is a contract.
interface IPaymentToken3 {
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
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes calldata signature
    ) external;
}

/// The proof verifier an order names (RISC Zero's interface). It must revert
/// unless `seal` proves that program `imageId` committed a journal with this
/// SHA-256 digest. Declared `view`, so the call cannot change any state.
interface IProofVerifier3 {
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external view;
}

/// Who is paid for the use of a checked base library, and at what rate.
/// An unknown base answers (address(0), 0).
interface IBaseRegistry {
    function entryOf(bytes32 base) external view returns (address payee, uint16 bps);
    /// The largest rate any entry may carry. Read once, at construction.
    function maximumBps() external view returns (uint16);
}

/// Thin vault, third form. Model: proofs/commerce/Vault3.lean. Reference:
/// crates/nucleus-proof-commerce/src/vault.rs (`Rules::Third`).
///
/// It takes a buyer's deposit only under the buyer's own token authorization
/// for exactly this order, by an ordinary or a contract-wallet signature. It
/// books what the seller, the treasury and a base library's payee are owed
/// only when the verifier the order names accepts a proof for the delivered
/// artifact. After the delivery deadline it books the whole deposit back to
/// the buyer.
///
/// Nothing is paid inside `fund`, `settle` or `refund`. `claim`, open to any
/// caller, pays one payee everything it is owed in one token. A payee the
/// token refuses to pay therefore blocks its own claim and nothing else.
///
/// No owner, no upgrade, no pause. Fee rate, fee cap, treasury, registry and
/// the longest term are fixed at deployment. Callers carry no authority.
contract NucleusVault3 {
    struct Order {
        address buyer;
        address seller;
        address asset;
        uint256 amount;
        address verifier;
        bytes32 program;
        bytes32 policyHash;
        bytes32 base;
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

    /// The royalty an order will pay if it settles, fixed when it was funded.
    struct Royalty {
        address payee;
        uint256 amount;
    }

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant ORDER_TYPEHASH = keccak256(
        "Order(address buyer,address seller,address asset,uint256 amount,address verifier,bytes32 program,bytes32 policyHash,bytes32 base,uint64 fundBy,uint64 deliverBy,bytes32 salt,bytes32 context)"
    );
    bytes32 private constant ACCEPTANCE_TAG = keccak256("NucleusAcceptanceV1");
    uint256 private constant SCALE = 10000;
    /// Gas the registry is given to answer. A registry that needs more, or
    /// that reverts, makes `fund` revert; it is never called after funding.
    uint256 private constant REGISTRY_GAS = 100000;

    address public immutable treasury;
    uint16 public immutable feeBps;
    uint16 public immutable maximumFeeBps;
    /// Longest time, in seconds, from funding to an order's delivery deadline.
    uint64 public immutable maximumTerm;
    address public immutable registry;

    /// Phase of each order, by digest.
    mapping(bytes32 => Phase) public phase;
    /// Keccak-256 of the artifact a settled order was paid for.
    mapping(bytes32 => bytes32) public artifactOf;
    /// The royalty fixed for each funded order.
    mapping(bytes32 => Royalty) public royaltyOf;
    /// Booked and not yet claimed, per payee and token.
    mapping(address => mapping(address => uint256)) public owed;

    bool private entered;

    event Funded(bytes32 indexed digest, address indexed buyer, address indexed seller, address asset, uint256 amount);
    event Settled(
        bytes32 indexed digest, bytes32 artifactHash, uint256 sellerOwed, uint256 feeOwed, address basePayee, uint256 royaltyOwed
    );
    event Refunded(bytes32 indexed digest, address indexed buyer, uint256 amount);
    event Claimed(address indexed payee, address indexed asset, uint256 amount);

    error InvalidDeployment();
    error CeilingExceedsRoom();
    error InvalidOrder();
    error FundingExpired();
    error TermTooLong();
    error RegistryFailed();
    error FeeExceedsCap();
    error NotEmpty();
    error NotFunded();
    error InexactDeposit();
    error DeliveryExpired();
    error DeadlineNotReached();
    error InexactPayout();
    error Reentered();
    error NothingOwed();

    modifier once() {
        if (entered) revert Reentered();
        entered = true;
        _;
        entered = false;
    }

    constructor(address treasury_, uint16 feeBps_, uint16 maximumFeeBps_, uint64 maximumTerm_, address registry_) {
        if (
            treasury_ == address(0) || treasury_ == address(this) || feeBps_ == 0 || feeBps_ > maximumFeeBps_
                || maximumFeeBps_ > SCALE || maximumTerm_ == 0 || registry_ == address(0) || registry_ == address(this)
        ) revert InvalidDeployment();
        // Decision 22 (model: `ceilingWithinRoom` in Vault3.lean): every rate the
        // registry can ever admit fits in the room the fee leaves under the cap,
        // so no registration can strand a base here. A registry that cannot
        // answer reverts the deployment.
        if (uint256(feeBps_) + IBaseRegistry(registry_).maximumBps() > maximumFeeBps_) revert CeilingExceedsRoom();
        treasury = treasury_;
        feeBps = feeBps_;
        maximumFeeBps = maximumFeeBps_;
        maximumTerm = maximumTerm_;
        registry = registry_;
    }

    /// EIP-712 digest of an order under this vault on this chain. It is the
    /// nonce of the token authorization that funds the order.
    function digest(Order calldata o) public view returns (bytes32) {
        bytes32 domain = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("NucleusVault"), keccak256("3"), block.chainid, address(this))
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
                o.base,
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

    /// What the registry says about a base, read with bounded gas. Anything
    /// but a clean two-word answer in range is a failure. A zero payee, or
    /// this vault as payee, means no entry.
    function entry(bytes32 base) private view returns (address payee, uint256 bps) {
        if (base == bytes32(0)) return (address(0), 0);
        bytes memory request = abi.encodeWithSelector(IBaseRegistry.entryOf.selector, base);
        address target = registry;
        uint256 gasLimit = REGISTRY_GAS;
        bool ok;
        uint256 size;
        uint256 first;
        uint256 second;
        assembly {
            let out := mload(0x40)
            ok := staticcall(gasLimit, target, add(request, 32), mload(request), out, 64)
            size := returndatasize()
            first := mload(out)
            second := mload(add(out, 32))
        }
        if (!ok || size != 64 || first > type(uint160).max || second > SCALE) revert RegistryFailed();
        payee = address(uint160(first));
        if (payee == address(0) || payee == address(this)) return (address(0), 0);
        bps = second;
    }

    /// Take the buyer's deposit for an order. `authorization` is the buyer's
    /// signature over the EIP-3009 receive authorization this order fixes: to
    /// this vault, for the exact amount, valid through `fundBy`, with the
    /// order digest as nonce. A 65-byte value is passed to the token as
    /// (r, s, v); any other length is passed as bytes, which a token that
    /// supports contract wallets checks with the buyer's wallet. The token
    /// decides in both cases; the vault judges no signature.
    function fund(Order calldata o, bytes calldata authorization) external once returns (bytes32 d) {
        if (
            o.buyer == address(0) || o.seller == address(0) || o.asset == address(0) || o.verifier == address(0)
                || o.amount == 0 || o.program == bytes32(0) || o.policyHash == bytes32(0) || o.buyer == address(this)
                || o.seller == address(this) || o.fundBy >= o.deliverBy
        ) revert InvalidOrder();
        if (block.timestamp > o.fundBy) revert FundingExpired();
        if (o.deliverBy > block.timestamp + maximumTerm) revert TermTooLong();

        Royalty memory r = charges(o.amount, o.base);

        d = digest(o);
        if (phase[d] != Phase.Empty) revert NotEmpty();
        phase[d] = Phase.Funded;
        if (r.amount != 0) royaltyOf[d] = r;

        pull(o, d, authorization);
        emit Funded(d, o.buyer, o.seller, o.asset, o.amount);
    }

    /// The royalty an order of this amount on this base would pay, or a
    /// revert if fee and royalty together exceed the fee cap.
    function charges(uint256 amount, bytes32 base) private view returns (Royalty memory r) {
        (address payee, uint256 bps) = entry(base);
        uint256 royalty = scaled(amount, bps, false);
        uint256 cap = scaled(amount, maximumFeeBps, false);
        if (royalty > cap || feeOf(amount) > cap - royalty) revert FeeExceedsCap();
        if (royalty != 0) r = Royalty(payee, royalty);
    }

    /// Redeem the buyer's authorization and require the exact deposit.
    function pull(Order calldata o, bytes32 d, bytes calldata authorization) private {
        IPaymentToken3 token = IPaymentToken3(o.asset);
        uint256 beforeBalance = token.balanceOf(address(this));
        if (authorization.length == 65) {
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
        } else {
            token.receiveWithAuthorization(
                o.buyer, address(this), o.amount, 0, uint256(o.fundBy) + 1, d, authorization
            );
        }
        if (token.balanceOf(address(this)) - beforeBalance != o.amount) revert InexactDeposit();
    }

    /// Book what a delivered artifact earns. The artifact travels in calldata,
    /// so the buyer can always read what was paid for. Nothing is transferred.
    function settle(Order calldata o, bytes calldata artifact, bytes calldata seal) external once {
        bytes32 d = digest(o);
        if (phase[d] != Phase.Funded) revert NotFunded();
        if (block.timestamp > o.deliverBy) revert DeliveryExpired();
        bytes32 artifactHash = keccak256(artifact);
        bytes32 journalDigest = sha256(abi.encode(ACCEPTANCE_TAG, block.chainid, address(this), d, artifactHash));
        IProofVerifier3(o.verifier).verify(seal, o.program, journalDigest);

        phase[d] = Phase.Settled;
        artifactOf[d] = artifactHash;
        uint256 fee = feeOf(o.amount);
        Royalty memory r = royaltyOf[d];
        // fee + r.amount <= o.amount: checked against the cap at funding.
        uint256 sellerShare = o.amount - fee - r.amount;
        owed[o.seller][o.asset] += sellerShare;
        owed[treasury][o.asset] += fee;
        if (r.amount != 0) owed[r.payee][o.asset] += r.amount;
        emit Settled(d, artifactHash, sellerShare, fee, r.payee, r.amount);
    }

    /// Book the whole deposit back to the buyer once the delivery deadline has
    /// passed. Nothing is transferred.
    function refund(Order calldata o) external once {
        bytes32 d = digest(o);
        if (phase[d] != Phase.Funded) revert NotFunded();
        if (block.timestamp <= o.deliverBy) revert DeadlineNotReached();
        phase[d] = Phase.Refunded;
        owed[o.buyer][o.asset] += o.amount;
        emit Refunded(d, o.buyer, o.amount);
    }

    /// Pay `payee` everything it is owed in one token. Any caller.
    function claim(address payee, address asset) external once {
        uint256 amount = owed[payee][asset];
        if (amount == 0) revert NothingOwed();
        owed[payee][asset] = 0;
        pay(asset, payee, amount);
        emit Claimed(payee, asset, amount);
    }

    /// Transfer and require that the vault was debited and the recipient
    /// credited by exactly `amount`. Tokens that return nothing are accepted;
    /// a `false` return is not.
    function pay(address asset, address to, uint256 amount) private {
        IPaymentToken3 token = IPaymentToken3(asset);
        uint256 vaultBefore = token.balanceOf(address(this));
        uint256 recipientBefore = token.balanceOf(to);
        (bool ok, bytes memory result) = asset.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!ok || (result.length != 0 && !abi.decode(result, (bool)))) revert InexactPayout();
        if (
            vaultBefore - token.balanceOf(address(this)) != amount || token.balanceOf(to) - recipientBefore != amount
        ) revert InexactPayout();
    }
}
