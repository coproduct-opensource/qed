//! Rust reference for `contracts/board/src/NucleusBoard.sol` (model:
//! proofs/commerce/Board.lean): the task a buyer posts, the ID the contract
//! gives it, the two calls, and the two events.
//!
//! The proof program does not link this crate. The board decides nothing
//! about payment; a wrong answer here misdirects an agent, it cannot move
//! funds.
use alloy_primitives::{Address as A, B256, U256, keccak256};
use alloy_sol_types::{SolCall, SolEvent, SolValue, sol};

pub type Hash = [u8; 32];
pub type Address = [u8; 20];

sol! {
    struct BoardTask {
        bytes32 statementSha256;
        bytes32 statementBlake3;
        bytes32 policyHash;
        address asset;
        uint256 maximumAmount;
        address verifier;
        bytes32 program;
        uint64 fundBy;
        uint64 deliverBy;
        bytes32 buyerNode;
        bytes32 buyerKeyBinding;
        bytes32 salt;
        string buyerAddress;
    }
    function post(BoardTask task) returns (bytes32 id);
    function withdraw(bytes32 id);
    function idOf(address poster, BoardTask task) returns (bytes32);
    function vault() returns (address);
    function posterOf(bytes32 id) returns (address);
    function withdrawn(bytes32 id) returns (bool);
    event Posted(bytes32 indexed id, address indexed poster, address vault, BoardTask task);
    event Withdrawn(bytes32 indexed id);
}

/// Longest `buyer_address` the contract takes.
pub const MAXIMUM_ADDRESS_BYTES: usize = 128;

/// What a buyer posts. Amount is a big-endian uint256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub statement_sha256: Hash,
    pub statement_blake3: Hash,
    pub policy_hash: Hash,
    pub asset: Address,
    pub maximum_amount: Hash,
    pub verifier: Address,
    pub program: Hash,
    pub fund_by: u64,
    pub deliver_by: u64,
    pub buyer_node: Hash,
    pub buyer_key_binding: Hash,
    pub salt: Hash,
    pub buyer_address: String,
}

impl Task {
    pub fn abi(&self) -> BoardTask {
        BoardTask {
            statementSha256: self.statement_sha256.into(),
            statementBlake3: self.statement_blake3.into(),
            policyHash: self.policy_hash.into(),
            asset: A::from(self.asset),
            maximumAmount: U256::from_be_bytes(self.maximum_amount),
            verifier: A::from(self.verifier),
            program: self.program.into(),
            fundBy: self.fund_by,
            deliverBy: self.deliver_by,
            buyerNode: self.buyer_node.into(),
            buyerKeyBinding: self.buyer_key_binding.into(),
            salt: self.salt.into(),
            buyerAddress: self.buyer_address.clone(),
        }
    }
    fn from_abi(task: BoardTask) -> Self {
        Self {
            statement_sha256: task.statementSha256.0,
            statement_blake3: task.statementBlake3.0,
            policy_hash: task.policyHash.0,
            asset: task.asset.into_array(),
            maximum_amount: task.maximumAmount.to_be_bytes(),
            verifier: task.verifier.into_array(),
            program: task.program.0,
            fund_by: task.fundBy,
            deliver_by: task.deliverBy,
            buyer_node: task.buyerNode.0,
            buyer_key_binding: task.buyerKeyBinding.0,
            salt: task.salt.0,
            buyer_address: task.buyerAddress,
        }
    }
    /// Why the contract would refuse this task at time `now`, if it would.
    /// Mirrors `post`'s checks other than "already posted".
    pub fn refusal(&self, now: u64) -> Option<&'static str> {
        let zero = |hash: &Hash| hash.iter().all(|b| *b == 0);
        if zero(&self.statement_sha256)
            || zero(&self.statement_blake3)
            || zero(&self.policy_hash)
            || self.asset == [0; 20]
            || zero(&self.maximum_amount)
            || self.verifier == [0; 20]
            || zero(&self.program)
            || zero(&self.buyer_node)
            || zero(&self.buyer_key_binding)
            || self.fund_by >= self.deliver_by
            || self.buyer_address.len() > MAXIMUM_ADDRESS_BYTES
        {
            return Some("InvalidTask");
        }
        if now > self.fund_by {
            return Some("FundingExpired");
        }
        None
    }
}

/// `keccak256(abi.encode(chainid, board, poster, task))`, as the contract
/// computes it.
pub fn id(chain_id: u64, board: Address, poster: Address, task: &Task) -> Hash {
    keccak256(
        (
            U256::from(chain_id),
            A::from(board),
            A::from(poster),
            task.abi(),
        )
            .abi_encode_params(),
    )
    .0
}

pub fn post_call(task: &Task) -> Vec<u8> {
    postCall { task: task.abi() }.abi_encode()
}
pub fn withdraw_call(id: Hash) -> Vec<u8> {
    withdrawCall { id: id.into() }.abi_encode()
}
pub fn id_of_call(poster: Address, task: &Task) -> Vec<u8> {
    idOfCall {
        poster: A::from(poster),
        task: task.abi(),
    }
    .abi_encode()
}
pub fn vault_call() -> Vec<u8> {
    vaultCall {}.abi_encode()
}
pub fn poster_of_call(id: Hash) -> Vec<u8> {
    posterOfCall { id: id.into() }.abi_encode()
}
pub fn withdrawn_call(id: Hash) -> Vec<u8> {
    withdrawnCall { id: id.into() }.abi_encode()
}

/// First topic of each event.
pub fn posted_topic() -> Hash {
    Posted::SIGNATURE_HASH.0
}
pub fn withdrawn_topic() -> Hash {
    Withdrawn::SIGNATURE_HASH.0
}

/// A `Posted` log, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PostedTask {
    pub id: Hash,
    pub poster: Address,
    pub vault: Address,
    pub task: Task,
}

/// What one of the board's logs says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Posted(Box<PostedTask>),
    Withdrawn(Hash),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogError {
    /// Not one of the board's two events.
    UnknownEvent,
    Malformed,
}

/// Decode a log's topics and data. It does not check which contract emitted
/// the log; the caller asks the chain for one address's logs.
pub fn decode_log(topics: &[Hash], data: &[u8]) -> Result<Notice, LogError> {
    let words: Vec<B256> = topics.iter().map(|t| B256::from(*t)).collect();
    match words.first().map(|t| t.0) {
        Some(t) if t == posted_topic() => {
            let event = Posted::decode_raw_log(words.iter().copied(), data)
                .map_err(|_| LogError::Malformed)?;
            Ok(Notice::Posted(Box::new(PostedTask {
                id: event.id.0,
                poster: event.poster.into_array(),
                vault: event.vault.into_array(),
                task: Task::from_abi(event.task),
            })))
        }
        Some(t) if t == withdrawn_topic() => {
            let event = Withdrawn::decode_raw_log(words.iter().copied(), data)
                .map_err(|_| LogError::Malformed)?;
            Ok(Notice::Withdrawn(event.id.0))
        }
        _ => Err(LogError::UnknownEvent),
    }
}
