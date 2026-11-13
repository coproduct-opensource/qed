//! Statements as content-addressed blobs over iroh (iroh-blobs, in-memory
//! store), as crates/nucleus-bundle-cas does it.
//!
//! A blob is fetched by its BLAKE3 hash over a verified stream: a peer cannot
//! substitute other bytes for the hash asked for. That is byte integrity for
//! that hash only. The policy pins the statement by SHA-256, which the
//! fetcher checks separately once it has the bytes.
//!
//! Not bounded here: the size of a blob being fetched is not known before it
//! arrives, and this module does not cap it. The seller checks the size
//! afterwards (`job::Received::new`).
use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::{BlobsProtocol, Hash, store::mem::MemStore};

pub use iroh_blobs::ALPN;
pub type Store = MemStore;

pub fn store() -> Store {
    MemStore::new()
}
/// The protocol handler that serves `store`'s blobs.
pub fn protocol(store: &Store) -> BlobsProtocol {
    BlobsProtocol::new(store, None)
}
/// Put bytes in the store; returns their BLAKE3 hash.
pub async fn add(store: &Store, bytes: Vec<u8>) -> Result<[u8; 32], String> {
    let tag = store.add_bytes(bytes).await.map_err(|e| e.to_string())?;
    Ok(*tag.hash.as_bytes())
}
/// Fetch the blob with this BLAKE3 hash from one node.
pub async fn fetch(
    endpoint: &Endpoint,
    store: &Store,
    from: EndpointAddr,
    blake3: [u8; 32],
) -> Result<Vec<u8>, String> {
    let hash = Hash::from_bytes(blake3);
    let connection = endpoint
        .connect(from, ALPN)
        .await
        .map_err(|e| format!("blob connection: {e}"))?;
    store
        .remote()
        .fetch(connection, hash)
        .await
        .map_err(|e| format!("blob fetch: {e}"))?;
    let bytes = store
        .get_bytes(hash)
        .await
        .map_err(|e| format!("blob read: {e}"))?;
    Ok(bytes.to_vec())
}
