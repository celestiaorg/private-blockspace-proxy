use super::tx_config::TxConfig;
use jsonrpsee::core::{StringError, async_trait};
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use celestia_client::types::nmt::{Namespace, NamespaceProof};
use celestia_client::types::{Blob, Commitment};
use jsonrpsee::PendingSubscriptionSink;
use serde::{Deserialize, Serialize};

/// Response type for [`BlobClient::blob_subscribe`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlobsAtHeight {
    /// Blobs submitted at given height.
    pub blobs: Option<Vec<Blob>>,
    /// A height for which the blobs were returned.
    pub height: u64,
}

/// Result type for [`BlobClient::blob_subscribe`].
pub type SubcriptionResult = Result<(), StringError>;

#[rpc(server, client)]
pub trait Blob {
    /// Get retrieves the blob by commitment under the given namespace and height.
    #[method(name = "blob.Get")]
    async fn blob_get(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: Commitment,
    ) -> Result<Blob, ErrorObjectOwned>;

    /// GetAll returns all blobs under the given namespaces and height.
    #[method(name = "blob.GetAll")]
    async fn blob_get_all(
        &self,
        height: u64,
        namespaces: Vec<Namespace>,
    ) -> Result<Option<Vec<Blob>>, ErrorObjectOwned>;

    /// GetProof retrieves proofs in the given namespaces at the given height by commitment.
    #[method(name = "blob.GetProof")]
    async fn blob_get_proof(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: Commitment,
    ) -> Result<Vec<NamespaceProof>, ErrorObjectOwned>;

    /// Included checks whether a blob's given commitment(Merkle subtree root) is included at given height and under the namespace.
    #[method(name = "blob.Included")]
    async fn blob_included(
        &self,
        height: u64,
        namespace: Namespace,
        proof: NamespaceProof,
        commitment: Commitment,
    ) -> Result<bool, ErrorObjectOwned>;

    /// Submit sends Blobs and reports the height in which they were included. Allows sending multiple Blobs atomically synchronously. Uses default wallet registered on the Node.
    #[method(name = "blob.Submit")]
    async fn blob_submit(&self, blobs: Vec<Blob>, opts: TxConfig) -> Result<u64, ErrorObjectOwned>;

    /// Subscribe to published blobs from the given namespace as they are included.
    ///
    /// # Notes
    ///
    /// Unsubscribe is not implemented by Celestia nodes.
    #[subscription(name = "blob.Subscribe", unsubscribe = "blob.Unsubscribe", item = BlobsAtHeight)]
    async fn blob_subscribe(&self, namespace: Namespace) -> SubcriptionResult;
}

pub struct BlobServerImpl;

#[async_trait]
impl BlobServer for BlobServerImpl {
    async fn blob_submit(&self, blobs: Vec<Blob>, opts: TxConfig) -> Result<u64, ErrorObjectOwned> {
        todo!()
    }

    async fn blob_get(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: Commitment,
    ) -> Result<Blob, ErrorObjectOwned> {
        todo!()
    }

    #[allow(unused_variables)]
    async fn blob_get_all(
        &self,
        height: u64,
        namespaces: Vec<Namespace>,
    ) -> Result<Option<Vec<Blob>>, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn blob_get_proof(
        &self,
        height: u64,
        namespace: Namespace,
        commitment: Commitment,
    ) -> Result<Vec<NamespaceProof>, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn blob_included(
        &self,
        height: u64,
        namespace: Namespace,
        proof: NamespaceProof,
        commitment: Commitment,
    ) -> Result<bool, ErrorObjectOwned> {
        unimplemented!()
    }

    #[allow(unused_variables)]
    async fn blob_subscribe(
        &self,
        pending: PendingSubscriptionSink,
        namespace: Namespace,
    ) -> SubcriptionResult {
        unimplemented!()
    }
}
