pub use rpp_identity_tree::{
    IdentityCommitmentProof, IdentityCommitmentTree, IdentityTreeError, IdentityTreeResult,
    IDENTITY_TREE_DEPTH,
};

use crate::errors::ChainError;

impl From<IdentityTreeError> for ChainError {
    fn from(err: IdentityTreeError) -> Self {
        ChainError::Transaction(err.to_string())
    }
}
