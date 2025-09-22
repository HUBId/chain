/// Abstraction over the sparse Merkle tree maintained for every committed state.
pub trait SparseMerkleTree {
    /// Error type for tree operations.
    type Error;
    /// Hash output representing the tree root.
    type Root: Clone + Eq;
    /// Leaf key type (typically a hash of the logical key).
    type Key: Clone + Eq;
    /// Value stored at a leaf position.
    type Value: Clone;
    /// Proof object generated for inclusion/exclusion checks.
    type Proof;

    /// Fetch the current root hash for the tree.
    fn root(&self) -> Self::Root;

    /// Apply a single leaf update.
    fn update(&mut self, key: &Self::Key, value: Self::Value) -> Result<Self::Root, Self::Error>;

    /// Apply a batch of leaf updates atomically, returning the resulting root.
    fn batch_update(
        &mut self,
        entries: &[(Self::Key, Self::Value)],
    ) -> Result<Self::Root, Self::Error>;

    /// Generate a Merkle proof for the supplied key.
    fn prove(&self, key: &Self::Key) -> Result<Self::Proof, Self::Error>;

    /// Verify a Merkle proof against an expected root.
    fn verify(
        root: &Self::Root,
        key: &Self::Key,
        value: &Self::Value,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error>;
}
