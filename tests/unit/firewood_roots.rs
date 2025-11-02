use storage_firewood::tree::FirewoodTree;

#[test]
fn firewood_tree_updates_and_proofs_roundtrip() {
    let mut tree = FirewoodTree::new();
    let empty_root = tree.root();

    let update_root = tree.update(b"account-1", b"balance:10".to_vec());
    assert_ne!(update_root, empty_root);

    let proof = tree.get_proof(b"account-1");
    assert_eq!(proof.value.as_deref(), Some(b"balance:10".as_ref()));
    assert!(FirewoodTree::verify_proof(&update_root, &proof));

    let delete_root = tree.delete(b"account-1");
    assert_eq!(delete_root, tree.root());
    assert!(FirewoodTree::verify_proof(
        &delete_root,
        &tree.get_proof(b"account-1")
    ));
    assert_eq!(delete_root, empty_root);
}

#[test]
fn firewood_tree_preserves_second_insert() {
    let mut tree = FirewoodTree::new();
    tree.update(b"alpha", vec![1, 2, 3]);
    let after_alpha = tree.root();

    tree.update(b"beta", vec![4, 5, 6]);
    let after_beta = tree.root();
    assert_ne!(after_alpha, after_beta);

    let proof_alpha = tree.get_proof(b"alpha");
    assert!(FirewoodTree::verify_proof(&after_beta, &proof_alpha));
    assert_eq!(proof_alpha.value.as_deref(), Some(&[1, 2, 3][..]));
}
