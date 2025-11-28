# Pruning integrity checks

Firewood pruning reclaims storage by returning deleted areas to the allocator's free lists.
Once historical revisions are pruned, the node now runs a post-pruning integrity pass that
verifies two conditions:

1. **Free-list consistency.** All free areas must reside on the free list that matches their
   encoded area size and form well-formed chains.
2. **No leaked areas.** Every on-disk range must either belong to a trie node or appear on an
   appropriate free list; stray ranges are treated as leaks.

If the checker reports errors, the commit is rejected and the node logs the offending errors so
operators can inspect the corrupted database. Typical remediations include:

- Running the storage checker (`fwdctl check <db path>`) to confirm and attempt to repair
  the free lists.
- Restoring the nodestore from the most recent healthy snapshot if corruption persists.
- Filing a support ticket with the logged error output if manual repair is unsuccessful.
