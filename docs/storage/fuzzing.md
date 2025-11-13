# Firewood storage fuzzing

The `FuzzTree` harness in `ffi/tests/firewood/merkle_compatibility_test.go` compares
Firewood and MerkleDB behaviour by executing a sequence of high level operations
chosen by Go's fuzzing engine. Historically, the harness used a PRNG to synthesize
value payloads, which meant that re-running the same byte sequence could produce
slightly different database states. The harness now derives every value payload
from the raw fuzzer input bytes via a deterministic `byteStepper`. Identical
`randSource`/`byteSteps` pairs therefore always produce identical key/value
material and, consequently, the same database roots.

## Reproducing a fuzz failure

1. Run the fuzz target: `go test ./ffi/tests/firewood -run FuzzTree -fuzz=FuzzTree`.
2. When the fuzzer finds an issue it prints the failing `randSource` and stores the
   input under `ffi/tests/firewood/testdata/fuzz/FuzzTree/`.
3. Re-run the failure deterministically with
   `go test ./ffi/tests/firewood -run=FuzzTree/<filename> -fuzz=FuzzTree -fuzztime=0`.
   The deterministic payload generator ensures this reproducer exercises the exact
   same sequence of Firewood and MerkleDB updates as the original failure.
4. If you need to write a regression test, call
   `executeTreeSteps(t, <randSource>, []byte{...})` with the values emitted by the
   fuzzer. The helper returns the final root hashes, making it easy to compare the
   database states produced by different inputs.

Because the payloads now come exclusively from the `byteSteps` slice, any future
failure can be deterministically investigated and added to the regression test
suite by pasting the recorded bytes into a unit test.

## Debugging iteration-106 regressions

The deterministic RNG used by the `firewood_merkle` fuzz target surfaced a
historical regression around iteration 106. To recreate the fixture without
running the ignored unit tests:

1. Dump the dataset with `cargo xtask fuzz-debug dump`. The command prints a
   replayable `ITER 106` header followed by colon-delimited index/key/value
   tuples.
2. Inspect the trie shape and root preimages with `cargo xtask fuzz-debug
   inspect`. The helper computes both the raw and deduplicated tries, prints the
   root preimage for each, and walks the branch/leaf structure so you can spot
   mismatched children quickly.

Both subcommands accept `--iteration`, `--items`, and `--seed` overrides if the
fuzzer uncovers a new problematic iteration in the future. The seed defaults to
`42`, matching the dataset baked into the regression test.
