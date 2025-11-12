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
