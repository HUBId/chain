# Firewood storage checker CLI

The `fwdctl check` subcommand validates on-disk Firewood databases and prints a
summary of detected issues alongside aggregate statistics about the image. By
default the checker runs in a dry mode that reports inconsistencies without
modifying the database:

```shell
fwdctl check --db /var/lib/firewood.db
```

Successful runs emit `Checker finished with 0 error(s).` before the statistics
report. Any non-zero error count is returned as a non-zero exit status, allowing
operators to wire the command into CI pipelines or monitoring probes.

## Repairing issues in place

Invoke the command with `--fix` to repair recoverable issues and write the
updated header and free list metadata back to disk:

```shell
fwdctl check --db /var/lib/firewood.db --fix
```

The repair pass prints a concise summary similar to `Repair summary: applied 3
fix(es), 0 issue(s) remain.`. When unrecoverable errors remain—or if a follow-up
verification still reports issues—the command exits with a non-zero status so it
can be chained with orchestration tooling. Use `--hash-check` alongside `--fix`
to rehash all nodes before persisting the repaired state when deeper validation
is required.

### IO failures during leak repair

When `--fix` is set the checker re-queues leaked ranges into the free list. If an
IO error occurs while writing a recovered block, the checker keeps enqueuing the
remaining blocks and records the partial progress in Prometheus metrics:

* `firewood_checker_leaked_areas_detected` reports the number of individual
  areas discovered inside leaked ranges.
* `firewood_checker_leaked_areas_fixed` increments for each block successfully
  re-enqueued, even if later writes fail.
* `firewood_checker_leaked_areas_failed_to_fix` counts the blocks that could not
  be written back.

Operators should re-run the checker after addressing the underlying storage
issue and confirm that the `*_failed_to_fix` counter remains flat while the
detected and fixed counts converge. Persistent failures indicate that a manual
free-list rebuild or node replacement is required before returning the database
to service.
