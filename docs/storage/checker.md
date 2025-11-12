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
