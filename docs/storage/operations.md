# Firewood storage operations

## io-uring ring sizing

Firewood allocates an [`io_uring`](https://docs.kernel.org/io_uring.html) ring when
`storage.ring_size` is configured in `config/node.toml` (or
`config/storage.toml`). The default ring contains 32 entries, which balances
moderate concurrency with kernel resource usage. Operators can tune the ring to
any value between 2 and 4096:

```toml
[storage]
ring_size = 32
```

The chosen size is emitted during bootstrap logs as the structured field
`storage_io_uring_ring_entries` and exported as the metric
`firewood.storage.io_uring_ring_entries`. The ring size can also be overridden at
startup with either the `--storage-ring-size <entries>` CLI flag or the
`RPP_NODE_STORAGE_RING_SIZE=<entries>` environment variable. Values outside the
supported range are rejected before the node initialises.

## WAL crash-recovery chaos drill

Nightly CI exercises abrupt termination of the Firewood write-ahead log to
validate crash recovery. The harness spawns a helper process that issues a
transaction containing 128 mutations of 64 kB each, pauses just before the
commit record is flushed, and is then terminated. The primary test process
reopens the database to confirm the partially written transaction is rolled
back and that the baseline state remains intact.

### Running the drill locally

```shell
cargo test --test storage -- --ignored wal_crash_recovery_handles_abrupt_termination
```

The test creates a temporary Firewood data directory, populates a committed
`baseline` key, and then kills the helper process while it is blocked on the
`FIREWOOD_KV_COMMIT_PAUSE_PATH` sentinel. Artifacts are written under
`target/compliance/chaos/firewood-wal` unless `FIREWOOD_WAL_CHAOS_ARTIFACT_DIR`
points elsewhere.

### Expected signals

* The recovered `FirewoodKv` instance still returns `baseline = "committed"`
  and its root hash matches the pre-crash baseline.
* Keys prefixed with `chaos-00000000-` do **not** exist after the restart; they
  were staged by the helper but never committed.
* Metrics exported through the Prometheus recorder contain
  `firewood_wal_transactions_total{result="rolled_back"} 1`, confirming the
  replay logic detected and discarded the incomplete transaction.【F:tests/storage/chaos.rs†L68-L116】【F:storage-firewood/src/kv.rs†L120-L165】
* Artifact bundle contents:
  * `firewood.wal.after_crash` and `firewood.wal.after_recovery` capture the WAL
    state before and after replay.
  * `metrics.prom` stores the rendered Prometheus metrics snapshot.
  * `helper.stdout.log` / `helper.stderr.log` preserve the helper process logs.
  * `recovery.summary` summarises the baseline root and artifact locations.

### Remediation guidance

If the drill fails to detect the rolled-back transaction or the baseline root
changes:

1. Inspect the preserved WAL artifacts to confirm whether the commit record was
   written. The absence of a `Commit` entry coupled with missing
   `rolled_back` metrics indicates replay instrumentation regressed.
2. Run `cargo run -p firewood --bin firewood_recovery -- --data <dir>` against
   the offending WAL to rebuild durable state and capture a detailed recovery
   report.
3. File an incident if the metrics counter does not increment; production alert
   thresholds rely on `firewood_wal_transactions_total{result="rolled_back"}`
   to surface crash recovery events.
4. Once recovery behaviour is validated, prune the damaged WAL segment and
   rerun the nightly chaos test before re-enabling affected nodes.

## Storage checker repairs

`firewood_storage::NodeStore::check_and_fix` returns a new committed view of the
database after applying repairs, allowing operators to run follow-up checks or
flush metadata without reopening the file. The CLI uses the returned handle to
re-run the checker when `--fix` is specified so the printed statistics reflect
the repaired state, surfacing any lingering issues immediately.【F:storage/src/checker/mod.rs†L604-L622】【F:fwdctl/src/check.rs†L67-L112】
