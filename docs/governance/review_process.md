# Review process

Maintainers enforce code review with the same CI gates that protect
`<PRIMARY_BRANCH_OR_COMMIT>`. A pull request must not merge until every
required status check reports success:

- `fmt`, `clippy`, `tests-default`, `tests-stwo`, `tests-rpp-stark`
  (`./scripts/test.sh --backend <backend> --unit --integration`) keep the
  formatting/lint matrix and backend regressions aligned with the release
  workflow.【F:.github/workflows/release.yml†L55-L120】【F:scripts/test.sh†L4-L210】
- `snapshot-cli` validates the snapshot backup/restore CLI scripts via the
  `storage_snapshot` regression (`cargo test --test storage_snapshot`).【F:tests/storage_snapshot.rs†L1-L73】
- `observability-snapshot` exercises the Prometheus scrapes that back the
  snapshot/timetoke dashboards (`cargo xtask test-observability`).【F:tests/observability/snapshot_timetoke_metrics.rs†L1-L219】【F:xtask/src/main.rs†L96-L107】
- `simnet-admission` replays the `gossip-backpressure` scenario so admission
  policies and gossip throttling stay reproducible
  (`cargo run -p simnet -- --scenario tools/simnet/scenarios/gossip_backpressure.ron`).【F:tools/simnet/scenarios/gossip_backpressure.ron†L1-L16】【F:tools/simnet/src/main.rs†L1-L53】
- `runtime-smoke` builds `rpp-node` and runs the node, wallet, and hybrid modes
  through the `scripts/run_*_mode.sh` helpers, asserting health and metrics are
  wired before shipping.【F:.github/workflows/ci.yml†L185-L316】【F:scripts/run_node_mode.sh†L1-L160】

## Branch protection verification

When workflow names change, re-run the branch protection update to keep the
contexts in sync:

```sh
gh api \
  repos/:owner/:repo/branches/<PRIMARY_BRANCH_OR_COMMIT>/protection \
  --method PUT \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "fmt",
      "clippy",
      "tests-default",
      "tests-stwo",
      "tests-rpp-stark",
      "snapshot-cli",
      "observability-snapshot",
      "simnet-admission",
      "runtime-smoke"
    ]
  }
}
JSON
```

This mirrors the branch-protection guidance in the governance playbook so the
review process blocks merges when any gate regresses.【F:docs/GOVERNANCE.md†L19-L44】
