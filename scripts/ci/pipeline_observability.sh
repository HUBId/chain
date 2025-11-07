#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

./scripts/ci/validate_prometheus_rules.rb

cargo test --test pipeline_orchestrator \
  pipeline_feed_propagates_errors_from_event_stream \
  pipeline_telemetry_summary_reports_latency_and_alerts
