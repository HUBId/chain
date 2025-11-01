#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

log() {
  printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*" >&2
}

CARGO_PROFILE="${PERF_CARGO_PROFILE:-release}"
BATCH_SIZE="${PERF_BATCH_SIZE:-1000}"
NUMBER_OF_BATCHES="${PERF_NUMBER_OF_BATCHES:-50}"
DURATION_MINUTES="${PERF_DURATION_MINUTES:-1}"
CACHE_SIZE="${PERF_CACHE_SIZE:-1500000}"
DB_ROOT="${PERF_DB_ROOT:-target/perf-db}"
RESULT_DIR="target/perf-results"
BASELINE_PATH="${PERF_BASELINE_PATH:-logs/perf/baseline.json}"
ARTIFACT_ROOT="${PERF_ARTIFACT_ROOT:-logs/perf}"
TPS_TOLERANCE="${PERF_TPS_TOLERANCE:-0.05}"
P99_TOLERANCE="${PERF_P99_TOLERANCE:-0.10}"
BASELINE_ALPHA="${PERF_BASELINE_ALPHA:-0.2}"
UPDATE_BASELINE="${PERF_UPDATE_BASELINE:-0}"

mkdir -p "${DB_ROOT}" "${ARTIFACT_ROOT}"
rm -rf "${RESULT_DIR}"
mkdir -p "${RESULT_DIR}"

GIT_SHA="$(git rev-parse HEAD)"
RUN_ARTIFACT_DIR="${ARTIFACT_ROOT}/${GIT_SHA}"
mkdir -p "${RUN_ARTIFACT_DIR}"

export RUN_ARTIFACT_DIR BASELINE_PATH UPDATE_BASELINE TPS_TOLERANCE P99_TOLERANCE BASELINE_ALPHA

SCENARIOS=("create" "tenk-random" "zipf" "single")

run_benchmark() {
  local scenario="$1"
  local db_path="${DB_ROOT}/${scenario}"
  rm -rf "${db_path}"
  mkdir -p "${db_path}"
  log "Running ${scenario} benchmark (profile=${CARGO_PROFILE}, batch_size=${BATCH_SIZE}, number_of_batches=${NUMBER_OF_BATCHES}, duration=${DURATION_MINUTES}m)"
  cargo run --profile "${CARGO_PROFILE}" -p firewood-benchmark -- \
    --batch-size "${BATCH_SIZE}" \
    --number-of-batches "${NUMBER_OF_BATCHES}" \
    --duration-minutes "${DURATION_MINUTES}" \
    --cache-size "${CACHE_SIZE}" \
    --dbname "${db_path}" \
    "${scenario}"
}

for scenario in "${SCENARIOS[@]}"; do
  run_benchmark "${scenario}"
  if [[ ! -f "${RESULT_DIR}/${scenario}.json" ]]; then
    echo "::error::Benchmark summary for ${scenario} not found" >&2
    exit 1
  fi
  cp "${RESULT_DIR}/${scenario}.json" "${RUN_ARTIFACT_DIR}/${scenario}.json"
  log "Captured metrics for ${scenario} -> ${RUN_ARTIFACT_DIR}/${scenario}.json"

done

python3 <<'PY'
import json
import os
from pathlib import Path

result_dir = Path("target/perf-results")
artifact_dir = Path(os.environ["RUN_ARTIFACT_DIR"])
baseline_path = Path(os.environ["BASELINE_PATH"])
update_baseline = os.environ["UPDATE_BASELINE"] == "1"
tps_tolerance = float(os.environ["TPS_TOLERANCE"])
p99_tolerance = float(os.environ["P99_TOLERANCE"])
alpha = float(os.environ["BASELINE_ALPHA"])

slo_targets = {
    "create": {"tps": 150_000.0, "p99_ms": 120.0, "cpu_pct": 85.0, "memory_gb": 8.0},
    "tenk-random": {"tps": 90_000.0, "p99_ms": 180.0, "cpu_pct": 85.0, "memory_gb": 8.0},
    "zipf": {"tps": 110_000.0, "p99_ms": 200.0, "cpu_pct": 85.0, "memory_gb": 8.0},
    "single": {"tps": 60_000.0, "p99_ms": 150.0, "cpu_pct": 75.0, "memory_gb": 6.0},
}

summaries = {}
for path in sorted(result_dir.glob("*.json")):
    with path.open("r", encoding="utf-8") as fp:
        data = json.load(fp)
    scenario = data["scenario"]
    summaries[scenario] = data

if not summaries:
    raise SystemExit("no benchmark summaries were produced")

if baseline_path.exists():
    with baseline_path.open("r", encoding="utf-8") as fp:
        baseline = json.load(fp)
else:
    baseline = {"scenarios": {}}

baseline.setdefault("scenarios", {})
report = {"scenarios": {}, "regressions": []}

for scenario, metrics in summaries.items():
    slo = slo_targets.get(scenario, {})
    delta = {}
    if slo.get("tps"):
        delta["tps_delta_pct"] = (
            (metrics["throughput_tps"] - slo["tps"]) / slo["tps"]
        )
    if slo.get("p99_ms"):
        delta["p99_delta_pct"] = (
            (slo["p99_ms"] - metrics["latency_ms"]["p99"]) / slo["p99_ms"]
        )

    baseline_entry = baseline["scenarios"].setdefault(
        scenario,
        {
            "avg_tps": metrics["throughput_tps"],
            "avg_p99_ms": metrics["latency_ms"]["p99"],
            "samples": 0,
        },
    )

    regressed = False
    if baseline_entry["avg_tps"] > 0:
        if metrics["throughput_tps"] < baseline_entry["avg_tps"] * (1 - tps_tolerance):
            regressed = True
            report["regressions"].append(
                {
                    "scenario": scenario,
                    "metric": "throughput_tps",
                    "baseline": baseline_entry["avg_tps"],
                    "observed": metrics["throughput_tps"],
                    "tolerance": tps_tolerance,
                }
            )
    if baseline_entry["avg_p99_ms"] > 0:
        if metrics["latency_ms"]["p99"] > baseline_entry["avg_p99_ms"] * (1 + p99_tolerance):
            regressed = True
            report["regressions"].append(
                {
                    "scenario": scenario,
                    "metric": "latency_ms.p99",
                    "baseline": baseline_entry["avg_p99_ms"],
                    "observed": metrics["latency_ms"]["p99"],
                    "tolerance": p99_tolerance,
                }
            )

    if update_baseline:
        samples = baseline_entry.get("samples", 0)
        if samples > 0:
            baseline_entry["avg_tps"] = (1 - alpha) * baseline_entry["avg_tps"] + alpha * metrics["throughput_tps"]
            baseline_entry["avg_p99_ms"] = (1 - alpha) * baseline_entry["avg_p99_ms"] + alpha * metrics["latency_ms"]["p99"]
        else:
            baseline_entry["avg_tps"] = metrics["throughput_tps"]
            baseline_entry["avg_p99_ms"] = metrics["latency_ms"]["p99"]
        baseline_entry["samples"] = samples + 1

    report["scenarios"][scenario] = {
        "metrics": metrics,
        "slo_targets": slo,
        "slo_delta": delta,
        "baseline": baseline_entry,
        "regressed": regressed,
    }

summary_path = artifact_dir / "summary.json"
with summary_path.open("w", encoding="utf-8") as fp:
    json.dump(report, fp, indent=2, sort_keys=True)

if update_baseline:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with baseline_path.open("w", encoding="utf-8") as fp:
        json.dump(baseline, fp, indent=2, sort_keys=True)

if report["regressions"]:
    failure_path = artifact_dir / "regressions.json"
    with failure_path.open("w", encoding="utf-8") as fp:
        json.dump(report["regressions"], fp, indent=2, sort_keys=True)
    raise SystemExit(1)
PY
status=$?

if [[ ${status} -ne 0 ]]; then
  echo "::error::Performance regression detected" >&2
  exit ${status}
fi

echo "Performance benchmarks complete. Artifacts available under ${RUN_ARTIFACT_DIR}" >&2
