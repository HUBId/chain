#!/usr/bin/env python3
import json
import sys
from pathlib import Path


def load_report(path: Path) -> dict:
    if not path.exists():
        raise SystemExit(f"simulation report not found at {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def assert_threshold(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> None:
    report_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/sim-large/report.json")
    report = load_report(report_path)

    failures: list[str] = []

    bft = report.get("bft_success")
    assert_threshold(bft is not None, "bft_success metrics missing", failures)
    if bft:
        success_rate = float(bft.get("success_rate", 0.0))
        rounds = int(bft.get("rounds", 0))
        assert_threshold(rounds > 0, "bft_success.rounds must be positive", failures)
        assert_threshold(success_rate >= 0.5, f"BFT success rate too low: {success_rate:.3f}", failures)

    performance = report.get("performance")
    assert_threshold(performance is not None, "performance KPIs missing", failures)
    if performance:
        receive_rate = float(performance.get("receive_rate_per_sec", 0.0))
        duplicate_rate = float(performance.get("duplicate_rate", 1.0))
        assert_threshold(receive_rate >= 0.1, f"Receive throughput too low: {receive_rate:.3f} rx/s", failures)
        assert_threshold(duplicate_rate <= 0.5, f"Duplicate rate too high: {duplicate_rate:.3f}", failures)

    proof = report.get("proof_latency")
    if proof:
        p99 = float(proof.get("p99_ms", 0.0))
        assert_threshold(p99 <= 60000.0, f"Proof p99 latency too high: {p99:.2f} ms", failures)

    reputation = report.get("reputation_drift")
    if reputation:
        mean = float(reputation.get("mean_receives", 0.0))
        std_dev = float(reputation.get("std_dev_receives", 0.0))
        allowed = mean * 1.5 + 1.0
        assert_threshold(
            std_dev <= allowed,
            f"Validator reputation drift exceeds tolerance: σ={std_dev:.3f} mean={mean:.3f}",
            failures,
        )

    if failures:
        print("Simulation KPIs failed:")
        for entry in failures:
            print(f" - {entry}")
        raise SystemExit(1)

    print("Simulation KPIs within thresholds")


if __name__ == "__main__":
    main()
