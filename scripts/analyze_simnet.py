#!/usr/bin/env python3
"""Aggregate metrics emitted by the simnet harness."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_summary(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def render_network_report(path: Path, summary: Dict[str, Any]) -> str:
    propagation = summary.get("propagation") or {}
    p50 = propagation.get("p50_ms")
    p95 = propagation.get("p95_ms")
    lines = [
        f"summary: {path}",
        f"  publishes: {summary.get('total_publishes', 0)}",
        f"  receives: {summary.get('total_receives', 0)}",
        f"  duplicates: {summary.get('duplicates', 0)}",
        f"  chunk_retries: {summary.get('chunk_retries', 0)}",
    ]
    if p50 is not None and p95 is not None:
        lines.append(f"  propagation_ms: p50={p50:.2f}, p95={p95:.2f}")
    else:
        lines.append("  propagation_ms: n/a")

    recovery = summary.get("recovery") or {}
    resume_events = len(recovery.get("resume_latencies_ms", []) or [])
    if resume_events:
        lines.append(f"  resume_events: {resume_events}")
        max_resume = recovery.get("max_resume_latency_ms")
        mean_resume = recovery.get("mean_resume_latency_ms")
        if max_resume is not None:
            lines.append(f"  max_resume_ms: {max_resume:.2f}")
        if mean_resume is not None:
            lines.append(f"  mean_resume_ms: {mean_resume:.2f}")

    bandwidth = summary.get("bandwidth") or {}
    if bandwidth:
        lines.append(
            "  bandwidth_throttling: "
            f"peers={bandwidth.get('throttled_peers', 0)}, "
            f"events={bandwidth.get('slow_peer_events', 0)}"
        )

    backpressure = summary.get("gossip_backpressure") or {}
    if backpressure:
        lines.append(
            "  gossip_backpressure: "
            f"events={backpressure.get('events', 0)}, "
            f"queue_full={backpressure.get('queue_full_messages', 0)}"
        )

    resource_usage = summary.get("resource_usage") or {}
    if resource_usage:
        max_rss = resource_usage.get("max_rss_bytes")
        max_rss_mib = max_rss / (1024 * 1024) if max_rss is not None else None
        cpu_percent = resource_usage.get("avg_cpu_percent")
        wall_secs = resource_usage.get("wall_time_secs")
        cpu_time = resource_usage.get("cpu_time_secs")
        formatted_parts = []
        if cpu_percent is not None:
            formatted_parts.append(f"cpu%={cpu_percent:.1f}")
        if cpu_time is not None and wall_secs is not None:
            formatted_parts.append(f"cpu_time_s={cpu_time:.1f}/{wall_secs:.1f}")
        if max_rss_mib is not None:
            formatted_parts.append(f"max_rss_mib={max_rss_mib:.0f}")
        if formatted_parts:
            lines.append("  resources: " + ", ".join(formatted_parts))

    comparison = summary.get("comparison")
    if comparison:
        deltas = comparison.get("deltas", {})
        lines.append("  comparison:")
        lines.append(
            "    publishes_delta: "
            f"{deltas.get('total_publishes', 'n/a')}"
        )
        lines.append(
            "    receives_delta: "
            f"{deltas.get('total_receives', 'n/a')}"
        )
        lines.append(
            "    duplicates_delta: "
            f"{deltas.get('duplicates', 'n/a')}"
        )
        if deltas.get("propagation_p95_ms") is not None:
            lines.append(
                "    propagation_delta_ms: "
                f"p50={deltas.get('propagation_p50_ms'):.2f}, "
                f"p95={deltas.get('propagation_p95_ms'):.2f}"
            )
    return "\n".join(lines)


def render_consensus_report(path: Path, summary: Dict[str, Any]) -> str:
    prove = summary.get("prove_ms") or {}
    verify = summary.get("verify_ms") or {}
    proof_bytes = summary.get("proof_bytes") or {}
    lines = [
        f"summary: {path}",
        f"  runs: {summary.get('runs', 0)} (validators={summary.get('validators', 'n/a')}, witness_commitments={summary.get('witness_commitments', 'n/a')})",
        f"  prove_ms: p50={prove.get('p50', 0.0):.2f}, p95={prove.get('p95', 0.0):.2f}, max={prove.get('max', 0.0):.2f}",
        f"  verify_ms: p50={verify.get('p50', 0.0):.2f}, p95={verify.get('p95', 0.0):.2f}, max={verify.get('max', 0.0):.2f}",
        f"  proof_bytes: p50={proof_bytes.get('p50', 0.0):.0f}, p95={proof_bytes.get('p95', 0.0):.0f}, max={proof_bytes.get('max', 0.0):.0f}",
    ]
    if summary.get("failures"):
        lines.append(f"  failures: {len(summary['failures'])}")
    for label in ("tamper_vrf", "tamper_quorum"):
        tamper = summary.get(label)
        if tamper:
            lines.append(
                f"  {label}: attempts={tamper.get('attempts', 0)}, rejected={tamper.get('rejected', 0)}, unexpected_accepts={tamper.get('unexpected_accepts', 0)}"
            )
    return "\n".join(lines)


def render_report(path: Path, summary: Dict[str, Any]) -> str:
    if summary.get("kind") == "consensus-load":
        return render_consensus_report(path, summary)
    return render_network_report(path, summary)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "summaries",
        nargs="+",
        type=Path,
        help="One or more JSON summaries emitted by simnet",
    )
    parser.add_argument(
        "--max-propagation-p95",
        type=float,
        default=500.0,
        help="Fail if the propagation p95 exceeds this threshold (ms)",
    )
    parser.add_argument(
        "--max-consensus-prove-p95",
        type=float,
        default=5500.0,
        help="Fail if the consensus prove p95 exceeds this threshold (ms)",
    )
    parser.add_argument(
        "--max-consensus-verify-p95",
        type=float,
        default=3200.0,
        help="Fail if the consensus verify p95 exceeds this threshold (ms)",
    )
    parser.add_argument(
        "--max-consensus-unexpected",
        type=int,
        default=0,
        help="Fail if more than this many tampered consensus proofs are accepted",
    )
    parser.add_argument(
        "--max-resume-latency",
        type=float,
        default=5000.0,
        help="Fail if the recovery max resume latency exceeds this threshold (ms)",
    )
    parser.add_argument(
        "--max-cpu-percent",
        type=float,
        default=320.0,
        help="Fail if simnet average CPU exceeds this percentage of a single core",
    )
    parser.add_argument(
        "--max-memory-mib",
        type=float,
        default=3500.0,
        help="Fail if simnet RSS exceeds this many MiB",
    )
    parser.add_argument(
        "--capture-dir",
        type=Path,
        help="If set, copy logs/profiles for failing summaries into this directory",
    )
    args = parser.parse_args(argv)

    failures: List[str] = []
    failure_roots: List[Path] = []
    for path in args.summaries:
        summary = load_summary(path)
        print(render_report(path, summary))
        print()

        if summary.get("kind") == "consensus-load":
            prove = (summary.get("prove_ms") or {}).get("p95")
            if prove is not None and prove > args.max_consensus_prove_p95:
                failures.append(
                    f"{path} consensus prove p95 {prove:.2f}ms exceeds threshold {args.max_consensus_prove_p95:.2f}ms"
                )
            verify = (summary.get("verify_ms") or {}).get("p95")
            if verify is not None and verify > args.max_consensus_verify_p95:
                failures.append(
                    f"{path} consensus verify p95 {verify:.2f}ms exceeds threshold {args.max_consensus_verify_p95:.2f}ms"
                )
            for label in ("tamper_vrf", "tamper_quorum"):
                tamper = summary.get(label) or {}
                if tamper.get("unexpected_accepts", 0) > args.max_consensus_unexpected:
                    failures.append(
                        f"{path} {label} unexpected accepts {tamper.get('unexpected_accepts', 0)} exceeds threshold {args.max_consensus_unexpected}"
                    )
            continue

        propagation = summary.get("propagation") or {}
        p95 = propagation.get("p95_ms")
        if p95 is not None and p95 > args.max_propagation_p95:
            failures.append(
                f"{path} propagation p95 {p95:.2f}ms exceeds threshold {args.max_propagation_p95:.2f}ms"
            )

        recovery = summary.get("recovery") or {}
        max_resume = recovery.get("max_resume_latency_ms")
        if max_resume is not None and max_resume > args.max_resume_latency:
            failures.append(
                f"{path} recovery max resume {max_resume:.2f}ms exceeds threshold {args.max_resume_latency:.2f}ms"
            )

        fault_kinds = {fault.get("kind") for fault in summary.get("faults") or []}
        if "partition_start" in fault_kinds and "partition_end" not in fault_kinds:
            failures.append(f"{path} recorded a partition_start without a corresponding partition_end event")
        if "partition_end" in fault_kinds:
            if not recovery:
                failures.append(f"{path} recorded a partition_end without recovery metrics")
            elif not (recovery.get("resume_latencies_ms") or []):
                failures.append(
                    f"{path} expected peer recovery resume events but none were recorded"
                )

        bandwidth = summary.get("bandwidth") or {}
        if bandwidth and bandwidth.get("throttled_peers", 0) == 0:
            failures.append(
                f"{path} reported bandwidth throttling metrics without throttled peers"
            )
        if bandwidth and bandwidth.get("slow_peer_events", 0) == 0:
            failures.append(
                f"{path} reported bandwidth throttling metrics without slow-peer events"
            )

        backpressure = summary.get("gossip_backpressure") or {}
        if backpressure:
            if backpressure.get("events", 0) == 0:
                failures.append(
                    f"{path} reported gossip backpressure metrics without events"
                )
            if backpressure.get("unique_peers", 0) == 0:
                failures.append(
                    f"{path} reported gossip backpressure metrics without unique peers"
                )
            if backpressure.get("queue_full_messages", 0) == 0:
                failures.append(
                    f"{path} reported gossip backpressure metrics without queue-full samples"
                )

        resource_usage = summary.get("resource_usage")
        if not resource_usage:
            failures.append(f"{path} missing resource_usage block")
            failure_roots.append(path)
        else:
            cpu_percent = resource_usage.get("avg_cpu_percent")
            if cpu_percent is not None and cpu_percent > args.max_cpu_percent:
                failures.append(
                    f"{path} cpu {cpu_percent:.1f}% exceeds threshold {args.max_cpu_percent:.1f}%"
                )
                failure_roots.append(path)

            max_rss = resource_usage.get("max_rss_bytes")
            if max_rss is not None:
                max_rss_mib = max_rss / (1024 * 1024)
                if max_rss_mib > args.max_memory_mib:
                    failures.append(
                        f"{path} rss {max_rss_mib:.0f}MiB exceeds threshold {args.max_memory_mib:.0f}MiB"
                    )
                    failure_roots.append(path)
            else:
                failures.append(f"{path} missing max_rss_bytes in resource_usage")
                failure_roots.append(path)

    if failures:
        if args.capture_dir:
            args.capture_dir.mkdir(parents=True, exist_ok=True)
            unique_roots = {p.parent.parent for p in failure_roots if p.parent.parent}
            for root in unique_roots:
                scenario_root = args.capture_dir / root.name
                for bucket in ("logs", "profiles", "summaries"):
                    src = root / bucket
                    dst = scenario_root / bucket
                    if src.exists():
                        shutil.copytree(src, dst, dirs_exist_ok=True)
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
