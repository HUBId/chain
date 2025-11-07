#!/usr/bin/env python3
"""Aggregate metrics emitted by the simnet harness."""

from __future__ import annotations

import argparse
import json
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
    args = parser.parse_args(argv)

    failures: List[str] = []
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

    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
