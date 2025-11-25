from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

try:  # pragma: no cover - import fallback for direct execution
    from .validation import (
        AlertValidationError,
        AlertValidationAggregateError,
        AlertValidator,
        AlertWebhookServer,
        RecordedWebhookClient,
        ValidationResult,
        default_alert_rules,
        default_validation_cases,
    )
except ImportError:  # pragma: no cover - direct script execution fallback
    import pathlib

    PACKAGE_ROOT = pathlib.Path(__file__).resolve().parent
    sys.path.append(str(PACKAGE_ROOT))
    from validation import (  # type: ignore[assignment]
        AlertValidationError,
        AlertValidationAggregateError,
        AlertValidator,
        AlertWebhookServer,
        RecordedWebhookClient,
        ValidationResult,
        default_alert_rules,
        default_validation_cases,
    )


def _format_result(result: ValidationResult) -> str:
    alert_names = ", ".join(sorted(event.name for event in result.fired_events)) or "no alerts"
    payloads = len(result.webhook_payloads)
    status = "ok" if result.error is None else "failed"
    return f"[{result.case.name}] {status} :: fired: {alert_names} (webhook payloads: {payloads})"


def _serialize_result(result: ValidationResult) -> dict:
    fired_alerts = sorted(event.name for event in result.fired_events)
    return {
        "case": result.case.name,
        "expected_alerts": sorted(result.case.expected_alerts),
        "fired_alerts": fired_alerts,
        "missing_alerts": sorted(result.case.expected_alerts - set(fired_alerts)),
        "webhook_payloads": result.webhook_payloads,
        "error": None
        if result.error is None
        else {
            "message": str(result.error),
            "missing": result.error.missing,
            "unexpected": result.error.unexpected,
            "webhook_alerts": result.error.webhook_alerts,
        },
    }


def _write_artifacts(results: Sequence[ValidationResult], artifact_dir: Path) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    payload_path = artifact_dir / "alert_probe_results.json"
    with payload_path.open("w", encoding="utf-8") as fp:
        json.dump([_serialize_result(result) for result in results], fp, indent=2)


def run_validation() -> Sequence[ValidationResult]:
    validator = AlertValidator(default_alert_rules())
    cases = default_validation_cases()
    with AlertWebhookServer() as server:
        client = RecordedWebhookClient(server)
        return validator.run(cases, client, fail_fast=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run alert probes against synthetic metric stores")
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=None,
        help="Optional directory for probe artifacts (JSON summaries)",
    )
    args = parser.parse_args()

    errors: Sequence[AlertValidationError] = []
    try:
        results = run_validation()
    except AlertValidationAggregateError as exc:
        results = exc.results
        errors = exc.errors
    except AlertValidationError as exc:
        results = []
        errors = [exc]
    if args.artifacts is not None:
        _write_artifacts(results, args.artifacts)
    for result in results:
        print(_format_result(result))
    if errors:
        for error in errors:
            print(f"::error ::{error}", file=sys.stderr)
        return 1
    print("Alert validation completed successfully.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
