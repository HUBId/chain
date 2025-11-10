from __future__ import annotations

import sys
from typing import Sequence

try:  # pragma: no cover - import fallback for direct execution
    from .validation import (
        AlertValidationError,
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
    return f"[{result.case.name}] fired: {alert_names} (webhook payloads: {payloads})"


def run_validation() -> Sequence[ValidationResult]:
    validator = AlertValidator(default_alert_rules())
    cases = default_validation_cases()
    with AlertWebhookServer() as server:
        client = RecordedWebhookClient(server)
        return validator.run(cases, client)


def main() -> int:
    try:
        results = run_validation()
    except AlertValidationError as exc:
        print(f"::error ::{exc}", file=sys.stderr)
        return 1
    for result in results:
        print(_format_result(result))
    print("Alert validation completed successfully.")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
