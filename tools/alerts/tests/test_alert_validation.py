from __future__ import annotations

import pytest

from tools.alerts.validation import (
    AlertValidationError,
    AlertValidator,
    AlertWebhookServer,
    RecordedWebhookClient,
    ValidationCase,
    default_alert_rules,
    default_validation_cases,
)


@pytest.fixture()
def validator() -> AlertValidator:
    return AlertValidator(default_alert_rules())


def test_alert_validation_triggers_expected_alerts(validator: AlertValidator) -> None:
    cases = default_validation_cases()
    with AlertWebhookServer() as server:
        client = RecordedWebhookClient(server)
        results = validator.run(cases, client)
    assert len(results) == 3

    consensus = next(result for result in results if result.case.name == "consensus-anomaly")
    assert {event.name for event in consensus.fired_events} == cases[0].expected_alerts
    assert len(consensus.webhook_payloads) == len(consensus.fired_events)
    first_payload = consensus.webhook_payloads[0]
    assert first_payload["alerts"][0]["labels"]["alertname"] in cases[0].expected_alerts

    snapshot = next(result for result in results if result.case.name == "snapshot-anomaly")
    assert {event.name for event in snapshot.fired_events} == cases[1].expected_alerts
    assert len(snapshot.webhook_payloads) == len(snapshot.fired_events)

    baseline = next(result for result in results if result.case.name == "baseline")
    assert baseline.fired_events == []
    assert baseline.webhook_payloads == []


def test_alert_validator_detects_missing_alerts(validator: AlertValidator) -> None:
    anomaly_case = default_validation_cases()[0]
    case = ValidationCase(
        name="invalid",
        store=anomaly_case.store,
        expected_alerts=anomaly_case.expected_alerts | {"NonexistentAlert"},
    )
    with AlertWebhookServer() as server:
        client = RecordedWebhookClient(server)
        with pytest.raises(AlertValidationError) as excinfo:
            validator.run([case], client)
    assert "NonexistentAlert" in str(excinfo.value)
