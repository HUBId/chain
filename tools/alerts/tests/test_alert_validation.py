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
    assert len(results) == 7

    results_by_case = {result.case.name: result for result in results}
    expected_case_names = {
        "consensus-anomaly",
        "snapshot-anomaly",
        "uptime-pause",
        "uptime-recovery",
        "timetoke-epoch-delay",
        "timetoke-epoch-recovery",
        "baseline",
    }
    assert set(results_by_case) == expected_case_names

    consensus = results_by_case["consensus-anomaly"]
    assert {event.name for event in consensus.fired_events} == consensus.case.expected_alerts
    assert len(consensus.webhook_payloads) == len(consensus.fired_events)
    first_payload = consensus.webhook_payloads[0]
    assert first_payload["alerts"][0]["labels"]["alertname"] in consensus.case.expected_alerts

    snapshot = results_by_case["snapshot-anomaly"]
    assert {event.name for event in snapshot.fired_events} == snapshot.case.expected_alerts
    assert len(snapshot.webhook_payloads) == len(snapshot.fired_events)

    uptime_pause = results_by_case["uptime-pause"]
    assert {event.name for event in uptime_pause.fired_events} == uptime_pause.case.expected_alerts
    assert len(uptime_pause.webhook_payloads) == len(uptime_pause.fired_events)

    uptime_recovery = results_by_case["uptime-recovery"]
    assert uptime_recovery.fired_events == []
    assert uptime_recovery.webhook_payloads == []

    timetoke_delay = results_by_case["timetoke-epoch-delay"]
    assert {event.name for event in timetoke_delay.fired_events} == timetoke_delay.case.expected_alerts
    assert len(timetoke_delay.webhook_payloads) == len(timetoke_delay.fired_events)

    timetoke_recovery = results_by_case["timetoke-epoch-recovery"]
    assert timetoke_recovery.fired_events == []
    assert timetoke_recovery.webhook_payloads == []

    baseline = results_by_case["baseline"]
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
