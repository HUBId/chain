from __future__ import annotations

import pytest
import yaml

from tools.alerts.validation import (
    AlertValidationError,
    AlertValidator,
    AlertWebhookServer,
    FINALITY_SLA,
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
    assert len(results) == 12

    results_by_case = {result.case.name: result for result in results}
    expected_case_names = {
        "consensus-anomaly",
        "snapshot-anomaly",
        "uptime-pause",
        "uptime-recovery",
        "missed-slots",
        "missed-slot-recovery",
        "missed-blocks",
        "missed-block-recovery",
        "restart-finality-correlation",
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

    missed_slots = results_by_case["missed-slots"]
    assert {event.name for event in missed_slots.fired_events} == missed_slots.case.expected_alerts
    assert len(missed_slots.webhook_payloads) == len(missed_slots.fired_events)

    missed_slot_recovery = results_by_case["missed-slot-recovery"]
    assert missed_slot_recovery.fired_events == []
    assert missed_slot_recovery.webhook_payloads == []

    missed_blocks = results_by_case["missed-blocks"]
    assert {event.name for event in missed_blocks.fired_events} == missed_blocks.case.expected_alerts
    assert len(missed_blocks.webhook_payloads) == len(missed_blocks.fired_events)

    missed_block_recovery = results_by_case["missed-block-recovery"]
    assert missed_block_recovery.fired_events == []
    assert missed_block_recovery.webhook_payloads == []

    restart_correlation = results_by_case["restart-finality-correlation"]
    assert {event.name for event in restart_correlation.fired_events} == restart_correlation.case.expected_alerts
    assert len(restart_correlation.webhook_payloads) == len(restart_correlation.fired_events)

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


def test_finality_alerts_match_sla_thresholds() -> None:
    with open("ops/alerts/consensus/finality.yaml", "r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)

    expressions = {
        rule["alert"]: rule["expr"]
        for group in manifest.get("groups", [])
        for rule in group.get("rules", [])
    }

    assert f"> {int(FINALITY_SLA.lag_warning_slots)}" in expressions["ConsensusFinalityLagWarning"]
    assert f"> {int(FINALITY_SLA.lag_critical_slots)}" in expressions["ConsensusFinalityLagCritical"]
    assert f"> {int(FINALITY_SLA.gap_warning_blocks)}" in expressions["ConsensusFinalizedHeightGapWarning"]
    assert f"> {int(FINALITY_SLA.gap_critical_blocks)}" in expressions["ConsensusFinalizedHeightGapCritical"]
