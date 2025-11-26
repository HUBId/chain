from __future__ import annotations

import pytest
import yaml

from tools.alerts.baselines import UPTIME_BASELINES, compute_uptime_thresholds
from tools.alerts.settings import BLOCK_PRODUCTION_SLA, FINALITY_SLA, UPTIME_SLA
from tools.alerts.validation import (
    AlertValidationError,
    AlertValidationAggregateError,
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
    assert len(results) == 18

    results_by_case = {result.case.name: result for result in results}
    expected_case_names = {
        "consensus-anomaly",
        "snapshot-anomaly",
        "uptime-pause",
        "uptime-recovery",
        "uptime-join",
        "uptime-departure",
        "missed-slots",
        "missed-slot-recovery",
        "missed-blocks",
        "missed-block-recovery",
        "block-schedule-deficit",
        "block-schedule-recovery",
        "rpc-availability-outage",
        "rpc-availability-recovery",
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

    uptime_join = results_by_case["uptime-join"]
    assert uptime_join.fired_events == []
    assert uptime_join.webhook_payloads == []

    uptime_departure = results_by_case["uptime-departure"]
    assert {event.name for event in uptime_departure.fired_events} == uptime_departure.case.expected_alerts
    assert len(uptime_departure.webhook_payloads) == len(uptime_departure.fired_events)

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

    rpc_outage = results_by_case["rpc-availability-outage"]
    assert {event.name for event in rpc_outage.fired_events} == rpc_outage.case.expected_alerts
    assert len(rpc_outage.webhook_payloads) == len(rpc_outage.fired_events)

    rpc_recovery = results_by_case["rpc-availability-recovery"]
    assert rpc_recovery.fired_events == []
    assert rpc_recovery.webhook_payloads == []

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


def test_alert_validator_collects_errors_without_fail_fast(validator: AlertValidator) -> None:
    anomaly_case = default_validation_cases()[0]
    invalid_case = ValidationCase(
        name="aggregate-invalid",
        store=anomaly_case.store,
        expected_alerts=anomaly_case.expected_alerts | {"Unexpected"},
    )
    with AlertWebhookServer() as server:
        client = RecordedWebhookClient(server)
        with pytest.raises(AlertValidationAggregateError) as excinfo:
            validator.run([invalid_case], client, fail_fast=False)
    assert excinfo.value.results
    assert excinfo.value.errors
    assert excinfo.value.results[0].error is not None


def test_finality_alerts_match_sla_thresholds() -> None:
    with open("ops/alerts/consensus/finality.yaml", "r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)

    expressions = {
        rule["alert"]: rule["expr"]
        for group in manifest.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }

    assert f"> {int(FINALITY_SLA.lag_warning_slots)}" in expressions["ConsensusFinalityLagWarning"]
    assert f"> {int(FINALITY_SLA.lag_critical_slots)}" in expressions["ConsensusFinalityLagCritical"]
    assert f"> {int(FINALITY_SLA.gap_warning_blocks)}" in expressions["ConsensusFinalizedHeightGapWarning"]
    assert f"> {int(FINALITY_SLA.gap_critical_blocks)}" in expressions["ConsensusFinalizedHeightGapCritical"]


def test_block_production_alerts_match_sla_thresholds() -> None:
    with open("ops/alerts/consensus/liveness.yaml", "r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)

    expressions = {
        rule["alert"]: rule["expr"]
        for group in manifest.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }

    assert (
        f"< {BLOCK_PRODUCTION_SLA.warning_ratio}"
        in expressions["ConsensusBlockProductionLagWarning"]
    )
    assert (
        f"< {BLOCK_PRODUCTION_SLA.critical_ratio}"
        in expressions["ConsensusBlockProductionLagCritical"]
    )


def test_uptime_alerts_follow_baseline_buffers() -> None:
    thresholds = compute_uptime_thresholds(UPTIME_SLA)
    with open("ops/alerts/uptime/reputation.yaml", "r", encoding="utf-8") as handle:
        manifest = yaml.safe_load(handle)

    expressions = {
        rule["alert"]: rule["expr"]
        for group in manifest.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }

    warning_expr = expressions["UptimeParticipationDropWarning"]
    assert f"{UPTIME_BASELINES.participation_warning_buffer}" in warning_expr
    assert f">= {thresholds.participation_warning}" not in warning_expr
    assert str(UPTIME_SLA.participation_warning_ratio) in warning_expr

    observation_expr = expressions["UptimeObservationGapWarning"]
    assert str(int(UPTIME_BASELINES.observation_warning_buffer)) in observation_expr
    assert str(int(thresholds.observation_warning_seconds)) in observation_expr

    epoch_expr = expressions["TimetokeEpochDelayWarning"]
    assert str(int(UPTIME_BASELINES.epoch_warning_buffer)) in epoch_expr
    assert str(int(thresholds.epoch_warning_seconds)) in epoch_expr

    accrual_expr = expressions["TimetokeAccrualStallWarning"]
    assert str(UPTIME_BASELINES.timetoke_rate_buffer) in accrual_expr
    assert f"{thresholds.timetoke_rate_per_second:.5f}" in accrual_expr
