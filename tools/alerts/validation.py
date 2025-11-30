from __future__ import annotations

import datetime as _dt
import json
import math
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple

from tools.alerts.baselines import UPTIME_BASELINES, UptimeBaselineThresholds, compute_uptime_thresholds
from tools.alerts.settings import (
    BLOCK_PRODUCTION_SLA,
    FINALITY_SLA,
    PIPELINE_LATENCY_SLA,
    UPTIME_SLA,
)

UPTIME_THRESHOLDS: UptimeBaselineThresholds = compute_uptime_thresholds(UPTIME_SLA)

PROVER_QUEUE_WARNING_DEPTH = 2.0
PROVER_LATENCY_WARNING_SECONDS = 180.0
PROVER_QUEUE_CORRELATION_DURATION = 300.0
PROVER_LATENCY_CORRELATION_DURATION = 600.0
MEMPOOL_PROBE_MIN_RATIO = 0.5
MEMPOOL_PROBE_FAILURE_DURATION = 600.0
PIPELINE_LATENCY_DURATION = PIPELINE_LATENCY_SLA.evaluation_duration_seconds

import socketserver


@dataclass(frozen=True)
class Sample:
    """A single metric sample at a timestamp."""

    timestamp: float
    value: float


class MetricSeries:
    """Chronological series of metric samples."""

    def __init__(self, samples: Sequence[Sample]):
        self._samples: List[Sample] = sorted(samples, key=lambda sample: sample.timestamp)

    @property
    def samples(self) -> Sequence[Sample]:
        return self._samples

    def latest_at(self, timestamp: float) -> Optional[Sample]:
        """Return the most recent sample at or before ``timestamp``."""

        for sample in reversed(self._samples):
            if sample.timestamp <= timestamp:
                return sample
        return None

    def delta_over_window(self, timestamp: float, window: float) -> Optional[float]:
        end = self.latest_at(timestamp)
        if end is None:
            return None
        start = self.latest_at(timestamp - window)
        if start is None:
            return None
        return end.value - start.value

    def rate_over_window(self, timestamp: float, window: float) -> Optional[float]:
        delta = self.delta_over_window(timestamp, window)
        if delta is None:
            return None
        if window <= 0:
            return None
        return delta / window

    def value_at(self, timestamp: float) -> Optional[float]:
        sample = self.latest_at(timestamp)
        if sample is None:
            return None
        return sample.value


@dataclass(frozen=True)
class MetricDefinition:
    metric: str
    labels: Dict[str, str]
    samples: Sequence[Sample]


def _series_key(metric: str, labels: Optional[Dict[str, str]]) -> str:
    if not labels:
        return metric
    parts = [f"{key}={value}" for key, value in sorted(labels.items())]
    return f"{metric}|" + ",".join(parts)


class MetricStore:
    """Collection of metric series keyed by metric name and labels."""

    def __init__(self, series: Dict[str, MetricSeries]):
        self._series = series

    @classmethod
    def from_definitions(cls, definitions: Sequence[MetricDefinition]) -> "MetricStore":
        series = {
            _series_key(defn.metric, defn.labels): MetricSeries(defn.samples)
            for defn in definitions
        }
        return cls(series)

    def series(self, metric: str, labels: Optional[Dict[str, str]] = None) -> Optional[MetricSeries]:
        return self._series.get(_series_key(metric, labels))

    def series_by_metric(self, metric: str) -> Sequence[Tuple[Dict[str, str], MetricSeries]]:
        matches: List[Tuple[Dict[str, str], MetricSeries]] = []
        for key, series in self._series.items():
            metric_name, _, label_str = key.partition("|")
            if metric_name != metric:
                continue
            labels: Dict[str, str] = {}
            if label_str:
                for pair in label_str.split(","):
                    if "=" not in pair:
                        continue
                    k, v = pair.split("=", maxsplit=1)
                    labels[k] = v
            matches.append((labels, series))
        return matches

    def all_timestamps(self) -> Iterator[float]:
        seen: Set[float] = set()
        for metric_series in self._series.values():
            for sample in metric_series.samples:
                if sample.timestamp not in seen:
                    seen.add(sample.timestamp)
                    yield sample.timestamp


@dataclass
class AlertComputation:
    starts_at: float
    value: Optional[float] = None
    details: Optional[str] = None


@dataclass
class AlertEvent:
    name: str
    severity: str
    service: str
    labels: Dict[str, str]
    annotations: Dict[str, str]
    starts_at: float
    value: Optional[float] = None


class AlertRule:
    def __init__(
        self,
        name: str,
        severity: str,
        service: str,
        summary: str,
        description: str,
        runbook_url: str,
        evaluator: Callable[[MetricStore], Optional[AlertComputation]],
    ) -> None:
        self.name = name
        self.severity = severity
        self.service = service
        self.summary = summary
        self.description = description
        self.runbook_url = runbook_url
        self._evaluator = evaluator

    def evaluate(self, metrics: MetricStore) -> Optional[AlertEvent]:
        computation = self._evaluator(metrics)
        if computation is None:
            return None
        labels = {
            "alertname": self.name,
            "severity": self.severity,
            "service": self.service,
        }
        annotations = {
            "summary": self.summary,
            "description": self.description,
            "runbook_url": self.runbook_url,
        }
        if computation.value is not None:
            annotations["validation.value"] = f"{computation.value:.6f}"
        if computation.details:
            annotations["validation.details"] = computation.details
        return AlertEvent(
            name=self.name,
            severity=self.severity,
            service=self.service,
            labels=labels,
            annotations=annotations,
            starts_at=computation.starts_at,
            value=computation.value,
        )


@dataclass
class ValidationCase:
    name: str
    store: MetricStore
    expected_alerts: Set[str]


@dataclass
class ValidationResult:
    case: ValidationCase
    fired_events: List[AlertEvent]
    webhook_payloads: List[Dict[str, object]]
    error: Optional[AlertValidationError] = None


class AlertValidationError(RuntimeError):
    def __init__(
        self,
        case_name: str,
        missing: Sequence[str],
        unexpected: Sequence[str],
        webhook_alerts: Sequence[str],
    ) -> None:
        message_parts: List[str] = []
        if missing:
            message_parts.append(f"missing alerts: {', '.join(missing)}")
        if unexpected:
            message_parts.append(f"unexpected alerts: {', '.join(unexpected)}")
        if webhook_alerts:
            message_parts.append(f"webhook alerts observed: {', '.join(webhook_alerts)}")
        message = f"validation case '{case_name}' failed"
        if message_parts:
            message = f"{message} ({'; '.join(message_parts)})"
        super().__init__(message)
        self.case_name = case_name
        self.missing = list(missing)
        self.unexpected = list(unexpected)
        self.webhook_alerts = list(webhook_alerts)


class AlertValidationAggregateError(RuntimeError):
    def __init__(self, errors: Sequence[AlertValidationError], results: Sequence[ValidationResult]):
        message = "; ".join(str(error) for error in errors)
        super().__init__(f"{len(errors)} alert validation failures: {message}")
        self.errors = list(errors)
        self.results = list(results)


class AlertValidator:
    def __init__(self, rules: Sequence[AlertRule]):
        self._rules = list(rules)

    def run(
        self,
        cases: Sequence[ValidationCase],
        webhook: "RecordedWebhookClient",
        *,
        fail_fast: bool = True,
    ) -> List[ValidationResult]:
        results: List[ValidationResult] = []
        errors: List[AlertValidationError] = []
        for case in cases:
            fired_events: List[AlertEvent] = []
            for rule in self._rules:
                event = rule.evaluate(case.store)
                if event is not None:
                    webhook.send(event)
                    fired_events.append(event)
            payloads = webhook.consume_events()
            payload_alerts: List[str] = []
            for payload in payloads:
                alerts = payload.get("alerts")
                if not isinstance(alerts, list):
                    continue
                for alert in alerts:
                    if isinstance(alert, dict):
                        name = alert.get("labels", {}).get("alertname")
                        if isinstance(name, str):
                            payload_alerts.append(name)
            fired_names = {event.name for event in fired_events}
            expected_names = set(case.expected_alerts)
            missing = sorted(expected_names - fired_names)
            unexpected = sorted(fired_names - expected_names)
            payload_set = set(payload_alerts)
            if missing or unexpected or payload_set != fired_names or len(payload_alerts) != len(fired_events):
                error = AlertValidationError(case.name, missing, unexpected, payload_alerts)
                results.append(
                    ValidationResult(
                        case=case,
                        fired_events=fired_events,
                        webhook_payloads=payloads,
                        error=error,
                    )
                )
                errors.append(error)
                if fail_fast:
                    raise error
                continue
            results.append(ValidationResult(case=case, fired_events=fired_events, webhook_payloads=payloads))
        if errors:
            raise AlertValidationAggregateError(errors, results)
        return results


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


class AlertWebhookServer:
    """Simple HTTP server that records webhook payloads."""

    def __init__(self) -> None:
        self._events: List[Dict[str, object]] = []
        self._lock = threading.Lock()
        self._server: Optional[_ThreadedHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.url: Optional[str] = None

    def __enter__(self) -> "AlertWebhookServer":
        handler = self._make_handler()
        self._server = _ThreadedHTTPServer(("127.0.0.1", 0), handler)
        host, port = self._server.server_address
        self.url = f"http://{host}:{port}/"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _make_handler(self) -> Callable[[BaseHTTPRequestHandler, bytes], None]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    payload = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError:
                    self.send_response(HTTPStatus.BAD_REQUEST)
                    self.end_headers()
                    return
                with server._lock:
                    server._events.append(payload)
                self.send_response(HTTPStatus.OK)
                self.end_headers()

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

        return Handler

    def consume_events(self) -> List[Dict[str, object]]:
        with self._lock:
            events = list(self._events)
            self._events.clear()
        return events


class RecordedWebhookClient:
    """HTTP webhook sender that can read back recorded payloads."""

    def __init__(self, server: AlertWebhookServer):
        if server.url is None:
            raise RuntimeError("AlertWebhookServer must be entered before creating the client")
        self._server = server
        self._url = server.url

    def send(self, event: AlertEvent) -> None:
        payload = self._build_payload(event)
        data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                # Drain the response to ensure the connection is closed promptly.
                response.read()
        except urllib.error.URLError as exc:  # pragma: no cover - network issues raise URLError
            raise RuntimeError(f"failed to deliver webhook payload to {self._url}: {exc}") from exc

    def consume_events(self) -> List[Dict[str, object]]:
        return self._server.consume_events()

    @staticmethod
    def _build_payload(event: AlertEvent) -> Dict[str, object]:
        starts_at = _dt.datetime.utcfromtimestamp(event.starts_at).isoformat() + "Z"
        payload = {
            "receiver": "alert-validation",
            "status": "firing",
            "alerts": [
                {
                    "status": "firing",
                    "labels": event.labels,
                    "annotations": event.annotations,
                    "startsAt": starts_at,
                    "endsAt": starts_at,
                    "generatorURL": "http://localhost/alert-validation",
                }
            ],
            "groupLabels": {"service": event.service},
            "commonLabels": event.labels,
            "commonAnnotations": event.annotations,
            "externalURL": "http://localhost/alert-validation",
        }
        if event.value is not None:
            payload["alerts"][0]["annotations"]["observed_value"] = f"{event.value:.6f}"
        return payload


def _histogram_quantile(quantile: float, buckets: Sequence[Tuple[str, float]]) -> float:
    parsed: List[Tuple[float, float]] = []
    for le, rate in buckets:
        if le == "+Inf":
            bound = math.inf
        else:
            bound = float(le)
        parsed.append((bound, rate))
    parsed.sort(key=lambda item: item[0])
    if not parsed:
        return 0.0
    total = parsed[-1][1]
    if total <= 0:
        return 0.0
    target = quantile * total
    previous_bound = 0.0
    previous_cumulative = 0.0
    for bound, cumulative in parsed:
        if cumulative >= target:
            if math.isinf(bound):
                return previous_bound
            bucket_total = cumulative - previous_cumulative
            if bucket_total <= 0:
                return bound
            fraction = (target - previous_cumulative) / bucket_total
            fraction = max(0.0, min(1.0, fraction))
            return previous_bound + (bound - previous_bound) * fraction
        previous_bound = bound
        previous_cumulative = cumulative
    return parsed[-1][0]


def _sustained(records: Sequence[Tuple[float, bool]], duration: float) -> Tuple[bool, Optional[float]]:
    if duration <= 0:
        for timestamp, flag in records:
            if flag:
                return True, timestamp
        return False, None
    start: Optional[float] = None
    for timestamp, flag in records:
        if flag:
            if start is None:
                start = timestamp
            if timestamp - start >= duration:
                return True, start
        else:
            start = None
    return False, None


def _maintenance_active(store: MetricStore, scope: str, timestamp: float) -> bool:
    for metric_name in ("maintenance:window_active", "rpp_node_maintenance_window_active"):
        series = store.series(metric_name, {"scope": scope}) or store.series(metric_name)
        if series is None:
            continue
        value = series.value_at(timestamp)
        if value is not None and value > 0:
            return True
    return False



def _evaluate_consensus_vrf_slow(store: MetricStore) -> Optional[AlertComputation]:
    bounds = ["10", "20", "50", "100", "+Inf"]
    bucket_series: List[Tuple[str, MetricSeries]] = []
    for bound in bounds:
        series = store.series("consensus_vrf_verification_time_ms_bucket", {"result": "success", "le": bound})
        if series is None:
            return None
        bucket_series.append((bound, series))
    timestamps: List[float] = sorted({sample.timestamp for _, series in bucket_series for sample in series.samples})
    quantiles: List[Tuple[float, float]] = []
    evaluations: List[Tuple[float, bool]] = []
    for timestamp in timestamps:
        rates: List[Tuple[str, float]] = []
        valid = True
        for bound, series in bucket_series:
            rate = series.rate_over_window(timestamp, 300.0)
            if rate is None:
                valid = False
                break
            rates.append((bound, rate))
        if not valid:
            continue
        quantile = _histogram_quantile(0.95, rates)
        quantiles.append((timestamp, quantile))
        evaluations.append((timestamp, quantile > 50.0))
    fired, start_ts = _sustained(evaluations, 300.0)
    if not fired or start_ts is None:
        return None
    observed = max((value for ts, value in quantiles if ts >= start_ts), default=None)
    detail = None
    if observed is not None:
        detail = f"p95 latency {observed:.2f} ms"
    return AlertComputation(starts_at=start_ts, value=observed, details=detail)


def _evaluate_consensus_vrf_failure_burst(store: MetricStore) -> Optional[AlertComputation]:
    series = store.series("consensus_vrf_verification_time_ms_count", {"result": "failure"})
    if series is None:
        return None
    timestamps = [sample.timestamp for sample in series.samples]
    observed_ts: Optional[float] = None
    observed_delta: Optional[float] = None
    for timestamp in timestamps:
        delta = series.delta_over_window(timestamp, 300.0)
        if delta is not None and delta > 2.0:
            observed_ts = timestamp
            observed_delta = delta
    if observed_ts is None:
        return None
    detail = None
    if observed_delta is not None:
        detail = f"failures in 5m window: {observed_delta:.0f}"
    return AlertComputation(starts_at=observed_ts, value=observed_delta, details=detail)


def _evaluate_consensus_quorum_failure(store: MetricStore) -> Optional[AlertComputation]:
    series = store.series("consensus_quorum_verifications_total", {"result": "failure"})
    if series is None:
        return None
    timestamps = [sample.timestamp for sample in series.samples]
    observed_ts: Optional[float] = None
    for timestamp in timestamps:
        delta = series.delta_over_window(timestamp, 120.0)
        if delta is not None and delta > 0:
            observed_ts = timestamp
            break
    if observed_ts is None:
        return None
    return AlertComputation(starts_at=observed_ts, value=1.0, details="quorum verification failure detected")


def _evaluate_snapshot_lag(store: MetricStore, threshold: float, duration: float) -> Optional[AlertComputation]:
    series = store.series("snapshot_stream_lag_seconds", {})
    if series is None:
        return None
    evaluations: List[Tuple[float, bool]] = []
    values: List[Tuple[float, float]] = []
    for sample in series.samples:
        evaluations.append((sample.timestamp, sample.value > threshold))
        values.append((sample.timestamp, sample.value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    observed = max((value for ts, value in values if ts >= start_ts), default=None)
    detail = None
    if observed is not None:
        detail = f"lag {observed:.2f} seconds"
    return AlertComputation(starts_at=start_ts, value=observed, details=detail)


def _evaluate_snapshot_zero_throughput(store: MetricStore, rate_window: float, duration: float) -> Optional[AlertComputation]:
    series = store.series("snapshot_bytes_sent_total", {"kind": "chunk"})
    if series is None:
        return None
    timestamps = [sample.timestamp for sample in series.samples]
    evaluations: List[Tuple[float, bool]] = []
    rates: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        activity = series.delta_over_window(timestamp, 1800.0)
        rate = series.rate_over_window(timestamp, rate_window)
        if activity is None or rate is None:
            continue
        condition = activity > 0 and rate < 1.0
        evaluations.append((timestamp, condition))
        rates.append((timestamp, rate))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    observed_rate = min((rate for ts, rate in rates if ts >= start_ts), default=None)
    detail = None
    if observed_rate is not None:
        detail = f"throughput rate {observed_rate:.4f} bytes/s"
    return AlertComputation(starts_at=start_ts, value=observed_rate, details=detail)


def _evaluate_snapshot_chunk_failures(
    store: MetricStore,
    outbound_threshold: float,
    inbound_threshold: float,
    duration: float,
) -> Optional[AlertComputation]:
    outbound = store.series("light_client_chunk_failures_total", {"direction": "outbound", "kind": "chunk"})
    inbound = store.series("light_client_chunk_failures_total", {"direction": "inbound", "kind": "chunk"})
    if outbound is None and inbound is None:
        return None
    timestamps: Set[float] = set()
    if outbound is not None:
        timestamps.update(sample.timestamp for sample in outbound.samples)
    if inbound is not None:
        timestamps.update(sample.timestamp for sample in inbound.samples)
    evaluations: List[Tuple[float, bool]] = []
    observed_values: List[Tuple[float, float]] = []
    for timestamp in sorted(timestamps):
        outbound_delta = outbound.delta_over_window(timestamp, 600.0) if outbound is not None else None
        inbound_delta = inbound.delta_over_window(timestamp, 600.0) if inbound is not None else None
        triggered = False
        value = 0.0
        if outbound_delta is not None and outbound_delta > outbound_threshold:
            triggered = True
            value = max(value, outbound_delta)
        if inbound_delta is not None and inbound_delta > inbound_threshold:
            triggered = True
            value = max(value, inbound_delta)
        evaluations.append((timestamp, triggered))
        if triggered:
            observed_values.append((timestamp, value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    observed = max((value for ts, value in observed_values if ts >= start_ts), default=None)
    detail = None
    if observed is not None:
        detail = f"chunk failures in 10m window: {observed:.0f}"
    return AlertComputation(starts_at=start_ts, value=observed, details=detail)


def _evaluate_finality_metric(
    store: MetricStore, metric: str, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        if value is None:
            continue
        triggered = value > threshold
        evaluations.append((timestamp, triggered))
        if triggered:
            observed.append((timestamp, value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=peak)


def _evaluate_restart_finality_correlation(
    store: MetricStore,
    lag_threshold: float,
    gap_threshold: float,
    restart_window: float,
    duration: float,
) -> Optional[AlertComputation]:
    restarts = store.series("process_start_time_seconds")
    lag_series = store.series("finality_lag_slots")
    gap_series = store.series("finalized_height_gap")

    if restarts is None or (lag_series is None and gap_series is None):
        return None

    restart_points: List[float] = []
    previous = None
    for sample in restarts.samples:
        if previous is not None and sample.value != previous.value:
            if restart_window <= 0 or sample.timestamp - previous.timestamp <= restart_window:
                restart_points.append(sample.timestamp)
        previous = sample

    if not restart_points:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in sorted(store.all_timestamps()):
        if timestamp < restart_points[0]:
            continue
        lag = lag_series.value_at(timestamp) if lag_series is not None else None
        gap = gap_series.value_at(timestamp) if gap_series is not None else None
        correlated = (lag is not None and lag > lag_threshold) or (
            gap is not None and gap > gap_threshold
        )
        evaluations.append((timestamp, correlated))
        if correlated:
            values = [value for value in (lag, gap) if value is not None]
            if values:
                observed.append((timestamp, max(values)))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    if not any(restart <= start_ts for restart in restart_points):
        return None

    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    detail = f"restart detected at {restart_points[0]:.0f}s"
    return AlertComputation(starts_at=start_ts, value=peak, details=detail)


def _evaluate_pruning_block_recovery(
    store: MetricStore,
    ratio_threshold: float,
    block_window: float,
    duration: float,
    pruning_window: float,
) -> Optional[AlertComputation]:
    cycles = store.series("rpp_node_pruning_cycle_total", {"result": "success"})
    expected_series = store.series("consensus_block_schedule_slots_total")
    produced_series = store.series("chain_block_height")

    if cycles is None or expected_series is None or produced_series is None:
        return None

    timestamps = sorted(store.all_timestamps())
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        window = min(pruning_window, timestamp)
        recent_cycles = cycles.delta_over_window(timestamp, window)
        if recent_cycles is None or recent_cycles <= 0.0:
            evaluations.append((timestamp, False))
            continue

        expected_delta = expected_series.delta_over_window(timestamp, block_window)
        produced_delta = produced_series.delta_over_window(timestamp, block_window)
        ratio = None
        if (
            expected_delta is not None
            and expected_delta > 0.0
            and produced_delta is not None
        ):
            ratio = produced_delta / expected_delta

        degraded = ratio is not None and ratio < ratio_threshold
        evaluations.append((timestamp, degraded))
        if degraded and ratio is not None:
            observed.append((timestamp, ratio))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    worst_ratio = min((ratio for ts, ratio in observed if ts >= start_ts), default=None)
    detail = None
    if worst_ratio is not None:
        detail = f"block production ratio={worst_ratio:.2f} after pruning"
    return AlertComputation(starts_at=start_ts, value=worst_ratio, details=detail)


def _evaluate_pruning_finality_recovery(
    store: MetricStore,
    lag_threshold: float,
    gap_threshold: float,
    duration: float,
    pruning_window: float,
) -> Optional[AlertComputation]:
    cycles = store.series("rpp_node_pruning_cycle_total", {"result": "success"})
    lag_series = store.series("finality_lag_slots")
    gap_series = store.series("finalized_height_gap")

    if cycles is None or (lag_series is None and gap_series is None):
        return None

    timestamps = sorted(store.all_timestamps())
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        window = min(pruning_window, timestamp)
        recent_cycles = cycles.delta_over_window(timestamp, window)
        if recent_cycles is None or recent_cycles <= 0.0:
            evaluations.append((timestamp, False))
            continue

        lag_value = lag_series.value_at(timestamp) if lag_series is not None else None
        gap_value = gap_series.value_at(timestamp) if gap_series is not None else None
        degraded = (lag_value is not None and lag_value > lag_threshold) or (
            gap_value is not None and gap_value > gap_threshold
        )
        evaluations.append((timestamp, degraded))
        if degraded:
            for value in (lag_value, gap_value):
                if value is not None:
                    observed.append((timestamp, value))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    detail = None
    if peak is not None:
        detail = f"finality backlog={peak:.0f} after pruning"
    return AlertComputation(starts_at=start_ts, value=peak, details=detail)


def _evaluate_metric_correlation(
    store: MetricStore,
    primary_metric: str,
    primary_threshold: float,
    secondary_metric: str,
    secondary_threshold: float,
    duration: float,
) -> Optional[AlertComputation]:
    primary = store.series(primary_metric)
    secondary = store.series(secondary_metric)

    if primary is None or secondary is None:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in sorted(store.all_timestamps()):
        primary_value = primary.value_at(timestamp)
        secondary_value = secondary.value_at(timestamp)
        correlated = (
            primary_value is not None
            and primary_value > primary_threshold
            and secondary_value is not None
            and secondary_value > secondary_threshold
        )
        evaluations.append((timestamp, correlated))
        if correlated:
            values = [value for value in (primary_value, secondary_value) if value is not None]
            if values:
                observed.append((timestamp, max(values)))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=peak)


def _evaluate_block_height_stall(
    store: MetricStore, metric: str, window: float, duration: float
) -> Optional[AlertComputation]:
    delta_series = store.series("consensus:block_height_delta:5m")
    if delta_series is not None:
        evaluations: List[Tuple[float, bool]] = []
        observed: List[Tuple[float, float]] = []
        for timestamp in store.all_timestamps():
            delta = delta_series.value_at(timestamp)
            stalled = delta is not None and delta <= 0.0
            evaluations.append((timestamp, stalled))
            if delta is not None:
                observed.append((timestamp, delta))
        fired, start_ts = _sustained(evaluations, duration)
        if not fired or start_ts is None:
            return None
        worst_delta = min((value for ts, value in observed if ts >= start_ts), default=None)
        detail = None
        if worst_delta is not None:
            detail = f"block production delta={worst_delta:.0f} over {window/60:.0f}m"
        return AlertComputation(starts_at=start_ts, value=worst_delta, details=detail)

    series = store.series(metric)
    if series is None:
        return None
    timestamps = [sample.timestamp for sample in series.samples]
    evaluations: List[Tuple[float, bool]] = []
    deltas: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        delta = series.delta_over_window(timestamp, window)
        stalled = delta is not None and delta <= 0.0
        evaluations.append((timestamp, stalled))
        if stalled and delta is not None:
            deltas.append((timestamp, delta))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    worst_delta = min((delta for ts, delta in deltas if ts >= start_ts), default=None)
    detail = None
    if worst_delta is not None:
        detail = f"block height stalled for {duration/60:.0f}m"
    return AlertComputation(starts_at=start_ts, value=worst_delta, details=detail)


def _evaluate_block_production_ratio(
    store: MetricStore, threshold: float, window: float, duration: float
) -> Optional[AlertComputation]:
    expected_series = store.series("consensus_block_schedule_slots_total")
    produced_series = store.series("chain_block_height")
    if expected_series is None or produced_series is None:
        return None

    timestamps = sorted(store.all_timestamps())
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        expected_delta = expected_series.delta_over_window(timestamp, window)
        produced_delta = produced_series.delta_over_window(timestamp, window)
        ratio = None
        if (
            expected_delta is not None
            and expected_delta > 0.0
            and produced_delta is not None
        ):
            ratio = produced_delta / expected_delta
        degraded = ratio is not None and ratio < threshold
        evaluations.append((timestamp, degraded))
        if ratio is not None:
            observed.append((timestamp, ratio))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    worst_ratio = min((ratio for ts, ratio in observed if ts >= start_ts), default=None)
    detail = None
    if worst_ratio is not None:
        detail = f"block production ratio={worst_ratio:.2f} over {window/60:.0f}m"
    return AlertComputation(starts_at=start_ts, value=worst_ratio, details=detail)


def _evaluate_rpc_availability(
    store: MetricStore, threshold: float, window: float, duration: float
) -> Optional[AlertComputation]:
    rpc_series = store.series_by_metric("rpp_runtime_rpc_request_total")
    success_series = [series for labels, series in rpc_series if labels.get("result") == "success"]
    other_results = [series for labels, series in rpc_series if labels.get("result") in {"client_error", "server_error"}]

    if not success_series:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        success_rate = 0.0
        success_observed = False
        for series in success_series:
            delta = series.delta_over_window(timestamp, window)
            if delta is None:
                continue
            success_observed = True
            success_rate += delta / window

        total_rate = success_rate
        for series in other_results:
            delta = series.delta_over_window(timestamp, window)
            if delta is None:
                continue
            total_rate += delta / window

        if total_rate <= 0.0 or not success_observed:
            evaluations.append((timestamp, False))
            continue

        ratio = success_rate / total_rate
        degraded = ratio < threshold
        evaluations.append((timestamp, degraded))
        observed.append((timestamp, ratio))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    lowest_ratio = min((ratio for ts, ratio in observed if ts >= start_ts), default=None)
    detail = None
    if lowest_ratio is not None:
        detail = f"success ratio={lowest_ratio:.3f}"
    return AlertComputation(starts_at=start_ts, value=lowest_ratio, details=detail)


def _evaluate_mempool_probe_readiness(
    store: MetricStore, metric: str, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        if value is None:
            evaluations.append((timestamp, False))
            continue
        degraded = value < threshold
        evaluations.append((timestamp, degraded))
        observed.append((timestamp, value))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    lowest = min((value for ts, value in observed if ts >= start_ts), default=None)
    detail = None
    if lowest is not None:
        detail = f"probe success ratio={lowest:.2f}"
    return AlertComputation(starts_at=start_ts, value=lowest, details=detail)


def _evaluate_pipeline_latency(
    store: MetricStore, metric: str, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        degraded = value is not None and value > threshold
        evaluations.append((timestamp, degraded))
        if value is not None:
            observed.append((timestamp, value))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    worst = max((value for ts, value in observed if ts >= start_ts), default=None)
    detail = None
    if worst is not None:
        detail = f"p95 latency={worst:.0f}s"
    return AlertComputation(starts_at=start_ts, value=worst, details=detail)


def _evaluate_rpc_subscription_health(
    store: MetricStore,
    phase: str,
    minimum_ratio: float,
    window: float,
    duration: float,
    max_disconnects: float,
) -> Optional[AlertComputation]:
    ratio_series = [
        series
        for labels, series in store.series_by_metric(
            "rpc_subscription_probe_success_ratio"
        )
        if labels.get("phase") == phase
    ]
    disconnect_series = [
        series
        for labels, series in store.series_by_metric(
            "rpc_subscription_probe_disconnects_total"
        )
        if labels.get("phase") == phase
    ]

    if not ratio_series and not disconnect_series:
        return None

    evaluations: List[Tuple[float, bool]] = []
    observed_ratios: List[Tuple[float, float]] = []
    observed_disconnects: List[Tuple[float, float]] = []
    for timestamp in sorted(store.all_timestamps()):
        degraded = False

        if ratio_series:
            ratios = [
                value
                for series in ratio_series
                if (value := series.value_at(timestamp)) is not None
            ]
            if ratios:
                ratio = min(ratios)
                observed_ratios.append((timestamp, ratio))
                degraded |= ratio < minimum_ratio

        if disconnect_series:
            worst_delta: Optional[float] = None
            for series in disconnect_series:
                delta = series.delta_over_window(timestamp, window)
                if delta is None:
                    continue
                worst_delta = max(worst_delta or delta, delta)
            if worst_delta is not None:
                observed_disconnects.append((timestamp, worst_delta))
                degraded |= worst_delta > max_disconnects

        evaluations.append((timestamp, degraded))

    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None

    detail_parts: List[str] = []
    worst_ratio = min((value for ts, value in observed_ratios if ts >= start_ts), default=None)
    if worst_ratio is not None:
        detail_parts.append(f"keep-alive ratio={worst_ratio:.2f}")
    worst_disconnect = max(
        (value for ts, value in observed_disconnects if ts >= start_ts),
        default=None,
    )
    if worst_disconnect is not None:
        detail_parts.append(f"disconnect delta={worst_disconnect:.0f}")

    detail = ", ".join(detail_parts) if detail_parts else None
    return AlertComputation(
        starts_at=start_ts,
        value=worst_ratio if worst_ratio is not None else worst_disconnect,
        details=detail,
    )


def _evaluate_epoch_delay(
    store: MetricStore, metric: str, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        if value is None:
            continue
        if _maintenance_active(store, "timetoke", timestamp):
            evaluations.append((timestamp, False))
            continue
        delayed = value > threshold
        evaluations.append((timestamp, delayed))
        if delayed:
            observed.append((timestamp, value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=peak)


def _evaluate_uptime_participation(
    store: MetricStore, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series("uptime_participation_ratio")
    if series is None:
        return None
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        if value is None:
            continue
        if _maintenance_active(store, "uptime", timestamp):
            evaluations.append((timestamp, False))
            continue
        degraded = value < threshold
        evaluations.append((timestamp, degraded))
        if degraded:
            observed.append((timestamp, value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    lowest = min((value for ts, value in observed if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=lowest)


def _evaluate_uptime_gap(
    store: MetricStore, metric: str, threshold: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None
    evaluations: List[Tuple[float, bool]] = []
    observed: List[Tuple[float, float]] = []
    for timestamp in store.all_timestamps():
        value = series.value_at(timestamp)
        if value is None:
            continue
        if _maintenance_active(store, "uptime", timestamp):
            evaluations.append((timestamp, False))
            continue
        breached = value > threshold
        evaluations.append((timestamp, breached))
        if breached:
            observed.append((timestamp, value))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    peak = max((value for ts, value in observed if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=peak)


def _evaluate_timetoke_rate(
    store: MetricStore, metric: str, window: float, minimum_rate: float, duration: float
) -> Optional[AlertComputation]:
    series = store.series(metric)
    if series is None:
        return None
    timestamps = [sample.timestamp for sample in series.samples]
    evaluations: List[Tuple[float, bool]] = []
    observed_rates: List[Tuple[float, float]] = []
    for timestamp in timestamps:
        rate = series.rate_over_window(timestamp, window)
        if _maintenance_active(store, "timetoke", timestamp):
            evaluations.append((timestamp, False))
            continue
        degraded = rate is not None and rate < minimum_rate
        if rate is not None:
            observed_rates.append((timestamp, rate))
        evaluations.append((timestamp, degraded))
    fired, start_ts = _sustained(evaluations, duration)
    if not fired or start_ts is None:
        return None
    worst = min((rate for ts, rate in observed_rates if ts >= start_ts), default=None)
    return AlertComputation(starts_at=start_ts, value=worst)


def default_alert_rules() -> List[AlertRule]:
    return [
        AlertRule(
            name="ConsensusVRFSlow",
            severity="warning",
            service="consensus",
            summary="VRF verification p95 latency exceeded 50 ms",
            description=(
                "VRF verification latency is above the documented 50 ms warning threshold for five "
                "consecutive minutes. Investigate validator CPU saturation, GPU misconfiguration, "
                "or unexpected workload spikes before the degradation impacts quorum formation."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/observability.md#consensus-vrf--quorum-alert-playbook",
            evaluator=_evaluate_consensus_vrf_slow,
        ),
        AlertRule(
            name="ConsensusVRFFailureBurst",
            severity="page",
            service="consensus",
            summary="Multiple VRF verification failures detected",
            description=(
                "More than two VRF verifications failed within the last five minutes. Review node logs "
                "for `invalid VRF proof` markers, confirm the validator key material, and execute the "
                "Simnet regression run to rule out regressions."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/observability.md#consensus-vrf--quorum-alert-playbook",
            evaluator=_evaluate_consensus_vrf_failure_burst,
        ),
        AlertRule(
            name="ConsensusQuorumVerificationFailure",
            severity="page",
            service="consensus",
            summary="Consensus quorum verification failed",
            description=(
                "A validator rejected a tampered or inconsistent consensus certificate. Capture the "
                "failure reason label, inspect node logs for rejection details, and follow the Phase-2 "
                "runbook before re-enabling block production."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/observability.md#consensus-vrf--quorum-alert-playbook",
            evaluator=_evaluate_consensus_quorum_failure,
        ),
        AlertRule(
            name="ConsensusFinalityLagWarning",
            severity="warning",
            service="consensus",
            summary="Finality lag exceeded 12 slots",
            description=(
                "The finalized tip trails the accepted head by more than twelve slots for at least five minutes."
                " Investigate proposer health and replay recent rounds to confirm quorum participation."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_finality_metric(
                store,
                "finality_lag_slots",
                FINALITY_SLA.lag_warning_slots,
                300.0,
            ),
        ),
        AlertRule(
            name="ConsensusFinalityLagCritical",
            severity="critical",
            service="consensus",
            summary="Finality lag exceeded 24 slots",
            description=(
                "Finality has stalled for at least twenty-four slots. Trigger the network snapshot failover procedure and"
                " verify witness signatures before resuming production."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_finality_metric(
                store,
                "finality_lag_slots",
                FINALITY_SLA.lag_critical_slots,
                120.0,
            ),
        ),
        AlertRule(
            name="ConsensusFinalizedHeightGapWarning",
            severity="warning",
            service="consensus",
            summary="Finalized height gap above warning budget",
            description=(
                "The finalized height trails the accepted head by more than four blocks for five minutes. Correlate with"
                " finality lag and prepare failover steps if the gap grows."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_finality_metric(
                store,
                "finalized_height_gap",
                FINALITY_SLA.gap_warning_blocks,
                300.0,
            ),
        ),
        AlertRule(
            name="ConsensusFinalizedHeightGapCritical",
            severity="critical",
            service="consensus",
            summary="Finalized height gap beyond critical budget",
            description=(
                "Finalization is lagging the accepted tip by more than eight blocks for at least two minutes. Page the on-call"
                " and execute the documented failover to restore proposer rotation."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_finality_metric(
                store,
                "finalized_height_gap",
                FINALITY_SLA.gap_critical_blocks,
                120.0,
            ),
        ),
        AlertRule(
            name="ConsensusRestartFinalityCorrelation",
            severity="warning",
            service="consensus",
            summary="Node restart correlated with finality regression",
            description=(
                "A node restart coincided with widening finality lag or finalized height gap. Inspect restart logs, peer "
                "counts, and pipeline health until the gap closes."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_restart_finality_correlation(
                store,
                lag_threshold=FINALITY_SLA.lag_warning_slots,
                gap_threshold=FINALITY_SLA.gap_warning_blocks,
                restart_window=900.0,
                duration=300.0,
            ),
        ),
        AlertRule(
            name="PruningRecoveryBlockRate",
            severity="warning",
            service="storage",
            summary="Block production lagged after pruning completion",
            description=(
                "Block production stayed below the documented slot coverage budget after a recent pruning run."
                " Inspect pacing decisions, mempool pressure, and recent pruning logs before resuming traffic."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/runbooks/pruning_operations.md#post-pruning-recovery",
            evaluator=lambda store: _evaluate_pruning_block_recovery(
                store,
                BLOCK_PRODUCTION_SLA.warning_ratio,
                BLOCK_PRODUCTION_SLA.window_seconds,
                300.0,
                900.0,
            ),
        ),
        AlertRule(
            name="PruningRecoveryFinality",
            severity="warning",
            service="storage",
            summary="Finality lag persisted after pruning completion",
            description=(
                "Finality lag or finalized height gaps remained above the warning budget after pruning completed."
                " Validate snapshot health, peer catch-up, and proposer rotation before scheduling new pruning windows."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/runbooks/pruning_operations.md#post-pruning-recovery",
            evaluator=lambda store: _evaluate_pruning_finality_recovery(
                store,
                FINALITY_SLA.lag_warning_slots,
                FINALITY_SLA.gap_warning_blocks,
                180.0,
                900.0,
            ),
        ),
        AlertRule(
            name="FinalityProverBacklogCorrelation",
            severity="warning",
            service="uptime",
            summary="Finality lag correlated with prover backlog",
            description=(
                "Finality lag stayed above the warning budget while prover queue depth remained elevated. Drain the prover "
                "backlog or expand capacity before the next deployment window."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#prover-backlog-correlation",
            evaluator=lambda store: _evaluate_metric_correlation(
                store,
                "finality_lag_slots",
                FINALITY_SLA.lag_warning_slots,
                "wallet:prover_queue_depth:max:10m",
                PROVER_QUEUE_WARNING_DEPTH,
                PROVER_QUEUE_CORRELATION_DURATION,
            ),
        ),
        AlertRule(
            name="UptimeProverLatencyCorrelation",
            severity="warning",
            service="uptime",
            summary="Uptime proofs delayed while prover latency elevated",
            description=(
                "Uptime observation age breached the warning buffer while prover p95 latency stayed above three minutes. "
                "Expect timetoke accrual to stall until prover capacity recovers."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#prover-backlog-correlation",
            evaluator=lambda store: _evaluate_metric_correlation(
                store,
                "uptime_observation_age_seconds",
                UPTIME_THRESHOLDS.observation_warning_seconds,
                "wallet:prover_job_latency:p95_seconds:10m",
                PROVER_LATENCY_WARNING_SECONDS,
                PROVER_LATENCY_CORRELATION_DURATION,
            ),
        ),
        AlertRule(
            name="ConsensusLivenessStall",
            severity="critical",
            service="consensus",
            summary="Consensus liveness stalled for 10 minutes",
            description=(
                "Accepted block height failed to advance for at least ten minutes. Validate proposer health, check peer"
                " counts, and follow the uptime soak runbook to restore block flow."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#consensus-liveness-and-rpc-availability",
            evaluator=lambda store: _evaluate_block_height_stall(
                store, "chain_block_height", FINALITY_SLA.stall_duration_seconds, FINALITY_SLA.stall_duration_seconds
            ),
        ),
        AlertRule(
            name="ConsensusBlockProductionLagWarning",
            severity="warning",
            service="consensus",
            summary="Block production rate below 90% of schedule",
            description=(
                "Block production is lagging the scheduled slot rate by more than ten percent for at least ten minutes."
                " Inspect proposer rotation, VRF submissions, and peer connectivity before the gap widens."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#block-production-rate-and-slot-budget",
            evaluator=lambda store: _evaluate_block_production_ratio(
                store,
                threshold=BLOCK_PRODUCTION_SLA.warning_ratio,
                window=BLOCK_PRODUCTION_SLA.window_seconds,
                duration=BLOCK_PRODUCTION_SLA.duration_seconds,
            ),
        ),
        AlertRule(
            name="ConsensusBlockProductionLagCritical",
            severity="critical",
            service="consensus",
            summary="Block production rate below 75% of schedule",
            description=(
                "Block production is below seventy-five percent of the scheduled slot rate for at least ten minutes."
                " Page the on-call and run the consensus liveness remediation until the rate returns to budget."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#block-production-rate-and-slot-budget",
            evaluator=lambda store: _evaluate_block_production_ratio(
                store,
                threshold=BLOCK_PRODUCTION_SLA.critical_ratio,
                window=BLOCK_PRODUCTION_SLA.window_seconds,
                duration=BLOCK_PRODUCTION_SLA.duration_seconds,
            ),
        ),
        AlertRule(
            name="ConsensusMissedSlotsWarning",
            severity="warning",
            service="consensus",
            summary="Proposers are missing scheduled slots",
            description=(
                "Scheduled slots exceeded produced blocks by more than two slots for at least ten minutes. "
                "Inspect per-slot prover latency and timetoke replay health before the deficit widens."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#missed-slots-under-prover-load",
            evaluator=lambda store: _evaluate_epoch_delay(
                store, "consensus:missed_slots:5m", 2.0, 600.0
            ),
        ),
        AlertRule(
            name="ConsensusMissedSlotsCritical",
            severity="critical",
            service="consensus",
            summary="Slot misses threaten finality",
            description=(
                "Scheduled slots exceeded produced blocks by more than four slots for five minutes. Quarantine slow leaders "
                "and drain prover queues until slot coverage recovers."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#missed-slots-under-prover-load",
            evaluator=lambda store: _evaluate_epoch_delay(
                store, "consensus:missed_slots:5m", 4.0, 300.0
            ),
        ),
        AlertRule(
            name="RpcAvailabilityDegradedWarning",
            severity="warning",
            service="rpc",
            summary="RPC availability dropped below 99%",
            description=(
                "RPC responses fell below the 99% success target for at least five minutes. Inspect ingress, recent"
                " deploys, and node health before the outage widens."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#consensus-liveness-and-rpc-availability",
            evaluator=lambda store: _evaluate_rpc_availability(
                store, threshold=0.99, window=300.0, duration=300.0
            ),
        ),
        AlertRule(
            name="RpcAvailabilityDegradedCritical",
            severity="critical",
            service="rpc",
            summary="RPC availability below 95% for 10 minutes",
            description=(
                "RPC endpoints failed more than 5% of requests for ten minutes. Page the on-call, validate node readiness,"
                " and consider draining traffic while recovering the API layer."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#consensus-liveness-and-rpc-availability",
            evaluator=lambda store: _evaluate_rpc_availability(
                store, threshold=0.95, window=300.0, duration=600.0
            ),
        ),
        AlertRule(
            name="RpcSubscriptionDisconnectLoad",
            severity="warning",
            service="rpc",
            summary="RPC subscriptions dropped during consensus load",
            description=(
                "Subscription probes lost keep-alives or disconnected while the consensus load generator ran. Inspect"
                " gateway timeouts, node RPC logs, and /wallet/pipeline/stream connectivity before resuming traffic."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#rpc-subscription-probes",
            evaluator=lambda store: _evaluate_rpc_subscription_health(
                store,
                phase="consensus_load",
                minimum_ratio=0.98,
                window=600.0,
                duration=600.0,
                max_disconnects=0.0,
            ),
        ),
        AlertRule(
            name="RpcSubscriptionDisconnectMaintenance",
            severity="warning",
            service="rpc",
            summary="RPC subscriptions dropped during maintenance",
            description=(
                "Maintenance-mode subscription probes still see disconnects or missing keep-alives. Confirm drains and"
                " restart ordering so long-running SSE/WebSocket streams survive maintenance windows."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#rpc-subscription-probes",
            evaluator=lambda store: _evaluate_rpc_subscription_health(
                store,
                phase="maintenance",
                minimum_ratio=0.90,
                window=900.0,
                duration=900.0,
                max_disconnects=1.0,
            ),
        ),
        AlertRule(
            name="UptimeMempoolProbeFailure",
            severity="warning",
            service="uptime",
            summary="Uptime probe could not reach the mempool",
            description=(
                "Lightweight uptime probes failed to submit or observe transactions for ten minutes while "
                "consensus was disrupted. Expect downstream traffic to stall until mempool readiness recovers; "
                "drain or restart stuck validators before reopening submissions."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#mempool-ready-probes",
            evaluator=lambda store: _evaluate_mempool_probe_readiness(
                store,
                "uptime_mempool_probe_success_ratio",
                MEMPOOL_PROBE_MIN_RATIO,
                MEMPOOL_PROBE_FAILURE_DURATION,
            ),
        ),
        AlertRule(
            name="TransactionInclusionLatencyWarning",
            severity="warning",
            service="uptime",
            summary="Synthetic inclusion probes exceeded the one-minute budget",
            description=(
                "Synthetic transaction probes are taking longer than the documented inclusion SLO. Inspect RPC ingress, "
                "mempool backlog, or proposer churn before queues build up during partial outages."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#transaction-latency-probes",
            evaluator=lambda store: _evaluate_pipeline_latency(
                store,
                "pipeline:time_to_inclusion_seconds:p95",
                PIPELINE_LATENCY_SLA.inclusion_warning_seconds,
                PIPELINE_LATENCY_DURATION,
            ),
        ),
        AlertRule(
            name="TransactionInclusionLatencyCritical",
            severity="critical",
            service="uptime",
            summary="Synthetic inclusion probes exceeded the two-minute budget",
            description=(
                "Synthetic transaction probes remain above the two-minute inclusion threshold. Drain traffic to healthy nodes "
                "or restart stuck validators before user submissions time out."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#transaction-latency-probes",
            evaluator=lambda store: _evaluate_pipeline_latency(
                store,
                "pipeline:time_to_inclusion_seconds:p95",
                PIPELINE_LATENCY_SLA.inclusion_critical_seconds,
                PIPELINE_LATENCY_DURATION,
            ),
        ),
        AlertRule(
            name="TransactionFinalityLatencyWarning",
            severity="warning",
            service="uptime",
            summary="Synthetic finality probes exceeded the three-minute budget",
            description=(
                "Synthetic transaction probes are taking longer than expected to finalize. Inspect prover queues, block "
                "production, and RPC availability before finality lag widens."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#transaction-latency-probes",
            evaluator=lambda store: _evaluate_pipeline_latency(
                store,
                "pipeline:time_to_finality_seconds:p95",
                PIPELINE_LATENCY_SLA.finality_warning_seconds,
                PIPELINE_LATENCY_DURATION,
            ),
        ),
        AlertRule(
            name="TransactionFinalityLatencyCritical",
            severity="critical",
            service="uptime",
            summary="Synthetic finality probes exceeded the five-minute budget",
            description=(
                "Synthetic transaction probes remain above the five-minute finality SLO. Escalate to uptime/finality "
                "runbooks, drain traffic, and clear prover bottlenecks before clients accumulate retries."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#transaction-latency-probes",
            evaluator=lambda store: _evaluate_pipeline_latency(
                store,
                "pipeline:time_to_finality_seconds:p95",
                PIPELINE_LATENCY_SLA.finality_critical_seconds,
                PIPELINE_LATENCY_DURATION,
            ),
        ),
        AlertRule(
            name="TimetokeEpochDelayWarning",
            severity="warning",
            service="reputation",
            summary="Timetoke epoch rollover delayed",
            description=(
                "Timetoke epochs have not rolled over within the expected window. Validators may not accrue uptime credit; "
                "inspect timetoke schedulers and recent proposer elections before the delay widens."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_epoch_delay(
                store,
                "timetoke_epoch_age_seconds",
                UPTIME_THRESHOLDS.epoch_warning_seconds,
                600.0,
            ),
        ),
        AlertRule(
            name="TimetokeEpochDelayCritical",
            severity="critical",
            service="reputation",
            summary="Timetoke epoch rollover critically delayed",
            description=(
                "Timetoke epochs have stalled for more than ninety minutes. Pause proposer changes and recover the timetoke "
                "scheduler before resuming normal block production."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_epoch_delay(
                store,
                "timetoke_epoch_age_seconds",
                UPTIME_THRESHOLDS.epoch_critical_seconds,
                600.0,
            ),
        ),
        AlertRule(
            name="UptimeParticipationDropWarning",
            severity="warning",
            service="uptime",
            summary="Uptime participation dipped below the warning ratio",
            description=(
                "Active validator participation fell beneath the 97% SLA target for at least ten minutes. "
                "Correlate with recent node joins/removals and confirm new validators are producing uptime proofs."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_uptime_participation(
                store, UPTIME_THRESHOLDS.participation_warning, 600.0
            ),
        ),
        AlertRule(
            name="UptimeParticipationDropCritical",
            severity="critical",
            service="uptime",
            summary="Uptime participation breached the critical ratio",
            description=(
                "Validator participation in uptime proofs fell below the 94% critical ceiling. Investigate churn, peer counts, "
                "and scheduler health to restore coverage before timetoke accrual stalls."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_uptime_participation(
                store, UPTIME_THRESHOLDS.participation_critical, 600.0
            ),
        ),
        AlertRule(
            name="UptimeObservationGapWarning",
            severity="warning",
            service="uptime",
            summary="Uptime proofs missing beyond the warning gap",
            description=(
                "The latest uptime proof age exceeded the 15 minute SLA window. Verify schedulers are running after node joins "
                "and that gossiped observations reach the reputation manager."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_uptime_gap(
                store,
                "uptime_observation_age_seconds",
                UPTIME_THRESHOLDS.observation_warning_seconds,
                600.0,
            ),
        ),
        AlertRule(
            name="UptimeObservationGapCritical",
            severity="critical",
            service="uptime",
            summary="Uptime proofs missing beyond the critical gap",
            description=(
                "No uptime proofs landed for thirty minutes. Page the on-call to restart schedulers, reseed peers, or remove "
                "faulty validators before timetoke balances decay."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_uptime_gap(
                store,
                "uptime_observation_age_seconds",
                UPTIME_THRESHOLDS.observation_critical_seconds,
                600.0,
            ),
        ),
        AlertRule(
            name="TimetokeAccrualStallWarning",
            severity="warning",
            service="reputation",
            summary="Timetoke accrual slowed below the warning rate",
            description=(
                "Timetoke credit accrual dipped under the documented rate after validator churn. Inspect the uptime scheduler, "
                "timetoke sync, and recent node removals before balances decay."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_timetoke_rate(
                store,
                "timetoke_accrual_hours_total",
                UPTIME_SLA.timetoke_window_seconds,
                UPTIME_THRESHOLDS.timetoke_rate_per_second,
                900.0,
            ),
        ),
        AlertRule(
            name="TimetokeAccrualStallCritical",
            severity="critical",
            service="reputation",
            summary="Timetoke accrual stalled after validator churn",
            description=(
                "Timetoke credits stopped increasing for more than thirty minutes. Pause additional removals, restart uptime "
                "pipelines, and replay missing proofs before the decay cycle slashes healthy operators."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_timetoke_rate(
                store,
                "timetoke_accrual_hours_total",
                UPTIME_SLA.timetoke_window_seconds,
                UPTIME_THRESHOLDS.timetoke_rate_per_second,
                1800.0,
            ),
        ),
        AlertRule(
            name="SnapshotStreamLagWarning",
            severity="warning",
            service="snapshots",
            summary="Snapshot stream lag exceeded 30 seconds",
            description=(
                "The snapshot stream lag has been above the 30 second warning threshold for five "
                "minutes. Inspect producer bandwidth, consumer back-pressure, and gossip health to "
                "keep snapshot replay within the target SLO."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_lag(store, threshold=30.0, duration=300.0),
        ),
        AlertRule(
            name="SnapshotStreamLagCritical",
            severity="critical",
            service="snapshots",
            summary="Snapshot stream lag exceeded 120 seconds",
            description=(
                "Snapshot lag has breached the 120 second critical threshold. Escalate to the on-call "
                "snapshot engineer and execute the failover playbook to restore healthy consumers."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_lag(store, threshold=120.0, duration=120.0),
        ),
        AlertRule(
            name="SnapshotStreamZeroThroughputWarning",
            severity="warning",
            service="snapshots",
            summary="Snapshot chunk throughput dropped to zero",
            description=(
                "Snapshot chunk throughput has been effectively zero for ten minutes despite recent "
                "activity. Verify active sessions via the /p2p/snapshots RPC and confirm outbound "
                "bandwidth limits."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_zero_throughput(store, rate_window=300.0, duration=600.0),
        ),
        AlertRule(
            name="SnapshotStreamZeroThroughputCritical",
            severity="critical",
            service="snapshots",
            summary="Snapshot chunk throughput stalled for 20 minutes",
            description=(
                "Snapshot chunk throughput has remained at zero for twenty minutes while sessions were "
                "recently active. Page the snapshot on-call and follow the failover runbook to restart "
                "producers or redirect consumers."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_zero_throughput(store, rate_window=900.0, duration=1200.0),
        ),
        AlertRule(
            name="SnapshotChunkFailureSpikeWarning",
            severity="warning",
            service="snapshots",
            summary="Snapshot chunk failures exceeded warning threshold",
            description=(
                "Snapshot chunk retries or decode failures crossed the warning threshold. Inspect peer "
                "logs for repeated `chunk transfer failed` entries and rebalance consumers if needed."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_chunk_failures(store, 3.0, 1.0, 0.0),
        ),
        AlertRule(
            name="SnapshotChunkFailureSpikeCritical",
            severity="critical",
            service="snapshots",
            summary="Snapshot chunk failures exceeded critical threshold",
            description=(
                "Snapshot chunk failure volume is spiking and breaching the critical ceiling. Escalate "
                "to the on-call to investigate peer health, storage backing services, or snapshot "
                "corruption before validators fall behind."
            ),
            runbook_url="https://github.com/chainbound/chain/blob/main/docs/runbooks/network_snapshot_failover.md",
            evaluator=lambda store: _evaluate_snapshot_chunk_failures(store, 6.0, 3.0, 300.0),
        ),
    ]


def _build_samples(pairs: Sequence[Tuple[float, float]]) -> List[Sample]:
    return [Sample(timestamp=ts, value=value) for ts, value in pairs]


def _build_counter_from_increments(
    metric: str, labels: Dict[str, str], increments: Sequence[float]
) -> MetricDefinition:
    samples: List[Tuple[float, float]] = []
    total = 0.0
    for minute, increment in enumerate(increments):
        total += increment
        samples.append((minute * 60.0, total))
    return MetricDefinition(metric=metric, labels=labels, samples=_build_samples(samples))


def _build_vrf_bucket_definitions(increment_per_minute: Dict[str, float], minutes: int) -> List[MetricDefinition]:
    definitions: List[MetricDefinition] = []
    for bound, increment in increment_per_minute.items():
        samples = []
        for minute in range(minutes + 1):
            timestamp = minute * 60.0
            samples.append(Sample(timestamp=timestamp, value=increment * minute))
        definitions.append(
            MetricDefinition(
                metric="consensus_vrf_verification_time_ms_bucket",
                labels={"result": "success", "le": bound},
                samples=samples,
            )
        )
    return definitions


def build_consensus_anomaly_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.extend(
        _build_vrf_bucket_definitions(
            {
                "10": 40.0,
                "20": 80.0,
                "50": 180.0,
                "100": 198.0,
                "+Inf": 200.0,
            },
            minutes=10,
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus_vrf_verification_time_ms_count",
            labels={"result": "failure"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (60.0, 0.0),
                    (120.0, 1.0),
                    (180.0, 2.0),
                    (240.0, 3.0),
                    (300.0, 4.0),
                    (360.0, 5.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus_quorum_verifications_total",
            labels={"result": "failure"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (60.0, 0.0),
                    (120.0, 0.0),
                    (180.0, 1.0),
                    (240.0, 1.0),
                    (300.0, 1.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_consensus_baseline_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.extend(
        _build_vrf_bucket_definitions(
            {
                "10": 160.0,
                "20": 190.0,
                "50": 200.0,
                "100": 200.0,
                "+Inf": 200.0,
            },
            minutes=10,
        )
    )
    zero_series = _build_samples(
        [
            (0.0, 0.0),
            (60.0, 0.0),
            (120.0, 0.0),
            (180.0, 0.0),
            (240.0, 0.0),
            (300.0, 0.0),
            (360.0, 0.0),
        ]
    )
    definitions.append(
        MetricDefinition(
            metric="consensus_vrf_verification_time_ms_count",
            labels={"result": "failure"},
            samples=zero_series,
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus_quorum_verifications_total",
            labels={"result": "failure"},
            samples=zero_series,
        )
    )
    return MetricStore.from_definitions(definitions)


def build_snapshot_anomaly_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="snapshot_stream_lag_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10.0),
                    (60.0, 15.0),
                    (120.0, 20.0),
                    (180.0, 25.0),
                    (240.0, 30.0),
                    (300.0, 80.0),
                    (360.0, 90.0),
                    (420.0, 130.0),
                    (480.0, 140.0),
                    (540.0, 150.0),
                    (600.0, 160.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="snapshot_bytes_sent_total",
            labels={"kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 1000.0),
                    (300.0, 1100.0),
                    (600.0, 1200.0),
                    (900.0, 1400.0),
                    (1200.0, 1600.0),
                    (1500.0, 1601.0),
                    (1800.0, 1602.0),
                    (2100.0, 1602.0),
                    (2400.0, 1602.0),
                    (2700.0, 1602.0),
                    (3000.0, 1602.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="light_client_chunk_failures_total",
            labels={"direction": "outbound", "kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (300.0, 1.0),
                    (600.0, 2.0),
                    (900.0, 3.0),
                    (1200.0, 4.0),
                    (1500.0, 6.0),
                    (1800.0, 8.0),
                    (2100.0, 10.0),
                    (2400.0, 13.0),
                    (2700.0, 17.0),
                    (3000.0, 21.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="light_client_chunk_failures_total",
            labels={"direction": "inbound", "kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (300.0, 0.0),
                    (600.0, 1.0),
                    (900.0, 1.0),
                    (1200.0, 1.0),
                    (1500.0, 2.0),
                    (1800.0, 3.0),
                    (2100.0, 4.0),
                    (2400.0, 4.0),
                    (2700.0, 5.0),
                    (3000.0, 6.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_disk_pressure_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 6.0),
                    (300.0, 10.0),
                    (600.0, 14.0),
                    (900.0, 26.0),
                    (1200.0, 30.0),
                    (1500.0, 29.0),
                    (1800.0, 18.0),
                    (2100.0, 12.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (300.0, 2.0),
                    (600.0, 5.0),
                    (900.0, 9.0),
                    (1200.0, 10.5),
                    (1500.0, 10.0),
                    (1800.0, 6.0),
                    (2100.0, 3.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1_000.0),
                    (300.0, 1_010.0),
                    (600.0, 1_020.0),
                    (900.0, 1_025.0),
                    (1200.0, 1_025.0),
                    (1500.0, 1_025.0),
                    (1800.0, 1_025.0),
                    (2100.0, 1_025.0),
                    (2400.0, 1_040.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 400.0),
                    (600.0, 1_100.0),
                    (1200.0, 1_900.0),
                    (1800.0, 2_000.0),
                    (2400.0, 500.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_mempool_probe_success_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (600.0, 0.45),
                    (1200.0, 0.2),
                    (1800.0, 0.2),
                    (2400.0, 0.95),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="snapshot_stream_lag_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 5.0),
                    (300.0, 40.0),
                    (600.0, 140.0),
                    (900.0, 160.0),
                    (1200.0, 15.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_disk_pressure_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10.0),
                    (300.0, 8.0),
                    (600.0, 6.0),
                    (900.0, 4.0),
                    (1200.0, 3.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 3.0),
                    (300.0, 2.0),
                    (600.0, 1.5),
                    (900.0, 1.0),
                    (1200.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1_040.0),
                    (300.0, 1_060.0),
                    (600.0, 1_080.0),
                    (900.0, 1_100.0),
                    (1200.0, 1_125.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 500.0),
                    (600.0, 600.0),
                    (1200.0, 450.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_mempool_probe_success_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.9),
                    (600.0, 1.0),
                    (1200.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="snapshot_stream_lag_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 20.0),
                    (300.0, 18.0),
                    (600.0, 12.0),
                    (900.0, 8.0),
                    (1200.0, 5.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_snapshot_baseline_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="snapshot_stream_lag_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 5.0),
                    (60.0, 7.0),
                    (120.0, 10.0),
                    (180.0, 12.0),
                    (240.0, 15.0),
                    (300.0, 18.0),
                    (360.0, 20.0),
                    (420.0, 22.0),
                    (480.0, 24.0),
                    (540.0, 25.0),
                    (600.0, 26.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="snapshot_bytes_sent_total",
            labels={"kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 1000.0),
                    (300.0, 1360.0),
                    (600.0, 1720.0),
                    (900.0, 2080.0),
                    (1200.0, 2440.0),
                    (1500.0, 2800.0),
                    (1800.0, 3160.0),
                    (2100.0, 3520.0),
                    (2400.0, 3880.0),
                    (2700.0, 4240.0),
                    (3000.0, 4600.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="light_client_chunk_failures_total",
            labels={"direction": "outbound", "kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (300.0, 0.0),
                    (600.0, 0.0),
                    (900.0, 1.0),
                    (1200.0, 1.0),
                    (1500.0, 1.0),
                    (1800.0, 1.0),
                    (2100.0, 2.0),
                    (2400.0, 2.0),
                    (2700.0, 2.0),
                    (3000.0, 3.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="light_client_chunk_failures_total",
            labels={"direction": "inbound", "kind": "chunk"},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (300.0, 0.0),
                    (600.0, 0.0),
                    (900.0, 0.0),
                    (1200.0, 0.0),
                    (1500.0, 0.0),
                    (1800.0, 0.0),
                    (2100.0, 0.0),
                    (2400.0, 0.0),
                    (2700.0, 0.0),
                    (3000.0, 1.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_baseline_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="uptime_participation_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, UPTIME_BASELINES.participation_ratio),
                    (600.0, UPTIME_BASELINES.participation_ratio - 0.001),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, UPTIME_BASELINES.observation_gap_seconds),
                    (600.0, UPTIME_BASELINES.observation_gap_seconds + 60.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_accrual_hours_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 20.0),
                    (
                        UPTIME_SLA.timetoke_window_seconds,
                        20.0
                        + UPTIME_THRESHOLDS.timetoke_rate_per_second
                        * UPTIME_SLA.timetoke_window_seconds,
                    ),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_epoch_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, UPTIME_BASELINES.epoch_age_seconds),
                    (
                        600.0,
                        min(
                            UPTIME_BASELINES.epoch_age_seconds
                            + UPTIME_BASELINES.epoch_warning_buffer / 2,
                            UPTIME_THRESHOLDS.epoch_warning_seconds,
                        ),
                    ),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_pause_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 4.0),
                    (300.0, 6.0),
                    (600.0, 10.0),
                    (900.0, 12.0),
                    (1200.0, 15.0),
                    (1500.0, 22.0),
                    (1800.0, 26.0),
                    (2100.0, 27.0),
                    (2400.0, 12.0),
                    (2700.0, 8.0),
                    (3000.0, 5.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (300.0, 2.0),
                    (600.0, 3.0),
                    (900.0, 4.5),
                    (1200.0, 6.0),
                    (1500.0, 9.0),
                    (1800.0, 9.5),
                    (2100.0, 9.0),
                    (2400.0, 4.0),
                    (2700.0, 2.0),
                    (3000.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 100.0),
                    (300.0, 110.0),
                    (600.0, 120.0),
                    (900.0, 130.0),
                    (1200.0, 140.0),
                    (1500.0, 140.0),
                    (1800.0, 140.0),
                    (2100.0, 140.0),
                    (2400.0, 140.0),
                    (2700.0, 150.0),
                    (3000.0, 160.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_mempool_probe_success_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (300.0, 1.0),
                    (600.0, 1.0),
                    (900.0, 0.8),
                    (1200.0, 0.4),
                    (1500.0, 0.0),
                    (1800.0, 0.0),
                    (2100.0, 0.3),
                    (2400.0, 0.7),
                    (2700.0, 0.95),
                    (3000.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus:missed_slots:5m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (120.0, 5.0),
                    (240.0, 5.0),
                    (360.0, 5.0),
                    (480.0, 5.0),
                    (600.0, 5.0),
                    (720.0, 5.0),
                    (840.0, 5.0),
                    (960.0, 4.5),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus:missed_slots:5m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (120.0, 5.0),
                    (240.0, 5.0),
                    (360.0, 5.0),
                    (480.0, 5.0),
                    (600.0, 5.0),
                    (720.0, 5.0),
                    (840.0, 5.0),
                    (960.0, 4.5),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 6.0),
                    (300.0, 5.0),
                    (600.0, 4.0),
                    (900.0, 3.0),
                    (1200.0, 2.5),
                    (1500.0, 2.0),
                    (1800.0, 2.0),
                    (2100.0, 1.5),
                    (2400.0, 1.0),
                    (2700.0, 1.0),
                    (3000.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_mempool_probe_success_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (300.0, 1.0),
                    (600.0, 1.0),
                    (900.0, 1.0),
                    (1200.0, 1.0),
                    (1500.0, 1.0),
                    (1800.0, 1.0),
                    (2100.0, 1.0),
                    (2400.0, 1.0),
                    (2700.0, 1.0),
                    (3000.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2.0),
                    (300.0, 2.0),
                    (600.0, 1.5),
                    (900.0, 1.5),
                    (1200.0, 1.0),
                    (1500.0, 1.0),
                    (1800.0, 1.0),
                    (2100.0, 0.5),
                    (2400.0, 0.5),
                    (2700.0, 0.5),
                    (3000.0, 0.5),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 200.0),
                    (300.0, 215.0),
                    (600.0, 230.0),
                    (900.0, 245.0),
                    (1200.0, 260.0),
                    (1500.0, 275.0),
                    (1800.0, 290.0),
                    (2100.0, 305.0),
                    (2400.0, 320.0),
                    (2700.0, 335.0),
                    (3000.0, 350.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_transaction_latency_outage_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="pipeline:time_to_inclusion_seconds:p95",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 45.0),
                    (300.0, 55.0),
                    (600.0, 80.0),
                    (900.0, 140.0),
                    (1200.0, 150.0),
                    (1500.0, 130.0),
                    (1800.0, 90.0),
                    (2100.0, 55.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="pipeline:time_to_finality_seconds:p95",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 120.0),
                    (300.0, 160.0),
                    (600.0, 190.0),
                    (900.0, 320.0),
                    (1200.0, 340.0),
                    (1500.0, 310.0),
                    (1800.0, 220.0),
                    (2100.0, 150.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_join_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="uptime_participation_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.985),
                    (300.0, 0.99),
                    (600.0, 0.992),
                    (900.0, 0.993),
                    (1200.0, 0.992),
                    (1500.0, 0.991),
                    (1800.0, 0.993),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 120.0),
                    (300.0, 180.0),
                    (600.0, 240.0),
                    (900.0, 180.0),
                    (1200.0, 150.0),
                    (1500.0, 210.0),
                    (1800.0, 240.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_accrual_hours_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10.0),
                    (300.0, 10.3),
                    (600.0, 10.6),
                    (900.0, 10.95),
                    (1200.0, 11.3),
                    (1500.0, 11.6),
                    (1800.0, 11.95),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_departure_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="uptime_participation_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.99),
                    (300.0, 0.965),
                    (600.0, 0.94),
                    (900.0, 0.925),
                    (1200.0, 0.92),
                    (1500.0, 0.918),
                    (1800.0, 0.915),
                    (2100.0, 0.9),
                    (2400.0, 0.9),
                    (2700.0, 0.9),
                    (3000.0, 0.9),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 420.0),
                    (300.0, 780.0),
                    (600.0, 1200.0),
                    (900.0, 1680.0),
                    (1200.0, 1920.0),
                    (1500.0, 2100.0),
                    (1800.0, 2100.0),
                    (2100.0, 2160.0),
                    (2400.0, 2220.0),
                    (2700.0, 2400.0),
                    (3000.0, 2520.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_accrual_hours_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 8.0),
                    (300.0, 8.1),
                    (600.0, 8.2),
                    (900.0, 8.25),
                    (1200.0, 8.27),
                    (1500.0, 8.27),
                    (1800.0, 8.27),
                    (2100.0, 8.27),
                    (2400.0, 8.27),
                    (2700.0, 8.27),
                    (3000.0, 8.27),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_maintenance_suppression_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="uptime_participation_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.93),
                    (600.0, 0.92),
                    (1200.0, 0.99),
                    (1800.0, 0.992),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2100.0),
                    (600.0, 2400.0),
                    (1200.0, 420.0),
                    (1800.0, 240.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_epoch_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 5000.0),
                    (600.0, 5200.0),
                    (1200.0, 1200.0),
                    (1800.0, 900.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_accrual_hours_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10.0),
                    (600.0, 10.05),
                    (1200.0, 10.5),
                    (1800.0, 10.9),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="maintenance:window_active",
            labels={"scope": "uptime"},
            samples=_build_samples([(0.0, 1.0), (1200.0, 0.0)]),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="maintenance:window_active",
            labels={"scope": "timetoke"},
            samples=_build_samples([(0.0, 1.0), (1200.0, 0.0)]),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_uptime_maintenance_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="uptime_participation_ratio",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.99),
                    (600.0, 0.95),
                    (1200.0, 0.93),
                    (1800.0, 0.92),
                    (2400.0, 0.92),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 420.0),
                    (600.0, 900.0),
                    (1200.0, 1800.0),
                    (1800.0, 2100.0),
                    (2400.0, 2160.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_epoch_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2400.0),
                    (600.0, 2700.0),
                    (1200.0, 3900.0),
                    (1800.0, 4800.0),
                    (2400.0, 5100.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="timetoke_accrual_hours_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10.0),
                    (600.0, 10.05),
                    (1200.0, 10.05),
                    (1800.0, 10.1),
                    (2400.0, 10.12),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="maintenance:window_active",
            labels={"scope": "uptime"},
            samples=_build_samples([(0.0, 1.0), (1200.0, 0.0)]),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="maintenance:window_active",
            labels={"scope": "timetoke"},
            samples=_build_samples([(0.0, 1.0), (1200.0, 0.0)]),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_missed_slot_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2.0),
                    (120.0, 4.0),
                    (240.0, 8.0),
                    (360.0, 14.0),
                    (480.0, 18.0),
                    (600.0, 26.0),
                    (720.0, 25.0),
                    (840.0, 10.0),
                    (960.0, 5.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (120.0, 1.5),
                    (240.0, 2.5),
                    (360.0, 5.5),
                    (480.0, 7.5),
                    (600.0, 9.5),
                    (720.0, 8.5),
                    (840.0, 3.5),
                    (960.0, 1.5),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus_block_schedule_slots_total",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (120.0, 12.0),
                    (240.0, 24.0),
                    (360.0, 36.0),
                    (480.0, 48.0),
                    (600.0, 64.0),
                    (720.0, 80.0),
                    (840.0, 96.0),
                    (960.0, 112.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10_000.0),
                    (120.0, 10_006.0),
                    (240.0, 10_012.0),
                    (360.0, 10_016.0),
                    (480.0, 10_018.0),
                    (600.0, 10_020.0),
                    (720.0, 10_022.0),
                    (840.0, 10_026.0),
                    (960.0, 10_030.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus:missed_slots:5m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.0),
                    (120.0, 5.0),
                    (240.0, 5.0),
                    (360.0, 5.0),
                    (480.0, 5.0),
                    (600.0, 5.0),
                    (720.0, 5.0),
                    (840.0, 5.0),
                    (960.0, 4.5),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_block_miss_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10_000.0),
                    (300.0, 10_025.0),
                    (600.0, 10_050.0),
                    (900.0, 10_050.0),
                    (1200.0, 10_050.0),
                    (1500.0, 10_050.0),
                    (1800.0, 10_050.0),
                    (2100.0, 10_110.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 3.0),
                    (300.0, 5.0),
                    (600.0, 6.0),
                    (900.0, 12.5),
                    (1200.0, 18.0),
                    (1500.0, 9.0),
                    (1800.0, 6.0),
                    (2100.0, 4.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_missed_slot_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 3.0),
                    (120.0, 6.0),
                    (240.0, 10.0),
                    (360.0, 12.0),
                    (480.0, 11.0),
                    (600.0, 8.0),
                    (720.0, 6.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (120.0, 2.0),
                    (240.0, 3.0),
                    (360.0, 3.5),
                    (480.0, 3.0),
                    (600.0, 2.0),
                    (720.0, 1.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_block_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 5_000.0),
                    (300.0, 5_015.0),
                    (600.0, 5_030.0),
                    (900.0, 5_050.0),
                    (1200.0, 5_075.0),
                    (1500.0, 5_110.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 4.0),
                    (300.0, 5.0),
                    (600.0, 6.0),
                    (900.0, 6.5),
                    (1200.0, 5.5),
                    (1500.0, 4.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_block_schedule_deficit_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    schedule_increments = [12.0] * 18
    produced_increments = [12.0, 12.0] + [6.0] * 12 + [12.0] * 4
    definitions.append(
        _build_counter_from_increments(
            "consensus_block_schedule_slots_total", {}, schedule_increments
        )
    )
    definitions.append(
        _build_counter_from_increments("chain_block_height", {}, produced_increments)
    )
    return MetricStore.from_definitions(definitions)


def build_block_schedule_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    schedule_increments = [12.0] * 18
    produced_increments = [12.0, 12.0] + [6.0] * 6 + [12.0] * 10
    definitions.append(
        _build_counter_from_increments(
            "consensus_block_schedule_slots_total", {}, schedule_increments
        )
    )
    definitions.append(
        _build_counter_from_increments("chain_block_height", {}, produced_increments)
    )
    return MetricStore.from_definitions(definitions)


def build_pruning_recovery_regression_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    schedule_increments = [12.0] * 18
    produced_increments = [12.0] * 5 + [6.0] * 7 + [12.0] * 6
    definitions.append(
        _build_counter_from_increments(
            "rpp_node_pruning_cycle_total", {"result": "success"}, [0.0, 0.0, 0.0, 0.0, 0.0, 1.0] + [0.0] * 12
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "consensus_block_schedule_slots_total", {}, schedule_increments
        )
    )
    definitions.append(
        _build_counter_from_increments("chain_block_height", {}, produced_increments)
    )
    lag_values = [2.0] * 5 + [20.0] * 4 + [4.0] * 9
    gap_values = [1.0] * 5 + [6.0] * 4 + [2.0] * 9
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples([(idx * 60.0, value) for idx, value in enumerate(lag_values)]),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples([(idx * 60.0, value) for idx, value in enumerate(gap_values)]),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_pruning_recovery_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    schedule_increments = [12.0] * 18
    produced_increments = [12.0] * 5 + [12.0, 10.0, 12.0, 12.0] + [12.0] * 8
    definitions.append(
        _build_counter_from_increments(
            "rpp_node_pruning_cycle_total", {"result": "success"}, [0.0, 0.0, 0.0, 0.0, 0.0, 1.0] + [0.0] * 12
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "consensus_block_schedule_slots_total", {}, schedule_increments
        )
    )
    definitions.append(
        _build_counter_from_increments("chain_block_height", {}, produced_increments)
    )
    lag_values = [2.0] * 5 + [14.0, 10.0, 6.0, 4.0] + [3.0] * 8
    gap_values = [1.0] * 5 + [5.0, 3.0, 2.0, 2.0] + [1.0] * 8
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples([(idx * 60.0, value) for idx, value in enumerate(lag_values)]),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples([(idx * 60.0, value) for idx, value in enumerate(gap_values)]),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_rpc_outage_store() -> MetricStore:
    definitions: List[MetricDefinition] = []

    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "success", "method": "health_live"},
            increments=[100.0] * 5 + [50.0] * 10,
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "client_error", "method": "health_live"},
            increments=[0.0] * 5 + [50.0] * 10,
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "server_error", "method": "health_live"},
            increments=[0.0] * 15,
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus:block_height_delta:5m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 75.0),
                    (300.0, 75.0),
                    (600.0, 75.0),
                    (900.0, 75.0),
                    (1200.0, 75.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_rpc_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "success", "method": "health_live"},
            increments=[100.0] * 12,
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "client_error", "method": "health_live"},
            increments=[0.0] * 12,
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "rpp_runtime_rpc_request_total",
            labels={"result": "server_error", "method": "health_live"},
            increments=[0.0] * 12,
        )
    )
    definitions.append(
        MetricDefinition(
            metric="consensus:block_height_delta:5m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 75.0),
                    (300.0, 75.0),
                    (600.0, 75.0),
                    (900.0, 75.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_rpc_subscription_drop_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        _build_counter_from_increments(
            "rpc_subscription_probe_disconnects_total",
            labels={"phase": "consensus_load", "stream": "pipeline"},
            increments=[0.0, 0.0, 1.0, 0.0, 0.0],
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "consensus_load"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (300.0, 1.0),
                    (600.0, 0.97),
                    (900.0, 0.72),
                    (1200.0, 0.70),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "maintenance"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (600.0, 1.0),
                    (1200.0, 1.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_rpc_subscription_maintenance_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        _build_counter_from_increments(
            "rpc_subscription_probe_disconnects_total",
            labels={"phase": "maintenance", "stream": "pipeline"},
            increments=[0.0, 1.0, 1.0, 0.0],
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "maintenance"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (600.0, 0.95),
                    (1200.0, 0.82),
                    (1800.0, 0.78),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "consensus_load"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (900.0, 1.0),
                    (1800.0, 1.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_rpc_subscription_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        _build_counter_from_increments(
            "rpc_subscription_probe_disconnects_total",
            labels={"phase": "consensus_load", "stream": "pipeline"},
            increments=[0.0, 0.0, 0.0, 0.0],
        )
    )
    definitions.append(
        _build_counter_from_increments(
            "rpc_subscription_probe_disconnects_total",
            labels={"phase": "maintenance", "stream": "pipeline"},
            increments=[0.0, 0.0, 0.0, 0.0],
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "consensus_load"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (600.0, 1.0),
                    (1200.0, 1.0),
                    (1800.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="rpc_subscription_probe_success_ratio",
            labels={"phase": "maintenance"},
            samples=_build_samples(
                [
                    (0.0, 1.0),
                    (900.0, 0.96),
                    (1800.0, 0.95),
                    (2700.0, 0.96),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_prover_backlog_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 6.0),
                    (300.0, 8.0),
                    (600.0, 10.0),
                    (900.0, 14.0),
                    (1200.0, 15.0),
                    (1500.0, 13.0),
                    (1800.0, 9.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="wallet:prover_queue_depth:max:10m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 0.5),
                    (300.0, 1.2),
                    (600.0, 2.1),
                    (900.0, 3.5),
                    (1200.0, 3.2),
                    (1500.0, 3.0),
                    (1800.0, 1.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="uptime_observation_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 200.0),
                    (300.0, 400.0),
                    (600.0, 750.0),
                    (900.0, 980.0),
                    (1200.0, 1020.0),
                    (1500.0, 980.0),
                    (1800.0, 500.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="wallet:prover_job_latency:p95_seconds:10m",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 60.0),
                    (300.0, 120.0),
                    (600.0, 150.0),
                    (900.0, 210.0),
                    (1200.0, 240.0),
                    (1500.0, 230.0),
                    (1800.0, 140.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 10_000.0),
                    (300.0, 10_030.0),
                    (600.0, 10_060.0),
                    (900.0, 10_080.0),
                    (1200.0, 10_110.0),
                    (1500.0, 10_140.0),
                    (1800.0, 10_170.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_restart_finality_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="process_start_time_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1_700_000_000.0),
                    (300.0, 1_700_000_000.0),
                    (600.0, 1_700_000_000.0),
                    (900.0, 1_700_000_900.0),
                    (1200.0, 1_700_000_900.0),
                    (1500.0, 1_700_000_900.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finality_lag_slots",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 6.0),
                    (300.0, 8.0),
                    (600.0, 10.0),
                    (900.0, 14.0),
                    (1200.0, 18.0),
                    (1500.0, 11.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="finalized_height_gap",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2.0),
                    (300.0, 3.0),
                    (600.0, 3.5),
                    (900.0, 5.0),
                    (1200.0, 6.0),
                    (1500.0, 3.0),
                ]
            ),
        )
    )
    definitions.append(
        MetricDefinition(
            metric="chain_block_height",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1_000.0),
                    (300.0, 1_020.0),
                    (600.0, 1_040.0),
                    (900.0, 1_050.0),
                    (1200.0, 1_065.0),
                    (1500.0, 1_090.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_timetoke_epoch_delay_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="timetoke_epoch_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 1800.0),
                    (600.0, 2400.0),
                    (1200.0, 3600.0),
                    (1800.0, 4200.0),
                    (2400.0, 5600.0),
                    (3000.0, 6600.0),
                    (3600.0, 7200.0),
                    (4200.0, 2400.0),
                    (4800.0, 1800.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def build_timetoke_epoch_recovery_store() -> MetricStore:
    definitions: List[MetricDefinition] = []
    definitions.append(
        MetricDefinition(
            metric="timetoke_epoch_age_seconds",
            labels={},
            samples=_build_samples(
                [
                    (0.0, 2400.0),
                    (600.0, 2100.0),
                    (1200.0, 1800.0),
                    (1800.0, 1500.0),
                    (2400.0, 1200.0),
                    (3000.0, 900.0),
                    (3600.0, 800.0),
                ]
            ),
        )
    )
    return MetricStore.from_definitions(definitions)


def default_validation_cases() -> List[ValidationCase]:
    return [
        ValidationCase(
            name="consensus-anomaly",
            store=build_consensus_anomaly_store(),
            expected_alerts={
                "ConsensusVRFSlow",
                "ConsensusVRFFailureBurst",
                "ConsensusQuorumVerificationFailure",
            },
        ),
        ValidationCase(
            name="snapshot-anomaly",
            store=build_snapshot_anomaly_store(),
            expected_alerts={
                "SnapshotStreamLagWarning",
                "SnapshotStreamLagCritical",
                "SnapshotStreamZeroThroughputWarning",
                "SnapshotStreamZeroThroughputCritical",
                "SnapshotChunkFailureSpikeWarning",
                "SnapshotChunkFailureSpikeCritical",
            },
        ),
        ValidationCase(
            name="uptime-pause",
            store=build_uptime_pause_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalityLagCritical",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusFinalizedHeightGapCritical",
                "ConsensusLivenessStall",
                "UptimeMempoolProbeFailure",
                "ConsensusMissedSlotsWarning",
                "ConsensusMissedSlotsCritical",
            },
        ),
        ValidationCase(
            name="uptime-recovery",
            store=build_uptime_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="uptime-join",
            store=build_uptime_join_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="uptime-departure",
            store=build_uptime_departure_store(),
            expected_alerts={
                "TimetokeAccrualStallCritical",
                "TimetokeAccrualStallWarning",
                "UptimeObservationGapCritical",
                "UptimeObservationGapWarning",
                "UptimeParticipationDropCritical",
                "UptimeParticipationDropWarning",
            },
        ),
        ValidationCase(
            name="transaction-latency-outage",
            store=build_transaction_latency_outage_store(),
            expected_alerts={
                "TransactionFinalityLatencyCritical",
                "TransactionFinalityLatencyWarning",
                "TransactionInclusionLatencyCritical",
                "TransactionInclusionLatencyWarning",
            },
        ),
        ValidationCase(
            name="maintenance-window-suppression",
            store=build_uptime_maintenance_suppression_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="maintenance-window-resume",
            store=build_uptime_maintenance_recovery_store(),
            expected_alerts={
                "TimetokeAccrualStallWarning",
                "TimetokeEpochDelayWarning",
                "UptimeObservationGapCritical",
                "UptimeObservationGapWarning",
                "UptimeParticipationDropCritical",
                "UptimeParticipationDropWarning",
            },
        ),
        ValidationCase(
            name="missed-slots",
            store=build_missed_slot_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalityLagCritical",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusFinalizedHeightGapCritical",
                "ConsensusMissedSlotsWarning",
                "ConsensusMissedSlotsCritical",
                "ConsensusBlockProductionLagWarning",
                "ConsensusBlockProductionLagCritical",
            },
        ),
        ValidationCase(
            name="missed-slot-recovery",
            store=build_missed_slot_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="missed-blocks",
            store=build_block_miss_store(),
            expected_alerts={"ConsensusLivenessStall", "ConsensusFinalityLagWarning"},
        ),
        ValidationCase(
            name="missed-block-recovery",
            store=build_block_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="block-schedule-deficit",
            store=build_block_schedule_deficit_store(),
            expected_alerts={
                "ConsensusBlockProductionLagWarning",
                "ConsensusBlockProductionLagCritical",
            },
        ),
        ValidationCase(
            name="block-schedule-recovery",
            store=build_block_schedule_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="rpc-availability-outage",
            store=build_rpc_outage_store(),
            expected_alerts={"RpcAvailabilityDegradedWarning", "RpcAvailabilityDegradedCritical"},
        ),
        ValidationCase(
            name="rpc-availability-recovery",
            store=build_rpc_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="rpc-subscription-drop-load",
            store=build_rpc_subscription_drop_store(),
            expected_alerts={"RpcSubscriptionDisconnectLoad"},
        ),
        ValidationCase(
            name="rpc-subscription-drop-maintenance",
            store=build_rpc_subscription_maintenance_store(),
            expected_alerts={"RpcSubscriptionDisconnectMaintenance"},
        ),
        ValidationCase(
            name="rpc-subscription-recovery",
            store=build_rpc_subscription_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="disk-pressure-pruning",
            store=build_disk_pressure_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalityLagCritical",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusFinalizedHeightGapCritical",
                "ConsensusLivenessStall",
                "SnapshotStreamLagWarning",
                "SnapshotStreamLagCritical",
                "UptimeMempoolProbeFailure",
                "UptimeObservationGapWarning",
                "UptimeObservationGapCritical",
            },
        ),
        ValidationCase(
            name="disk-pressure-recovery",
            store=build_disk_pressure_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="prover-backlog-correlation",
            store=build_prover_backlog_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "FinalityProverBacklogCorrelation",
                "UptimeObservationGapWarning",
                "UptimeProverLatencyCorrelation",
            },
        ),
        ValidationCase(
            name="restart-finality-correlation",
            store=build_restart_finality_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusRestartFinalityCorrelation",
            },
        ),
        ValidationCase(
            name="pruning-recovery-regression",
            store=build_pruning_recovery_regression_store(),
            expected_alerts={"PruningRecoveryBlockRate", "PruningRecoveryFinality"},
        ),
        ValidationCase(
            name="pruning-recovery-recovery",
            store=build_pruning_recovery_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="timetoke-epoch-delay",
            store=build_timetoke_epoch_delay_store(),
            expected_alerts={
                "TimetokeEpochDelayWarning",
                "TimetokeEpochDelayCritical",
            },
        ),
        ValidationCase(
            name="timetoke-epoch-recovery",
            store=build_timetoke_epoch_recovery_store(),
            expected_alerts=set(),
        ),
        ValidationCase(
            name="baseline",
            store=_merge_stores(
                build_consensus_baseline_store(),
                build_snapshot_baseline_store(),
                build_uptime_baseline_store(),
            ),
            expected_alerts=set(),
        ),
    ]


def _merge_stores(*stores: MetricStore) -> MetricStore:
    series: Dict[str, MetricSeries] = {}
    for store in stores:
        series.update(store._series)  # type: ignore[attr-defined]
    return MetricStore(series)
