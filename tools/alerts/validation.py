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


@dataclass(frozen=True)
class FinalityServiceLevel:
    lag_warning_slots: float
    lag_critical_slots: float
    gap_warning_blocks: float
    gap_critical_blocks: float
    stall_duration_seconds: float


FINALITY_SLA = FinalityServiceLevel(
    lag_warning_slots=12.0,
    lag_critical_slots=24.0,
    gap_warning_blocks=4.0,
    gap_critical_blocks=8.0,
    stall_duration_seconds=600.0,
)


@dataclass(frozen=True)
class UptimeServiceLevel:
    participation_warning_ratio: float
    participation_critical_ratio: float
    uptime_gap_warning_seconds: float
    uptime_gap_critical_seconds: float
    timetoke_minimum_rate: float
    timetoke_window_seconds: float


UPTIME_SLA = UptimeServiceLevel(
    participation_warning_ratio=0.97,
    participation_critical_ratio=0.94,
    uptime_gap_warning_seconds=900.0,
    uptime_gap_critical_seconds=1800.0,
    timetoke_minimum_rate=0.00025,
    timetoke_window_seconds=900.0,
)

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


def _evaluate_block_height_stall(
    store: MetricStore, metric: str, window: float, duration: float
) -> Optional[AlertComputation]:
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
            name="ConsensusLivenessStall",
            severity="critical",
            service="consensus",
            summary="Block production stalled for 10 minutes",
            description=(
                "Accepted block height failed to advance for at least ten minutes. Validate proposer health, check peer counts,"
                " and follow the uptime soak runbook to restore block flow."
            ),
            runbook_url="https://github.com/ava-labs/chain/blob/main/docs/operations/uptime.md#alerts",
            evaluator=lambda store: _evaluate_block_height_stall(
                store, "chain_block_height", FINALITY_SLA.stall_duration_seconds, FINALITY_SLA.stall_duration_seconds
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
                store, "timetoke_epoch_age_seconds", 3600.0, 600.0
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
                store, "timetoke_epoch_age_seconds", 5400.0, 600.0
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
                store, UPTIME_SLA.participation_warning_ratio, 600.0
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
                store, UPTIME_SLA.participation_critical_ratio, 600.0
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
                store, "uptime_observation_age_seconds", UPTIME_SLA.uptime_gap_warning_seconds, 600.0
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
                store, "uptime_observation_age_seconds", UPTIME_SLA.uptime_gap_critical_seconds, 600.0
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
                UPTIME_SLA.timetoke_minimum_rate,
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
                UPTIME_SLA.timetoke_minimum_rate,
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
            name="missed-slots",
            store=build_missed_slot_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalityLagCritical",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusFinalizedHeightGapCritical",
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
            name="restart-finality-correlation",
            store=build_restart_finality_store(),
            expected_alerts={
                "ConsensusFinalityLagWarning",
                "ConsensusFinalizedHeightGapWarning",
                "ConsensusRestartFinalityCorrelation",
            },
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
            store=_merge_stores(build_consensus_baseline_store(), build_snapshot_baseline_store()),
            expected_alerts=set(),
        ),
    ]


def _merge_stores(*stores: MetricStore) -> MetricStore:
    series: Dict[str, MetricSeries] = {}
    for store in stores:
        series.update(store._series)  # type: ignore[attr-defined]
    return MetricStore(series)
