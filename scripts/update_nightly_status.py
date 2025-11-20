#!/usr/bin/env python3
"""Generate a nightly status summary and inject it into the weekly report."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

JOB_LABELS: Dict[str, str] = {
    "snapshot-verifier": "Snapshot verifier smoke test",
    "worm-export-smoke": "WORM export pipeline smoke test",
}

EMOJI_BY_CONCLUSION = {
    "success": "✅",
    "failure": "❌",
    "cancelled": "⚠️",
    "skipped": "⚠️",
    "timed_out": "❌",
    "action_required": "⚠️",
}


class NightlyStatusError(RuntimeError):
    """Raised if the status summary cannot be produced."""


@dataclass
class ControlStatus:
    """Represents the rendered status for a compliance control."""

    name: str
    source: str
    timestamp: str
    icon: str
    label: str
    details: str
    notes: List[str]


def gh_api(path: str, *, params: Optional[Dict[str, str]] = None) -> dict:
    """Execute a GitHub API request via the gh CLI and return the JSON payload."""

    cmd: List[str] = ["gh", "api", path]
    if params:
        for key, value in params.items():
            if value is None or value == "":
                continue
            cmd.extend(["-f", f"{key}={value}"])
    try:
        completed = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - CLI errors bubble up
        raise NightlyStatusError(
            f"gh api call failed for {path}: {exc.stderr or exc.stdout}"
        ) from exc
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive parsing
        raise NightlyStatusError(
            f"invalid JSON response for {path}: {completed.stdout}"
        ) from exc


def collect_jobs(repo: str, workflow: str, branch: str) -> tuple[dict, List[dict]]:
    runs = gh_api(
        f"/repos/{repo}/actions/workflows/{workflow}/runs",
        params={
            "branch": branch,
            "status": "success",
            "per_page": "1",
        },
    )
    workflow_runs: List[dict] = runs.get("workflow_runs", [])
    if not workflow_runs:
        raise NightlyStatusError(
            f"kein erfolgreicher Lauf für Workflow '{workflow}' auf Branch '{branch}' gefunden"
        )
    workflow_run = workflow_runs[0]
    run_id = workflow_run.get("id")
    if not run_id:
        raise NightlyStatusError("Antwort enthielt keine Run-ID")

    jobs: List[dict] = []
    page = 1
    while True:
        response = gh_api(
            f"/repos/{repo}/actions/runs/{run_id}/jobs",
            params={
                "per_page": "100",
                "page": str(page),
            },
        )
        page_jobs = response.get("jobs", [])
        jobs.extend(page_jobs)
        if len(page_jobs) < 100:
            break
        page += 1
    return workflow_run, jobs


def render_table_row(job_key: str, job: Optional[dict]) -> str:
    label = JOB_LABELS[job_key]
    if not job:
        return f"| {label} | ❔ nicht gefunden | ❔ | n/a | n/a |"

    status = job.get("status", "unknown")
    conclusion = job.get("conclusion") or "pending"
    icon = EMOJI_BY_CONCLUSION.get(conclusion, "❔")
    display_status = status.replace("_", " ")
    display_conclusion = conclusion.replace("_", " ")
    completed_at = job.get("completed_at") or job.get("started_at") or ""
    if completed_at:
        try:
            timestamp = dt.datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
            completed_at = timestamp.strftime("%Y-%m-%d %H:%M UTC")
        except ValueError:
            pass
    else:
        completed_at = "n/a"
    html_url = job.get("html_url") or ""
    link = f"[Logs]({html_url})" if html_url else "n/a"
    return (
        f"| {label} | {display_status} | {icon} {display_conclusion} | {completed_at} | {link} |"
    )


def build_summary(workflow_run: dict, jobs: Iterable[dict]) -> str:
    jobs_by_name = {job.get("name"): job for job in jobs}
    rows = [
        "| Job | Status | Ergebnis | Aktualisiert | Details |",
        "| --- | --- | --- | --- | --- |",
    ]
    for key, display_name in JOB_LABELS.items():
        row = render_table_row(key, jobs_by_name.get(display_name))
        rows.append(row)

    run_title = workflow_run.get("display_title") or workflow_run.get("name") or "CI"
    run_url = workflow_run.get("html_url") or ""
    run_line = (
        f"Zuletzt geprüfter CI-Lauf: [{run_title}]({run_url})"
        if run_url
        else f"Zuletzt geprüfter CI-Lauf: {run_title}"
    )
    generated_at = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Nightly Status — {generated_at}",
        "",
        run_line,
        "",
        *rows,
    ]
    return "\n".join(lines)


def _format_iso_timestamp(value: Optional[str]) -> str:
    if not value:
        return "n/a"
    candidate = value.strip()
    if not candidate:
        return "n/a"
    try:
        timestamp = dt.datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        return candidate
    return timestamp.strftime("%Y-%m-%d %H:%M UTC")


def _format_file_timestamp(path: pathlib.Path) -> str:
    try:
        mtime = path.stat().st_mtime
    except (FileNotFoundError, OSError):
        return "n/a"
    timestamp = dt.datetime.utcfromtimestamp(mtime)
    return timestamp.strftime("%Y-%m-%d %H:%M UTC")


def _load_json(path: pathlib.Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except OSError as exc:  # pragma: no cover - I/O errors bubble up
        raise NightlyStatusError(f"Konnte {path} nicht lesen: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise NightlyStatusError(f"Ungültiges JSON in {path}: {exc}") from exc


def _format_ms(value: Optional[float | int]) -> str:
    if value is None:
        return "n/a"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if abs(numeric) >= 1000.0:
        return f"{numeric / 1000.0:.2f}s"
    return f"{numeric:.0f}ms"


def summarise_retention(report_path: Optional[pathlib.Path]) -> ControlStatus:
    name = "WORM-Retention"
    source = "worm-retention-report.json"
    if report_path is None or not report_path.exists():
        notes = [
            "⚠️ WORM-Retention: Report fehlt – Nightly-Artefakt prüfen und bei Bedarf `cargo xtask worm-retention-check` manuell neu ausführen."
        ]
        return ControlStatus(
            name=name,
            source=source,
            timestamp="n/a",
            icon="⚠️",
            label="Fehlt",
            details="Report nicht gefunden – Artefakt `worm-retention-report.json` prüfen.",
            notes=notes,
        )

    data = _load_json(report_path)
    generated_at = _format_iso_timestamp(data.get("generated_at"))
    summaries: Sequence[dict[str, Any]] = data.get("summaries") or []
    total_summaries = len(summaries)
    stale = len(data.get("stale_entries") or [])
    orphaned = len(data.get("orphaned_entries") or [])
    unsigned = len(data.get("unsigned_records") or [])

    warnings: List[str] = list(data.get("warnings") or [])
    for summary in summaries:
        summary_path = summary.get("summary_path") or "(unbekannt)"
        for warning in summary.get("warnings") or []:
            warnings.append(f"{summary_path}: {warning}")
        metadata = summary.get("retention_metadata") or {}
        for warning in metadata.get("warnings") or []:
            warnings.append(f"{summary_path} (metadata): {warning}")
        if not summary.get("entries"):
            warnings.append(f"{summary_path}: keine exportierten Einträge gefunden")

    notes = [f"⚠️ WORM-Retention: {warning}" for warning in warnings]
    issues = []
    if stale:
        issues.append(f"{stale} abgelaufene Einträge")
    if orphaned:
        issues.append(f"{orphaned} verwaiste Audit-/Export-Paare")
    if unsigned:
        issues.append(f"{unsigned} unsignierte Logeinträge")
    if total_summaries == 0:
        notes.append(
            "⚠️ WORM-Retention: Es wurden keine Summaries gefunden – Artefakt `worm-export-smoke` prüfen."
        )

    if issues:
        icon = "❌"
        label = "Fehler"
        detail = ", ".join(issues)
    elif warnings:
        icon = "⚠️"
        label = "Warnung"
        detail = f"{total_summaries} Summaries, {len(warnings)} Warnungen"
    else:
        icon = "✅"
        label = "OK"
        detail = f"{total_summaries} Summaries ohne Befund"

    return ControlStatus(
        name=name,
        source=source,
        timestamp=generated_at,
        icon=icon,
        label=label,
        details=detail,
        notes=notes,
    )


def summarise_snapshot_partition(report_path: Optional[pathlib.Path]) -> ControlStatus:
    name = "Snapshot Partition Drill"
    source = "snapshot_partition_report.json"
    if report_path is None or not report_path.exists():
        notes = [
            "⚠️ Snapshot Partition Drill: Report fehlt – Actions-Artefakt `snapshot_partition_report.json` prüfen und Chaos-Test bei Bedarf erneut ausführen."
        ]
        return ControlStatus(
            name=name,
            source=source,
            timestamp="n/a",
            icon="⚠️",
            label="Fehlt",
            details="Report nicht gefunden – Chaos-Artefakt überprüfen.",
            notes=notes,
        )

    data = _load_json(report_path)
    thresholds = data.get("thresholds") or {}
    recovery = data.get("recovery") or {}
    propagation = data.get("propagation_ms") or {}

    max_resume = recovery.get("max_resume_latency_ms")
    mean_resume = recovery.get("mean_resume_latency_ms")
    resume_events = recovery.get("resume_events")
    chunk_retries = data.get("chunk_retries")
    threshold_resume = thresholds.get("max_resume_latency_ms")
    threshold_chunk = thresholds.get("max_chunk_retries")

    issues = []
    notes: List[str] = []

    if (
        max_resume is not None
        and threshold_resume is not None
        and float(max_resume) > float(threshold_resume)
    ):
        issues.append(
            "Resume-Latenz überschreitet Grenzwert"
        )
    if (
        chunk_retries is not None
        and threshold_chunk is not None
        and int(chunk_retries) > int(threshold_chunk)
    ):
        issues.append("Chunk-Retries überschreiten Grenzwert")

    if resume_events in (0, None):
        notes.append(
            "⚠️ Snapshot Partition Drill: Keine Resume-Ereignisse im Report – Datenlage prüfen."
        )

    if propagation.get("p95") is None:
        notes.append(
            "⚠️ Snapshot Partition Drill: Propagation-P95 fehlt im Report."
        )

    icon: str
    label: str
    if issues:
        icon = "❌"
        label = "Fehler"
    elif notes:
        icon = "⚠️"
        label = "Warnung"
    else:
        icon = "✅"
        label = "OK"

    details_parts = [
        f"p95 Propagation {_format_ms(propagation.get('p95'))}",
        f"Resume max {_format_ms(max_resume)} (Limit {_format_ms(threshold_resume)})",
        f"Chunk retries {chunk_retries if chunk_retries is not None else 'n/a'} (Limit {threshold_chunk if threshold_chunk is not None else 'n/a'})",
    ]
    if mean_resume is not None:
        details_parts.append(f"Resume Ø {_format_ms(mean_resume)}")

    timestamp = data.get("generated_at")
    if timestamp:
        rendered_timestamp = _format_iso_timestamp(timestamp)
    else:
        rendered_timestamp = _format_file_timestamp(report_path)

    return ControlStatus(
        name=name,
        source=source,
        timestamp=rendered_timestamp,
        icon=icon,
        label=label,
        details=", ".join(details_parts),
        notes=notes,
    )


def build_phasec_status(
    retention_report: Optional[pathlib.Path],
    chaos_report: Optional[pathlib.Path],
) -> str:
    statuses = [
        summarise_retention(retention_report),
        summarise_snapshot_partition(chaos_report),
    ]
    _validate_phasec_status(statuses)
    generated_at = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"### Phase‑C Kontrollen — {generated_at}",
        "",
        "| Kontrolle | Quelle | Stand | Ergebnis | Details |",
        "| --- | --- | --- | --- | --- |",
    ]
    for status in statuses:
        lines.append(
            "| {name} | `{source}` | {timestamp} | {icon} {label} | {details} |".format(
                name=status.name,
                source=status.source,
                timestamp=status.timestamp or "n/a",
                icon=status.icon,
                label=status.label,
                details=status.details,
            )
        )

    notes: List[str] = []
    for status in statuses:
        notes.extend(status.notes)
    if notes:
        lines.extend(["", "#### Hinweise", "", *notes])

    artifact_hashes = _render_artifact_hashes(
        {
            "worm-retention-report.json": retention_report,
            "snapshot_partition_report.json": chaos_report,
        }
    )
    if artifact_hashes:
        lines.extend(["", "#### Artefakte", "", *artifact_hashes])

    return "\n".join(lines)


def write_status_file(path: pathlib.Path, content: str) -> None:
    path.write_text(content + "\n", encoding="utf-8")


def _validate_phasec_status(statuses: Sequence[ControlStatus]) -> None:
    failures = [s for s in statuses if s.icon == "❌"]
    if failures:
        failing_labels = ", ".join(f"{s.name}: {s.label}" for s in failures)
        raise NightlyStatusError(
            f"Phase‑C Drill fehlgeschlagen: {failing_labels}"
        )


def _hash_file(path: pathlib.Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except FileNotFoundError:
        return "n/a"
    except OSError as exc:  # pragma: no cover - I/O errors bubble up
        raise NightlyStatusError(f"Konnte Hash für {path} nicht berechnen: {exc}") from exc


def _render_artifact_hashes(paths: dict[str, Optional[pathlib.Path]]) -> List[str]:
    lines: List[str] = []
    for name, path in paths.items():
        if path is None:
            lines.append(f"- `{name}`: fehlt (kein Pfad übergeben)")
            continue
        hash_value = _hash_file(path)
        if hash_value == "n/a":
            lines.append(f"- `{name}`: Report fehlt – Hash nicht verfügbar")
        else:
            lines.append(f"- `{name}`: SHA256 `{hash_value}`")
    return lines


def _replace_marker(text: str, marker: str, payload: str, path: pathlib.Path) -> str:
    pattern = re.compile(rf"<!-- {marker}:start -->.*?<!-- {marker}:end -->", re.S)
    replacement = (
        f"<!-- {marker}:start -->\n"
        f"{payload}\n"
        f"<!-- {marker}:end -->"
    )
    if f"<!-- {marker}:start -->" not in text:
        raise NightlyStatusError(
            f"Marker <!-- {marker}:start --> nicht in {path} gefunden"
        )
    new_text, count = pattern.subn(replacement, text)
    if count == 0:
        raise NightlyStatusError(
            f"Konnte Abschnitt zwischen {marker}-Markern in {path} nicht ersetzen"
        )
    return new_text


def update_weekly_report(
    weekly_path: pathlib.Path, summary: str, phasec_block: str
) -> None:
    text = weekly_path.read_text(encoding="utf-8")
    text = _replace_marker(text, "nightly-status", summary, weekly_path)
    text = _replace_marker(text, "phasec-status", phasec_block, weekly_path)
    if not text.endswith("\n"):
        text += "\n"
    weekly_path.write_text(text, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        default=os.environ.get("REPOSITORY") or os.environ.get("GITHUB_REPOSITORY"),
        help="<owner>/<repo> für GitHub API-Aufrufe",
    )
    parser.add_argument(
        "--workflow",
        default="ci.yml",
        help="Workflow-Dateiname (Default: ci.yml)",
    )
    parser.add_argument(
        "--branch",
        default=(
            os.environ.get("TARGET_BRANCH")
            or os.environ.get("DEFAULT_BRANCH")
            or "main"
        ),
        help="Branch-Name für den CI-Lauf (Default: TARGET_BRANCH/DEFAULT_BRANCH/main)",
    )
    parser.add_argument(
        "--status-file",
        default="nightly_status.md",
        help="Pfad für die generierte Statusdatei",
    )
    parser.add_argument(
        "--weekly",
        default="docs/status/weekly.md",
        help="Pfad zur Weekly-Statusdatei, die aktualisiert werden soll",
    )
    parser.add_argument(
        "--phasec-status-file",
        default="phaseC_status.md",
        help="Pfad für den generierten Phase‑C-Statusblock",
    )
    parser.add_argument(
        "--retention-report",
        default=None,
        help="Pfad zur worm-retention-report.json (optional)",
    )
    parser.add_argument(
        "--chaos-report",
        default=None,
        help="Pfad zur snapshot_partition_report.json (optional)",
    )
    parser.add_argument(
        "--skip-weekly",
        action="store_true",
        help="Weekly-Report nicht aktualisieren, nur Statusdatei schreiben",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.repo:
        raise NightlyStatusError(
            "Kein Repository angegeben (Setze --repo oder REPOSITORY/GITHUB_REPOSITORY)"
        )
    workflow_run, jobs = collect_jobs(args.repo, args.workflow, args.branch)
    summary = build_summary(workflow_run, jobs)

    retention_report = pathlib.Path(args.retention_report).resolve() if args.retention_report else None
    chaos_report = pathlib.Path(args.chaos_report).resolve() if args.chaos_report else None
    phasec_block = build_phasec_status(retention_report, chaos_report)

    status_path = pathlib.Path(args.status_file)
    write_status_file(status_path, summary)
    phasec_path = pathlib.Path(args.phasec_status_file)
    write_status_file(phasec_path, phasec_block)

    if not args.skip_weekly:
        weekly_path = pathlib.Path(args.weekly)
        update_weekly_report(weekly_path, summary, phasec_block)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NightlyStatusError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1)
