#!/usr/bin/env python3
"""Generate a nightly status summary and inject it into the weekly report."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Dict, Iterable, List, Optional

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


def write_status_file(path: pathlib.Path, content: str) -> None:
    path.write_text(content + "\n", encoding="utf-8")


def update_weekly_report(weekly_path: pathlib.Path, summary: str) -> None:
    pattern = re.compile(r"<!-- nightly-status:start -->.*?<!-- nightly-status:end -->", re.S)
    replacement = (
        "<!-- nightly-status:start -->\n"
        f"{summary}\n"
        "<!-- nightly-status:end -->"
    )
    text = weekly_path.read_text(encoding="utf-8")
    if "<!-- nightly-status:start -->" not in text:
        raise NightlyStatusError(
            f"Marker <!-- nightly-status:start --> nicht in {weekly_path} gefunden"
        )
    new_text, count = pattern.subn(replacement, text)
    if count == 0:
        raise NightlyStatusError(
            f"Konnte Abschnitt zwischen nightly-status-Markern in {weekly_path} nicht ersetzen"
        )
    if not new_text.endswith("\n"):
        new_text += "\n"
    weekly_path.write_text(new_text, encoding="utf-8")


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

    status_path = pathlib.Path(args.status_file)
    write_status_file(status_path, summary)

    if not args.skip_weekly:
        weekly_path = pathlib.Path(args.weekly)
        update_weekly_report(weekly_path, summary)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except NightlyStatusError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1)
