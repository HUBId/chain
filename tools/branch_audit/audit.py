#!/usr/bin/env python3
"""Branch audit tool for cataloging remote branches without deleting anything.

The tool produces a JSON report summarizing remote branches, their merge state
relative to a canonical branch, and suggested clean-up categories.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - fallback for older interpreters
    import tomli as tomllib  # type: ignore


SYSTEM_INFRA_PATTERNS = (
    "main",
    "master",
    "dev",
    "develop",
    "production",
    "prod",
    "staging/",
    "release/",
    "infra/",
)

EXPERIMENT_PREFIXES = ("experiment/", "spike/", "codex/")

TRIVIAL_AHEAD_THRESHOLD = 5
TRIVIAL_RECENCY_DAYS = 90
ACTIVE_RECENCY_DAYS = 60
STALE_AGE_DAYS = 180


@dataclass
class BranchRecord:
    name: str
    remote: str
    short_name: str
    commit: str
    author: str
    last_commit_iso: str
    ahead: Optional[int]
    behind: Optional[int]
    is_merged: bool
    category: str
    is_system_infra: bool
    is_experiment: bool


@dataclass
class AuditReport:
    canonical_branch: str
    generated_at: str
    branches: List[BranchRecord]

    def to_dict(self) -> Dict:
        return {
            "canonical_branch": self.canonical_branch,
            "generated_at": self.generated_at,
            "branches": [asdict(b) for b in self.branches],
        }


def run_git(args: List[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=False
    )


def load_config(repo: Path) -> Dict[str, str]:
    config_path = repo / "tools" / "branch_audit" / "config.toml"
    if not config_path.exists():
        return {}
    with config_path.open("rb") as fp:
        return tomllib.load(fp)


def determine_canonical_branch(args_canonical: Optional[str], repo: Path) -> str:
    if args_canonical:
        return args_canonical
    env_branch = os.getenv("CANONICAL_BRANCH")
    if env_branch:
        return env_branch
    config = load_config(repo)
    if config.get("canonical_branch"):
        return config["canonical_branch"]
    return "main"


def fetch_remotes(repo: Path, skip_fetch: bool) -> None:
    if skip_fetch:
        return
    result = run_git(["fetch", "--all", "--prune"], cwd=repo)
    if result.returncode != 0:
        print("[warn] git fetch failed; continuing with existing refs")
        print(result.stderr)


def iter_remote_branches(repo: Path) -> Iterable[Tuple[str, str, str, str]]:
    fmt = "%(refname:short)|%(objectname)|%(committerdate:iso8601)|%(authorname)"
    result = run_git(["for-each-ref", f"--format={fmt}", "refs/remotes"], cwd=repo)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        name, commit, date_str, author = line.split("|", 3)
        if name.endswith("/HEAD") or "->" in name:
            continue
        yield name, commit, date_str, author


def ref_exists(repo: Path, ref: str) -> bool:
    result = run_git(["show-ref", "--verify", f"refs/remotes/{ref}"], cwd=repo)
    return result.returncode == 0


def ahead_behind(repo: Path, canonical_ref: str, branch_ref: str) -> Tuple[Optional[int], Optional[int]]:
    if not ref_exists(repo, canonical_ref):
        return None, None
    result = run_git(
        ["rev-list", "--left-right", "--count", f"refs/remotes/{canonical_ref}...refs/remotes/{branch_ref}"],
        cwd=repo,
    )
    if result.returncode != 0:
        return None, None
    ahead_str, behind_str = result.stdout.strip().split()
    return int(ahead_str), int(behind_str)


def is_merged(repo: Path, branch_ref: str, canonical_ref: str) -> bool:
    if not ref_exists(repo, canonical_ref):
        return False
    result = run_git(["merge-base", "--is-ancestor", f"refs/remotes/{branch_ref}", f"refs/remotes/{canonical_ref}"], cwd=repo)
    return result.returncode == 0


def parse_date(date_str: str) -> datetime:
    try:
        return datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return datetime.fromisoformat(date_str)


def categorize_branch(
    branch: str,
    last_commit: datetime,
    ahead: Optional[int],
    merged: bool,
    canonical_branch: str,
) -> Tuple[str, bool, bool]:
    canonical_ref = f"origin/{canonical_branch}"
    is_system = branch == canonical_ref or any(
        branch.startswith(f"origin/{p}") if p.endswith("/") else branch == f"origin/{p}"
        for p in SYSTEM_INFRA_PATTERNS
    )
    short_name = branch.split("/", 1)[1] if "/" in branch else branch
    is_experiment = any(short_name.startswith(prefix) for prefix in EXPERIMENT_PREFIXES)

    if is_system:
        return "SYSTEM_INFRA", is_system, is_experiment
    if merged:
        return "SAFE_MERGED", is_system, is_experiment

    now = datetime.now(timezone.utc)
    age = now - last_commit

    if age > timedelta(days=STALE_AGE_DAYS):
        return "STALE_UNMERGED", is_system, is_experiment
    if ahead is not None and ahead <= TRIVIAL_AHEAD_THRESHOLD and age <= timedelta(days=TRIVIAL_RECENCY_DAYS):
        return "TRIVIAL_MERGE_CANDIDATE", is_system, is_experiment
    if age <= timedelta(days=ACTIVE_RECENCY_DAYS):
        return "ACTIVE_WORK", is_system, is_experiment
    return "STALE_UNMERGED", is_system, is_experiment


def build_report(repo: Path, canonical_branch: str, skip_fetch: bool, output_dir: Path) -> AuditReport:
    fetch_remotes(repo, skip_fetch)
    canonical_ref = f"origin/{canonical_branch}"

    branches: List[BranchRecord] = []
    for name, commit, date_str, author in iter_remote_branches(repo):
        remote, short_name = name.split("/", 1)
        ahead, behind = ahead_behind(repo, canonical_ref, name)
        merged = is_merged(repo, name, canonical_ref)
        last_commit_dt = parse_date(date_str)
        category, is_system, is_experiment = categorize_branch(
            name, last_commit_dt, ahead, merged, canonical_branch
        )
        branches.append(
            BranchRecord(
                name=name,
                remote=remote,
                short_name=short_name,
                commit=commit,
                author=author,
                last_commit_iso=last_commit_dt.astimezone(timezone.utc).isoformat(),
                ahead=ahead,
                behind=behind,
                is_merged=merged,
                category=category,
                is_system_infra=is_system,
                is_experiment=is_experiment,
            )
        )

    branches.sort(key=lambda b: b.name)
    return AuditReport(
        canonical_branch=canonical_branch,
        generated_at=datetime.now(timezone.utc).isoformat(),
        branches=branches,
    )


def write_report(report: AuditReport, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "report.json"
    with out_path.open("w", encoding="utf-8") as fp:
        json.dump(report.to_dict(), fp, indent=2)
    return out_path


def summarize_counts(report: AuditReport) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for branch in report.branches:
        counts[branch.category] = counts.get(branch.category, 0) + 1
    return counts


def generate_markdown_summary(report: AuditReport, output_dir: Path, repo: Path) -> Path:
    counts = summarize_counts(report)
    samples: Dict[str, List[str]] = {}
    for branch in report.branches:
        samples.setdefault(branch.category, [])
        if len(samples[branch.category]) < 5:
            samples[branch.category].append(branch.name)

    lines = [
        "# Branch Audit Report",
        "",
        "This file is generated by `tools/branch_audit/audit.py` and is intended for operators.",
        "Run the audit regularly to keep the numbers current.",
        "",
        "## Category Definitions",
        "- **SAFE_MERGED**: Branch is fully merged into the canonical branch (0 commits ahead).",
        "- **TRIVIAL_MERGE_CANDIDATE**: Few commits ahead (<=5) and recent (within ~90 days).",
        "- **STALE_UNMERGED**: Not merged and older than ~6 months.",
        "- **ACTIVE_WORK**: Not merged and last commit within 60 days.",
        "- **SYSTEM_INFRA**: Protected, long-lived branches such as main/dev/release/staging/infra.",
        "",
        f"Canonical branch: **{report.canonical_branch}**",
        "",
        "## Category Summary",
        "",
    ]

    for category in [
        "SAFE_MERGED",
        "TRIVIAL_MERGE_CANDIDATE",
        "STALE_UNMERGED",
        "ACTIVE_WORK",
        "SYSTEM_INFRA",
    ]:
        lines.append(f"- {category}: {counts.get(category, 0)}")
    lines.append("")

    lines.append("## Sample Branches per Category")
    lines.append("")
    for category in [
        "SAFE_MERGED",
        "TRIVIAL_MERGE_CANDIDATE",
        "STALE_UNMERGED",
        "ACTIVE_WORK",
        "SYSTEM_INFRA",
    ]:
        lines.append(f"### {category}")
        lines.append("")
        lines.append("| Branch | Ahead | Behind | Last Commit |")
        lines.append("| --- | --- | --- | --- |")
        for name in samples.get(category, []):
            br = next(b for b in report.branches if b.name == name)
            lines.append(
                f"| `{br.name}` | {br.ahead if br.ahead is not None else '-'} | {br.behind if br.behind is not None else '-'} | {br.last_commit_iso} |"
            )
        if not samples.get(category):
            lines.append("| _none_ | - | - | - |")
        lines.append("")

    lines.append("## How to Use This Report")
    lines.append("")
    lines.append("1. Review the counts above to estimate clean-up scope.")
    lines.append(
        "2. Generate delete suggestions for merged branches: `tools/branch_audit/generate_delete_commands.py --report tools/branch_audit/report.json`."
    )
    lines.append(
        "3. Generate merge/PR suggestions for small branches: `tools/branch_audit/generate_trivial_merge_commands.py --report tools/branch_audit/report.json`."
    )
    lines.append(
        "4. List stale branches for manual inspection: `tools/branch_audit/list_stale_unmerged.py --report tools/branch_audit/report.json`."
    )
    lines.append(
        "5. Manually execute only the commands you agree with; nothing here auto-deletes or auto-merges branches."
    )

    out_path = repo / "docs" / "branch_audit_report.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate branch audit report without deleting anything.")
    parser.add_argument("--canonical-branch", help="Override canonical branch (default from CANONICAL_BRANCH env or config).")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Path to the git repository root.")
    parser.add_argument("--output-dir", type=Path, default=Path("tools/branch_audit"), help="Directory for generated artifacts.")
    parser.add_argument("--skip-fetch", action="store_true", help="Skip git fetch --all --prune (useful for offline runs/tests).")
    parser.add_argument("--write-markdown", action="store_true", help="Also write docs/branch_audit_report.md from the JSON report.")
    args = parser.parse_args()

    repo = args.repo.resolve()
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo / args.output_dir
    canonical_branch = determine_canonical_branch(args.canonical_branch, repo)
    report = build_report(repo, canonical_branch, args.skip_fetch, output_dir)
    report_path = write_report(report, output_dir)
    print(f"Report written to {report_path}")
    if args.write_markdown:
        md_path = generate_markdown_summary(report, output_dir, repo)
        print(f"Markdown summary written to {md_path}")


if __name__ == "__main__":
    main()
