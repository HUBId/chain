import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict


audit_script = Path(__file__).resolve().parents[1] / "audit.py"

def git(args, cwd: Path, env: Dict[str, str] | None = None):
    subprocess.run(["git", *args], cwd=cwd, check=True, env=env)


def commit_file(repo: Path, filename: str, content: str, message: str, days_ago: int = 0):
    path = repo / filename
    path.write_text(content, encoding="utf-8")
    git(["add", filename], cwd=repo)
    env = os.environ.copy()
    if days_ago:
        past = datetime.now() - timedelta(days=days_ago)
        env["GIT_COMMITTER_DATE"] = env["GIT_AUTHOR_DATE"] = past.isoformat()
    git(["commit", "-m", message], cwd=repo, env=env)


def setup_repo(tmpdir: Path) -> Path:
    origin = tmpdir / "origin"
    work = tmpdir / "work"
    git(["init", "--bare", origin.as_posix()], cwd=tmpdir)
    git(["clone", origin.as_posix(), work.as_posix()], cwd=tmpdir)
    git(["config", "user.email", "test@example.com"], cwd=work)
    git(["config", "user.name", "Tester"], cwd=work)

    git(["checkout", "-b", "main"], cwd=work)
    commit_file(work, "README.md", "root", "init")
    git(["push", "-u", "origin", "main"], cwd=work)

    # merged branch
    git(["checkout", "-b", "feature/merged"], cwd=work)
    commit_file(work, "merged.txt", "merged", "merged work")
    git(["push", "-u", "origin", "feature/merged"], cwd=work)
    git(["checkout", "main"], cwd=work)
    git(["merge", "feature/merged"], cwd=work)
    git(["push"], cwd=work)

    # trivial candidate (recent small change)
    git(["checkout", "-b", "feature/trivial"], cwd=work)
    commit_file(work, "trivial.txt", "trivial", "small change")
    git(["push", "-u", "origin", "feature/trivial"], cwd=work)

    # stale unmerged
    git(["checkout", "-b", "feature/stale"], cwd=work)
    commit_file(work, "stale.txt", "stale", "stale change", days_ago=220)
    git(["push", "-u", "origin", "feature/stale"], cwd=work)

    # system infra
    git(["checkout", "-b", "release/v1"], cwd=work)
    commit_file(work, "release.txt", "release", "release branch")
    git(["push", "-u", "origin", "release/v1"], cwd=work)

    git(["checkout", "main"], cwd=work)
    return work


def test_audit_categories(tmp_path):
    repo = setup_repo(tmp_path)
    output_dir = repo / "out"
    subprocess.run(
        ["python", audit_script.as_posix(), "--repo", repo.as_posix(), "--output-dir", output_dir.as_posix(), "--skip-fetch"],
        check=True,
    )
    report_path = output_dir / "report.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))
    branches = {b["name"]: b for b in data["branches"]}

    assert branches["origin/feature/merged"]["category"] == "SAFE_MERGED"
    assert branches["origin/feature/trivial"]["category"] == "TRIVIAL_MERGE_CANDIDATE"
    assert branches["origin/feature/stale"]["category"] == "STALE_UNMERGED"
    assert branches["origin/release/v1"]["category"] == "SYSTEM_INFRA"
    assert branches["origin/main"]["category"] == "SYSTEM_INFRA"


def test_protected_branches_not_deleted(tmp_path):
    repo = setup_repo(tmp_path)
    output_dir = repo / "out"
    subprocess.run(
        ["python", audit_script.as_posix(), "--repo", repo.as_posix(), "--output-dir", output_dir.as_posix(), "--skip-fetch"],
        check=True,
    )
    report_path = output_dir / "report.json"
    data = json.loads(report_path.read_text(encoding="utf-8"))

    main_entry = next(b for b in data["branches"] if b["name"] == "origin/main")
    assert main_entry["category"] == "SYSTEM_INFRA"
