from __future__ import annotations

import argparse
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

import yaml

AlertGroups = List[Dict[str, Any]]


def _load_rule_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _write_rule_file(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(data, handle, sort_keys=False)


def _extract_groups(data: Dict[str, Any], source: Path) -> AlertGroups:
    if "groups" in data:
        groups = data["groups"]
    else:
        groups = data.get("spec", {}).get("groups")
    if not isinstance(groups, list):
        raise ValueError(f"{source} is missing a groups list")
    return groups


def _ensure_environment_labels(groups: AlertGroups, environment: str) -> AlertGroups:
    updated: AlertGroups = []
    for group in groups:
        group_copy = deepcopy(group)
        rules = group_copy.get("rules")
        if not isinstance(rules, list):
            raise ValueError("invalid alert file: group missing rules array")
        for rule in rules:
            labels = rule.setdefault("labels", {})
            if "environment" not in labels:
                labels["environment"] = environment
        updated.append(group_copy)
    return updated


def render_environment_rules(source_dir: Path, output_dir: Path, environment: str) -> None:
    if not source_dir.is_dir():
        raise ValueError(f"source directory not found: {source_dir}")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    for path in sorted(source_dir.rglob("*.yaml")):
        relative = path.relative_to(source_dir)
        data = _load_rule_file(path)
        groups = _extract_groups(data, path)
        data_copy = deepcopy(data)
        if "spec" in data_copy and isinstance(data_copy["spec"], dict) and "groups" in data_copy["spec"]:
            data_copy["spec"]["groups"] = _ensure_environment_labels(groups, environment)
        else:
            data_copy["groups"] = _ensure_environment_labels(groups, environment)
        _write_rule_file(output_dir / relative, data_copy)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render alert rules with environment labels")
    parser.add_argument("--source", type=Path, default=Path("ops/alerts"), help="Path to the base alert rules")
    parser.add_argument("--output", type=Path, required=True, help="Directory to write rendered rules")
    parser.add_argument("--environment", type=str, default="staging", help="Environment label to inject")
    args = parser.parse_args()

    try:
        render_environment_rules(args.source, args.output, args.environment)
    except Exception as exc:  # pragma: no cover - CLI safety net
        print(f"error: {exc}")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
