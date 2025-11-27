from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

AlertGroups = List[Dict[str, Any]]


class ComparisonError(RuntimeError):
    pass


def _load_groups(path: Path) -> AlertGroups:
    with path.open("r", encoding="utf-8") as handle:
        data: Dict[str, Any] = yaml.safe_load(handle)
    if "groups" in data:
        groups = data["groups"]
    else:
        groups = data.get("spec", {}).get("groups")
    if not isinstance(groups, list):
        raise ComparisonError(f"{path} is missing a groups list")
    return deepcopy(groups)


def _normalize_environment(groups: AlertGroups, context: Path) -> AlertGroups:
    normalized: AlertGroups = []
    for group in groups:
        group_copy = deepcopy(group)
        rules = group_copy.get("rules")
        if not isinstance(rules, list):
            raise ComparisonError(f"{context} group missing rules array")
        for rule in rules:
            labels = rule.get("labels")
            if not isinstance(labels, dict):
                raise ComparisonError(f"{context} rule {rule.get('alert', '<unknown>')} is missing labels")
            environment = labels.get("environment")
            if environment is None:
                raise ComparisonError(f"{context} rule {rule.get('alert', '<unknown>')} missing environment label")
            labels = dict(labels)
            labels["environment"] = "<env>"
            rule["labels"] = labels
        normalized.append(group_copy)
    return normalized


def _collect_yaml_files(directory: Path) -> List[Path]:
    return sorted(directory.rglob("*.yaml"))


def compare_directories(staging_dir: Path, production_dir: Path) -> List[str]:
    if not staging_dir.is_dir():
        raise ComparisonError(f"staging directory not found: {staging_dir}")
    if not production_dir.is_dir():
        raise ComparisonError(f"production directory not found: {production_dir}")

    staging_files = _collect_yaml_files(staging_dir)
    production_files = _collect_yaml_files(production_dir)
    errors: List[str] = []

    staging_map = {path.relative_to(staging_dir): path for path in staging_files}
    production_map = {path.relative_to(production_dir): path for path in production_files}

    all_paths = sorted(set(staging_map) | set(production_map))
    for rel_path in all_paths:
        staging_path = staging_map.get(rel_path)
        production_path = production_map.get(rel_path)

        if staging_path is None:
            errors.append(f"missing staging file for {rel_path}")
            continue
        if production_path is None:
            errors.append(f"missing production file for {rel_path}")
            continue

        staging_groups = _normalize_environment(_load_groups(staging_path), staging_path)
        production_groups = _normalize_environment(_load_groups(production_path), production_path)
        if staging_groups != production_groups:
            errors.append(f"drift detected in {rel_path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare staging vs production alert rules after normalization")
    parser.add_argument("--staging", type=Path, required=True, help="Rendered staging alert directory")
    parser.add_argument("--production", type=Path, required=True, help="Rendered production alert directory")
    args = parser.parse_args()

    try:
        errors = compare_directories(args.staging, args.production)
    except ComparisonError as exc:  # pragma: no cover - CLI safety net
        print(f"error: {exc}")
        return 1
    if errors:
        for error in errors:
            print(f"::error ::{error}")
        return 1
    print("Staging and production alert rules match (environment label differences ignored).")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
