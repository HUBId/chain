import textwrap
from pathlib import Path

import pytest

from tools.alerts.compare_environment_rules import ComparisonError, compare_directories
from tools.alerts.render_environment_rules import render_environment_rules


def _write_rule(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")


def test_render_injects_environment_label(tmp_path: Path) -> None:
    source = tmp_path / "source"
    rendered = tmp_path / "rendered"

    _write_rule(
        source / "consensus" / "finality.yaml",
        """
        groups:
          - name: demo
            rules:
              - alert: MissingEnvironment
                expr: vector(1)
                labels:
                  severity: warning
              - alert: PreservesEnvironment
                expr: vector(1)
                labels:
                  severity: warning
                  environment: "{{ $labels.environment }}"
        """,
    )

    render_environment_rules(source, rendered, "staging")

    rendered_data = (rendered / "consensus" / "finality.yaml").read_text(encoding="utf-8")
    assert "environment: staging" in rendered_data
    assert "{{ $labels.environment }}" in rendered_data


def test_compare_directories_detects_drift(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    production = tmp_path / "production"

    _write_rule(
        staging / "rpc.yaml",
        """
        groups:
          - name: rpc
            rules:
              - alert: RpcAvailability
                expr: vector(1)
                labels:
                  severity: critical
                  environment: staging
        """,
    )
    _write_rule(
        production / "rpc.yaml",
        """
        groups:
          - name: rpc
            rules:
              - alert: RpcAvailability
                expr: vector(2)
                labels:
                  severity: critical
                  environment: production
        """,
    )

    errors = compare_directories(staging, production)
    assert errors == ["drift detected in rpc.yaml"]


def test_compare_directories_requires_environment_label(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    production = tmp_path / "production"

    _write_rule(
        staging / "rpc.yaml",
        """
        groups:
          - name: rpc
            rules:
              - alert: RpcAvailability
                expr: vector(1)
                labels:
                  severity: critical
                  environment: staging
        """,
    )
    _write_rule(
        production / "rpc.yaml",
        """
        groups:
          - name: rpc
            rules:
              - alert: RpcAvailability
                expr: vector(1)
                labels:
                  severity: critical
        """,
    )

    with pytest.raises(ComparisonError):
        _ = compare_directories(staging, production)
