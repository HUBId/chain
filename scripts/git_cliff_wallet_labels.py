#!/usr/bin/env python3
"""Augments git-cliff commit messages with wallet labels from GitHub PR metadata."""
from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import typing
import urllib.error
import urllib.request

REPO = os.environ.get("GIT_CLIFF_REPO", "ava-labs/chain")
CACHE_PATH = pathlib.Path(".git") / "wallet_label_cache.json"
PR_RE = re.compile(r"\(#(\d+)\)")


def load_cache() -> dict[str, typing.Any]:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def save_cache(cache: dict[str, typing.Any]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(cache))


def fetch_labels(pr_number: str) -> list[str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return []
    url = f"https://api.github.com/repos/{REPO}/issues/{pr_number}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError):
        return []
    labels = payload.get("labels", [])
    names: list[str] = []
    for entry in labels:
        name = entry.get("name")
        if isinstance(name, str):
            names.append(name)
    return names


def main() -> None:
    text = sys.stdin.read()
    match = PR_RE.search(text)
    if not match:
        sys.stdout.write(text)
        return

    pr_number = match.group(1)
    cache = load_cache()
    labels = cache.get(pr_number)
    if not isinstance(labels, list):
        labels = fetch_labels(pr_number)
        if labels:
            cache[pr_number] = labels
            save_cache(cache)

    wallet_labels = sorted({label for label in labels if label.startswith("wallet::")})
    if not wallet_labels:
        sys.stdout.write(text)
        return

    trailer = f"Wallet-Labels: {','.join(wallet_labels)}"
    if trailer in text:
        sys.stdout.write(text)
        return

    if text.endswith("\n"):
        result = f"{text}{trailer}\n"
    else:
        result = f"{text}\n{trailer}\n"
    sys.stdout.write(result)


if __name__ == "__main__":
    main()
