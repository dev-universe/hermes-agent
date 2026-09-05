#!/usr/bin/env python3
"""Render the exact-source Hermes Dockerfile with a reviewed canary stage."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

SOURCE_RUNTIME_FROM = "FROM debian:13.4\n"
PINNED_RUNTIME_FROM = (
    "FROM debian:13.5@sha256:"
    "d07d1b51c39f51188e60be9b64e6bf769fa94e187f092bc32b91305cfa34ba5a "
    "AS hermes_runtime\n"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def render(source: Path, fragment: Path, output: Path, artifact_dir: Path) -> None:
    source_bytes = source.read_bytes()
    fragment_bytes = fragment.read_bytes()
    source_text = source_bytes.decode("utf-8")
    if source_text.count(SOURCE_RUNTIME_FROM) != 1:
        raise ValueError("exact source runtime FROM contract changed")
    rendered = source_text.replace(SOURCE_RUNTIME_FROM, PINNED_RUNTIME_FROM, 1)
    rendered = rendered.rstrip() + "\n\n" + fragment_bytes.decode("utf-8").lstrip()
    output.write_text(rendered, encoding="utf-8")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "source-dockerfile.sha256").write_text(
        f"{_sha256(source_bytes)}  Dockerfile\n", encoding="utf-8"
    )
    (artifact_dir / "hardening-fragment.sha256").write_text(
        f"{_sha256(fragment_bytes)}  dashboard-canary.fragment\n", encoding="utf-8"
    )
    (artifact_dir / "rendered-dockerfile.sha256").write_text(
        f"{_sha256(rendered.encode())}  Dockerfile.canary\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fragment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        render(args.source, args.fragment, args.output, args.artifact_dir)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
