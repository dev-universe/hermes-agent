#!/usr/bin/env python3
"""Fail the canary release on blocked Trivy findings.

The workflow keeps Trivy itself on an evidence-preserving exit code 0 so JSON
and SARIF artifacts survive even when the scan finds problems. This parser is
the deterministic gate: it fails on any HIGH/CRITICAL vulnerability finding in
the vulnerability report and on any secret finding in the secret report.

Missing or null Trivy ``Results`` arrays are tolerated, but missing files and
malformed reports fail closed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"report missing: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"report is not valid JSON: {path}") from exc


def _as_dict(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} is malformed")
    return value


def _json_results(doc: Any, *, report_name: str) -> list[dict[str, Any]]:
    if not isinstance(doc, dict):
        raise ValueError(f"{report_name} is malformed")
    results = doc.get("Results")
    if results is None:
        return []
    if not isinstance(results, list):
        raise ValueError(f"{report_name} Results array is malformed")
    return [_as_dict(item, label=f"{report_name} result") for item in results]


def _blockable_vulns(report: dict[str, Any]) -> list[str]:
    blocked: list[str] = []
    for result in _json_results(report, report_name="vulnerability report"):
        target = str(result.get("Target", "unknown target"))
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            raise ValueError("vulnerability entries are malformed")
        for vuln in vulns:
            vuln = _as_dict(vuln, label="vulnerability entry")
            severity = str(vuln.get("Severity", "")).upper()
            if severity in {"HIGH", "CRITICAL"}:
                vuln_id = str(vuln.get("VulnerabilityID", "unknown"))
                title = str(vuln.get("Title", "")).strip()
                status = str(vuln.get("Status", "")).strip()
                detail = f"{vuln_id} ({severity}) on {target}"
                if title:
                    detail = f"{detail}: {title}"
                if status:
                    detail = f"{detail} [{status}]"
                blocked.append(detail)
    return blocked


def _secret_findings(report: dict[str, Any]) -> list[str]:
    blocked: list[str] = []
    for result in _json_results(report, report_name="secret report"):
        target = str(result.get("Target", "unknown target"))
        secrets = result.get("Secrets")
        if secrets is None:
            continue
        if not isinstance(secrets, list):
            raise ValueError("secret entries are malformed")
        for secret in secrets:
            secret = _as_dict(secret, label="secret entry")
            category = str(secret.get("Category", secret.get("Type", "secret"))).strip()
            severity = str(secret.get("Severity", "")).strip()
            line = str(secret.get("StartLine", secret.get("Line", "")))
            detail = f"{category} secret on {target}"
            if severity:
                detail = f"{detail} ({severity})"
            if line and line != "None":
                detail = f"{detail} line {line}"
            blocked.append(detail)
    return blocked


def _sarif_secret_findings(report: Any) -> list[str]:
    if not isinstance(report, dict):
        raise ValueError("secret report is malformed")
    runs = report.get("runs")
    if runs is None:
        return []
    if not isinstance(runs, list):
        raise ValueError("secret SARIF runs are malformed")

    blocked: list[str] = []
    for run in runs:
        run = _as_dict(run, label="secret SARIF run")
        results = run.get("results")
        if results is None:
            continue
        if not isinstance(results, list):
            raise ValueError("secret SARIF results are malformed")
        for result in results:
            result = _as_dict(result, label="secret SARIF result")
            rule_id = str(result.get("ruleId", "secret")).strip()
            message = _as_dict(result.get("message", {}), label="secret SARIF message")
            text = str(message.get("text", "")).strip()
            detail = rule_id
            if text:
                detail = f"{detail}: {text}"
            blocked.append(detail)
    return blocked


def check_reports(vuln_report: Path, secret_report: Path) -> list[str]:
    """Return all blocking findings from the supplied Trivy reports."""
    vuln_doc = _load_json(vuln_report)
    secret_doc = _load_json(secret_report)

    findings: list[str] = []
    findings.extend(_blockable_vulns(vuln_doc))
    findings.extend(_secret_findings(secret_doc))
    findings.extend(_sarif_secret_findings(secret_doc))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail on blocked Trivy findings.")
    parser.add_argument("--vuln-report", type=Path, required=True)
    parser.add_argument("--secret-report", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        findings = check_reports(args.vuln_report, args.secret_report)
    except ValueError as exc:
        print(f"::error::{exc}")
        return 1

    if findings:
        print("::error::blocked Trivy findings detected")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print("Trivy reports are clean.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
