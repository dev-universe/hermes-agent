from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "ci" / "check_trivy_reports.py"


def load_module():
    spec = importlib.util.spec_from_file_location("check_trivy_reports", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_check_trivy_reports_passes_on_clean_reports(tmp_path):
    module = load_module()
    vuln = tmp_path / "vuln.json"
    secret = tmp_path / "secret.json"
    vuln.write_text(json.dumps({"Results": []}), encoding="utf-8")
    secret.write_text(json.dumps({"Results": []}), encoding="utf-8")

    assert module.check_reports(vuln, secret) == []
    assert module.main(["--vuln-report", str(vuln), "--secret-report", str(secret)]) == 0


def test_check_trivy_reports_blocks_high_critical_and_secret_findings(tmp_path):
    module = load_module()
    vuln = tmp_path / "vuln.json"
    secret = tmp_path / "secret.json"
    vuln.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.20",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2026-1234",
                                "Severity": "HIGH",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": "1.0.1",
                                "Title": "demo vuln",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    secret.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "alpine:3.20",
                        "Secrets": [
                            {
                                "Category": "API key",
                                "Severity": "HIGH",
                                "StartLine": 12,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = module.check_reports(vuln, secret)
    assert any("CVE-2026-1234" in item for item in findings)
    assert any("API key secret" in item for item in findings)
    assert module.main(["--vuln-report", str(vuln), "--secret-report", str(secret)]) == 1


def test_check_trivy_reports_supports_sarif_secret_payloads(tmp_path):
    module = load_module()
    vuln = tmp_path / "vuln.json"
    secret = tmp_path / "secret.sarif"
    vuln.write_text(json.dumps({"Results": []}), encoding="utf-8")
    secret.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "TRIVY-SECRET",
                                "message": {"text": "token leak"},
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    findings = module.check_reports(vuln, secret)
    assert any("TRIVY-SECRET" in item for item in findings)


def test_missing_or_malformed_reports_fail_closed(tmp_path):
    module = load_module()
    vuln = tmp_path / "vuln.json"
    secret = tmp_path / "secret.json"
    vuln.write_text(json.dumps({"Results": []}), encoding="utf-8")

    assert module.main(["--vuln-report", str(vuln), "--secret-report", str(secret)]) == 1
    secret.write_text("not-json", encoding="utf-8")
    assert module.main(["--vuln-report", str(vuln), "--secret-report", str(secret)]) == 1
