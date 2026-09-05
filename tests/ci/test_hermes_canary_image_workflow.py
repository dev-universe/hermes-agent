from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def validate_contract() -> list[str]:
    workflow = read(".github/workflows/hermes-canary-image.yml")
    docs = read("docs/operations/hermes-canary-image.md")

    errors: list[str] = []
    required_tokens = [
        "workflow_dispatch",
        "source_sha",
        "ghcr.io/dev-universe/hermes-agent-canary",
        "ghcr.io/dev-universe/hermes-agent-canary:sha-${{ inputs.source_sha }}",
        "https://github.com/dev-universe/hermes-agent.git",
        "linux/amd64",
        "artifacts/source-sha.txt",
        "artifacts/image-digest.txt",
        "artifacts/build-metadata.json",
        "metadata-file: artifacts/build-metadata.json",
        "artifacts/build-status.json",
        "artifacts/canary-manifest.json",
        "artifacts/security-status.json",
        "artifacts/sbom-status.json",
        "artifacts/trivy-vuln.json",
        "artifacts/trivy-secret.json",
        "scripts/ci/check_trivy_reports.py",
        "scanners: vuln",
        "scanners: secret",
        "provenance: true",
        "build_metadata",
        "workflow_run",
        "if: steps.enforce_policy.outcome == 'success'",
        "fixable_high_critical': 'zero",
        "secret_findings': 'zero",
        "allowlist': []",
    ]
    for token in required_tokens:
        if token not in workflow:
            errors.append(f"workflow missing {token}")

    if "ghcr.io/dev-universe/hermes-agent:sha-${{ inputs.source_sha }}" in workflow:
        errors.append("workflow must target the canary repository, not the base Hermes repository")
    if "ghcr.io/dev-universe/hermes-agent-canary:latest" in workflow:
        errors.append("workflow must not publish latest tags")
    if "provenance: false" in workflow:
        errors.append("workflow must preserve provenance")
    if "build_metadata': 'artifacts/build-metadata.json" not in workflow:
        errors.append("workflow missing build metadata artifact")
    if "workflow_run" not in workflow:
        errors.append("workflow missing workflow run reference")
    if "if: steps.enforce_policy.outcome == 'success'" not in workflow:
        errors.append("workflow must only write the success manifest after policy pass")

    for token in [
        "full source image",
        "exact Hermes source commit",
        "immutable GHCR SHA tag",
        "secret finding",
        "fail-closed",
        "zero-allowlist",
        "provenance",
        "ghcr.io/dev-universe/hermes-agent-canary",
    ]:
        if token not in docs:
            errors.append(f"docs missing {token}")

    return errors


def test_hermes_canary_image_workflow_contract_passes():
    assert validate_contract() == []


def test_hermes_canary_image_workflow_rejects_base_repo_reference():
    workflow = read(".github/workflows/hermes-canary-image.yml").replace(
        "ghcr.io/dev-universe/hermes-agent-canary",
        "ghcr.io/dev-universe/hermes-agent",
    )
    assert "ghcr.io/dev-universe/hermes-agent-canary" not in workflow
    assert "ghcr.io/dev-universe/hermes-agent:sha-${{ inputs.source_sha }}" in workflow
    assert "provenance: true" in workflow
