from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "hermes-canary-image.yml"


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
        "steps.build_image.outputs.metadata",
        "build_metadata_ref",
        "Checkout trusted hardening recipe",
        "Render dashboard-only canary Dockerfile",
        "hermes-source/Dockerfile.canary",
        "target: dashboard_canary",
        "source-dockerfile.sha256",
        "hardening-fragment.sha256",
        "rendered-dockerfile.sha256",
        "Validate dashboard-only runtime",
        "smoke-status.json",
        "Checkout trusted workflow source",
        "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
        "ref: ${{ github.sha }}",
        "persist-credentials: false",
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
        "build_metadata': os.environ['BUILD_METADATA_REF']",
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
    if "metadata-file:" in workflow:
        errors.append("workflow must not use unsupported metadata-file input")
    if "build_metadata': os.environ['BUILD_METADATA_REF']" not in workflow:
        errors.append("workflow missing build metadata reference")
    if "workflow_run" not in workflow:
        errors.append("workflow missing workflow run reference")
    if "if: steps.enforce_policy.outcome == 'success'" not in workflow:
        errors.append("workflow must only write the success manifest after policy pass")
    if "canary-image-release.yml" in workflow:
        errors.append("workflow must not reference the duplicate canary-image-release filename")
    if "file: ./hermes-source/Dockerfile\n" in workflow:
        errors.append("workflow must not build the unhardened exact-source Dockerfile directly")

    for token in [
        "exact application source",
        "dashboard-only hardening recipe",
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
    assert WORKFLOW == ROOT / ".github" / "workflows" / "hermes-canary-image.yml"
    assert WORKFLOW.name == "hermes-canary-image.yml"
    assert validate_contract() == []


def test_hermes_canary_image_workflow_security_env_is_static_literals() -> None:
    workflow = yaml.safe_load(read(".github/workflows/hermes-canary-image.yml"))
    security_steps = [step["name"] for step in workflow["jobs"]["security"]["steps"]]
    assert security_steps.index("Checkout trusted workflow source") < security_steps.index(
        "Enforce fail-closed Trivy policy"
    )
    assert workflow["jobs"]["security"]["env"] == {
        "IMAGE_DIGEST_REF": "${{ needs.build.outputs.image_digest_ref }}",
        "IMAGE_REF": "${{ needs.build.outputs.image_ref }}",
        "BUILD_METADATA_REF": "${{ needs.build.outputs.build_metadata_ref }}",
        "SOURCE_REPOSITORY": "https://github.com/dev-universe/hermes-agent.git",
        "SOURCE_SHA": "${{ inputs.source_sha }}",
        "IMAGE_REPOSITORY": "ghcr.io/dev-universe/hermes-agent-canary",
    }


def test_hermes_canary_image_workflow_rejects_base_repo_reference():
    workflow = read(".github/workflows/hermes-canary-image.yml").replace(
        "ghcr.io/dev-universe/hermes-agent-canary",
        "ghcr.io/dev-universe/hermes-agent",
    )
    assert "ghcr.io/dev-universe/hermes-agent-canary" not in workflow
    assert "ghcr.io/dev-universe/hermes-agent:sha-${{ inputs.source_sha }}" in workflow
    assert "provenance: true" in workflow
