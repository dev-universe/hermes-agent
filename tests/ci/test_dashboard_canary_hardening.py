from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/hermes-canary-image.yml"
FRAGMENT = ROOT / ".github/docker/dashboard-canary.fragment"
RENDERER = ROOT / ".github/scripts/render_dashboard_canary_dockerfile.py"


def _load_renderer():
    spec = importlib.util.spec_from_file_location("render_dashboard_canary", RENDERER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_renderer_names_exact_runtime_stage_and_records_hashes(tmp_path: Path) -> None:
    module = _load_renderer()
    source = tmp_path / "Dockerfile"
    source.write_text(
        "FROM debian:13.4 AS sqlite_build\nRUN true\nFROM debian:13.4\nRUN true\n",
        encoding="utf-8",
    )
    output = tmp_path / "Dockerfile.canary"
    artifacts = tmp_path / "artifacts"
    module.render(source, FRAGMENT, output, artifacts)
    rendered = output.read_text(encoding="utf-8")
    assert rendered.count("AS hermes_runtime") == 1
    assert "debian:13.5@sha256:d07d1b51" in rendered
    assert "FROM hermes_runtime AS dashboard_canary" in rendered
    assert rendered.endswith("runtime\"\n")
    assert sorted(path.name for path in artifacts.iterdir()) == [
        "hardening-fragment.sha256",
        "rendered-dockerfile.sha256",
        "source-dockerfile.sha256",
    ]


def test_hardening_fragment_pins_fixes_and_removes_build_tooling() -> None:
    fragment = FRAGMENT.read_text(encoding="utf-8")
    for token in (
        "2.41.5-0+deb13u1",
        "libcap2=1:2.75-10+deb13u1+b1",
        "tornado-6.5.8",
        "547d63f450d570c14fe0e8db2cfb14c9bbd1c2503b4a6612586267955aa47b58",
        "/opt/hermes/node_modules",
        "/usr/local/lib/node_modules/npm",
        "/usr/local/bin/uvx",
    ):
        assert token in fragment


def test_workflow_consumes_generated_hardened_dockerfile_and_smoke_gates_security() -> None:
    workflow_text = WORKFLOW.read_text(encoding="utf-8")
    workflow = yaml.safe_load(workflow_text)
    jobs = workflow["jobs"]
    build_steps = jobs["build"]["steps"]
    build = next(step for step in build_steps if step.get("id") == "build_image")
    assert build["with"]["file"] == "./hermes-source/Dockerfile.canary"
    assert build["with"]["target"] == "dashboard_canary"
    assert any(step.get("id") == "render_canary_dockerfile" for step in build_steps)
    assert jobs["security"]["needs"] == ["build", "smoke"]
    smoke_text = str(jobs["smoke"])
    assert "dashboard --help" in smoke_text
    assert "/api/status" in smoke_text
    assert "/api/sessions" in smoke_text
    assert "tornado.version == \"6.5.8\"" in smoke_text
    assert "HERMES_DASHBOARD_BASIC_AUTH_USERNAME" in smoke_text
    assert "HERMES_DASHBOARD_BASIC_AUTH_PASSWORD" in smoke_text
    assert "HERMES_DASHBOARD_BASIC_AUTH_SECRET" in smoke_text
    assert "HERMES_DASHBOARD_OAUTH_CLIENT_ID" not in smoke_text
    assert "::add-mask::" in smoke_text
    assert 'container_id=""' in smoke_text
    assert '${container_id:-}' in smoke_text
    assert "docker top" in smoke_text
    assert "s6-svstat /run/service/dashboard" not in smoke_text
    assert "docker logs" not in smoke_text
    assert "sleep infinity" not in smoke_text
    assert "--host 0.0.0.0 --port 9119 --no-open" in smoke_text
    assert "HERMES_DASHBOARD=1" not in smoke_text
    assert "HERMES_DASHBOARD_HOST" not in smoke_text
    assert "allowlist': []" in workflow_text
