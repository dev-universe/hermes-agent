# Hermes canary image workflow

This document defines the dev-universe fork-only, exact-SHA Hermes canary image build gate.
It builds the exact application source through a committed dashboard-only hardening recipe and publishes only an immutable GHCR SHA tag. Build provenance is preserved and referenced in the release manifest.

## Workflow entrypoint

- Workflow file: `.github/workflows/hermes-canary-image.yml`
- Trigger: `workflow_dispatch`
- Required input: `source_sha`
- Source repository: `https://github.com/dev-universe/hermes-agent.git`
- Registry: GHCR only
- Immutable tag: `ghcr.io/dev-universe/hermes-agent-canary:sha-<source_sha>`
- Platform: `linux/amd64`
- Forbidden tag policy: never publish `latest`

## Build contract

The workflow checks out the exact Hermes application source commit provided in `source_sha`, verifies that checkout, then renders `hermes-source/Dockerfile.canary` from the exact source Dockerfile plus the reviewed hardening fragment. It builds only the `dashboard_canary` target and pushes only the immutable SHA tag. The source Dockerfile, hardening fragment, and rendered Dockerfile hashes are recorded separately.
The checkout is fork-specific and does not touch the upstream PR host or any live runtime host.

The build job writes:

- `artifacts/source-sha.txt`
- `artifacts/source-dockerfile.sha256`
- `artifacts/hardening-fragment.sha256`
- `artifacts/rendered-dockerfile.sha256`
- `artifacts/image-digest.txt`
- `artifacts/build-metadata.json`
- `artifacts/build-status.json`

## SBOM contract

The SBOM job pulls the immutable digest produced by the build job and generates both of the following artifacts from the pushed image:

- `artifacts/hermes.spdx.json`
- `artifacts/hermes.cyclonedx.json`
- `artifacts/sbom-status.json`

## Vulnerability and secret policy

The security job scans the immutable digest twice:

1. JSON output for fixable HIGH/CRITICAL vulnerabilities
2. JSON output for secret findings

The workflow is fail-closed. A run fails if Trivy reports any fixable HIGH or CRITICAL vulnerability or any secret finding. There is no allowlist. Success manifest generation happens only after the policy step passes; failure status and evidence remain always-uploaded.

The security job writes:

- `artifacts/trivy-vuln.json`
- `artifacts/trivy-secret.json`
- `artifacts/canary-manifest.json`
- `artifacts/security-status.json`

The separate smoke job writes `artifacts/smoke-status.json` and runs CLI, tool-removal, Tornado-version, dashboard status, and unauthenticated-session checks against the pushed digest. Build metadata remains in the build artifact and is referenced by path and registry attestation from the final manifest.

## Manifest content

The manifest records:

- source repository
- source SHA
- exact source commit SHA
- immutable GHCR SHA tag and digest reference
- workflow run ID / attempt / URL
- provenance reference
- the amd64 platform contract
- SBOM artifact paths
- Trivy artifact paths
- the zero-allowlist fail-closed policy for vulnerabilities and secrets

## Why this workflow exists

Earlier partial overlays drifted away from the actual runtime image.
This workflow exists so the canary uses a single, exact source commit and a single immutable GHCR digest rather than a mutable host overlay.
