# Hermes canary image workflow

This document defines the dev-universe fork-only, exact-SHA Hermes canary image build gate.
It builds the full source image from a fresh fork/main checkout and publishes only an immutable GHCR SHA tag.

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

The workflow checks out the exact Hermes source commit provided in `source_sha`, builds the full image from that source tree, and pushes only the immutable SHA tag.
The checkout is fork-specific and does not touch the upstream PR host or any live runtime host.

The build job writes:

- `artifacts/source-sha.txt`
- `artifacts/image-digest.txt`
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

The workflow is fail-closed. A run fails if Trivy reports any fixable HIGH or CRITICAL vulnerability or any secret finding. There is no allowlist.

The security job writes:

- `artifacts/trivy-vuln.json`
- `artifacts/trivy-secret.json`
- `artifacts/canary-manifest.json`
- `artifacts/security-status.json`

## Manifest content

The manifest records:

- source repository
- source SHA
- immutable image reference and digest reference
- the amd64 platform contract
- SBOM artifact paths
- Trivy artifact paths
- the zero-allowlist fail-closed policy for vulnerabilities and secrets

## Why this workflow exists

Earlier partial overlays drifted away from the actual runtime image.
This workflow exists so the canary uses a single, exact source commit and a single immutable GHCR digest rather than a mutable host overlay.
