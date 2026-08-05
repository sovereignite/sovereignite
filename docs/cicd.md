# CI/CD

GitHub Actions workflows build and push images to `ghcr.io/sovereignite/sovereignite`.
Per-service workflows trigger only on their own code paths.

## Shared Workflow

`.github/workflows/build-service.yaml` — reusable workflow that:
1. Checks out code
2. Sets up Go from `go.mod`
3. Installs `ko`
4. Logs into GHCR
5. Builds and pushes the image with `ko-action`

## Per-Service Workflows

Each service has its own caller workflow (e.g. `.github/workflows/build-keymanager.yaml`)
with narrow path triggers matching only that service's code.
