# Releasing Relay

Releases are cut by pushing a `vX.Y.Z` tag. The `release` GitHub Actions workflow
(`.github/workflows/release.yml`) then builds cross-platform binaries, publishes
the container image, and produces the supply-chain metadata (SBOM, cosign
signatures, SLSA build provenance) via GoReleaser.

## One-time setup

Configure these repository secrets (Settings → Secrets and variables → Actions):

- `DOCKERHUB_USERNAME` — Docker Hub account that owns `algoryn/relay`.
- `DOCKERHUB_TOKEN` — a Docker Hub access token with push permission.

`GITHUB_TOKEN` is provided automatically. The workflow already requests the
`id-token: write` and `attestations: write` permissions needed for keyless
signing and provenance.

## Cutting a release

1. Make sure `main` is green (CI) and all intended PRs are merged.
2. Update [`CHANGELOG.md`](CHANGELOG.md): rename the `## [Unreleased]` section to
   `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty `## [Unreleased]` above it.
3. Verify locally:
   ```sh
   go test -race ./...
   golangci-lint run
   goreleaser check
   ```
4. Tag and push:
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```
5. Watch the `release` workflow. On success it creates the GitHub release with
   archives, `checksums.txt`, SBOMs, cosign signatures, and attaches SLSA build
   provenance.
6. Verify the artifacts as documented in [`SECURITY.md`](SECURITY.md).

## Cutting `v1.0.0`

`v1.0.0` is the first release under the stability guarantees in the README
(“Versioning & stability”): the YAML config schema and the `/_relay/*` HTTP
surface become the public contract. Before tagging `v1.0.0`, confirm:

- [ ] The [configuration reference](docs/configuration.md) matches the code.
- [ ] The [deployment guide](docs/deployment.md) and Helm chart `appVersion` are current.
- [ ] `CHANGELOG.md` `[1.0.0]` section is complete.
- [ ] Docker Hub secrets are configured.
