# Contributing To SigilGuard

## Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/sigil_guard.git`
3. Install dependencies: `mix setup`
4. Create a branch: `git checkout -b feat/short-description`

## Development

```bash
mix setup          # Install dependencies
mix test           # Run tests
mix lint           # Run linters (format, credo, dialyzer)
./bin/check         # Run the clean-clone-safe complete gate
mix docs           # Generate documentation
mix bench          # Run benchmarks
```

## Code Quality

Before you open a pull request, run `./bin/check`. It bootstraps the locked
dependency graph and enforces every required check, including the production
package build. The focused commands below are faster while iterating:

- [ ] Tests cover new behavior and pass: `mix test`
- [ ] Code is formatted: `mix format`
- [ ] Credo passes: `mix credo --strict`
- [ ] Dialyzer passes: `mix dialyzer`
- [ ] Documentation is updated
- [ ] The pull request description says what changed and why

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new features
- `fix:` bug fixes
- `docs:` documentation changes
- `refactor:` code refactoring
- `test:` test additions or changes
- `chore:` maintenance tasks

## Releasing

Releases are managed by maintainers using git_ops:

1. Ensure the complete gate passes: `./bin/check`
2. Run `mix release` (alias for `mix git_ops.release`). It updates the
   changelog, bumps the version, commits, and tags.
3. Push with tags: `git push --follow-tags`
4. CI verifies the exact version tag and commit, then validates, attests, and
   publishes through isolated jobs

The publish workflow builds a Hex tarball and SPDX SBOM after the complete gate,
signs a release predicate that names both artifacts and their SHA-256 digests,
and verifies both provenance forms. The environment-scoped publish job has no
OIDC or attestation-write permission; it receives the Hex key only for the
publish step, requires a fresh build to equal the attested tar, then compares
the Hex registry download byte for byte. Before any release, administrators
must complete the tag-ruleset, `hex-publish` protection, environment-secret,
and `main` protection checklist in `guides/release-and-anchoring.md`; release
verification rejects an unprotected tag.

## Questions

Open an issue for questions or discussions.
