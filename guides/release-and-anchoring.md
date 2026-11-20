# Release Verification and WORM Anchoring

Verifying a release's SBOM and provenance, and running a write-once/read-many
(WORM) or append-only audit anchor store, are host operations. SigilGuard ships
the primitives; the host owns transport, storage, and CI. The library performs
no network calls of its own in any decision path.

## Verifying a release SBOM

SigilGuard generates an SPDX 2.3 SBOM with the built-in Mix task. Generation
reads the Mix project, `mix.lock`, the `hex_metadata.config` of each locked
runtime dependency under `deps/`, and the checked-out Git revision. It makes
no network call, so fetch the dependencies first:

```bash
mix deps.get
mix sigil_guard.sbom --output dist/sigil_guard.spdx.json
```

A runtime dependency whose `hex_metadata.config` is missing, names another
version, or lists no license fails generation with
`{:invalid_runtime_dependency_metadata, package}`.

Verification has two levels. **Structural** verification compares the
document with what the task would generate for the Mix project it runs in:
the project name and version, the lockfile, the fetched dependency metadata,
and the Git revision bound into the document namespace. Run it in the
`sigil_guard` checkout the SBOM was generated from:

```bash
mix sigil_guard.sbom --verify dist/sigil_guard.spdx.json
```

**Digest** verification also binds the file to the exact bytes attested
in the release provenance (the SLSA build-provenance subject and the `artifacts`
list under the signed predicate's `release` object). Pass the digest recorded
in the provenance, not one computed from the file being checked; `shasum`
prints the local value for comparison:

```bash
shasum -a 256 dist/sigil_guard.spdx.json
mix sigil_guard.sbom --verify dist/sigil_guard.spdx.json \
  --sha256 <expected-sha256-from-provenance>
```

If the SBOM on disk has drifted from the attested bytes, verification fails
fast with `:sbom_digest_mismatch` before any structural check runs. The digest
comparison is case-insensitive on the expected value.

Verify the build provenance with the GitHub CLI and gate publication on the
result:

```bash
gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard
gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard \
  --predicate-type https://sigilguard.dev/attestation/release/v1
```

### Consumer-side verification in CI

A downstream consumer gates its own build on the signed evidence before
trusting the release. `gh attestation verify` hashes the downloaded file and
accepts it only when a signed attestation names that digest, so these
commands bind the tarball and the SBOM bytes to the release:

```yaml
- name: Verify sigil_guard release
  env:
    GH_TOKEN: ${{ github.token }}
  run: |
    gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard
    gh attestation verify sigil_guard-1.0.0.spdx.json --repo refpath/sigil_guard
    gh attestation verify sigil_guard-1.0.0.tar --repo refpath/sigil_guard \
      --predicate-type https://sigilguard.dev/attestation/release/v1
    gh attestation verify sigil_guard-1.0.0.spdx.json --repo refpath/sigil_guard \
      --predicate-type https://sigilguard.dev/attestation/release/v1
```

`mix sigil_guard.sbom --verify` is not a consumer-side check. It compares the
document with the Mix project it runs in, so inside a consumer project it
fails with `:invalid_document_name`. A `--sha256` value computed from the
same file can never mismatch; take the expected digest from the signed
release predicate (`release.artifacts[].sha256`). To repeat the structural
check, run it in a `sigil_guard` checkout of the released tag after
`mix deps.get`.

The tagged-release workflow accepts only the exact Mix-project version tag at
the triggering commit. It produces build provenance with `actions/attest`, then
signs the predicate from `mix sigil_guard.release_statement` against both the
tarball and SBOM. The predicate's `release` object records the package, version,
artifact names, and SHA-256 values. Both predicate types are verified before the
environment-scoped publish job starts. Release verification also fails unless
GitHub reports the exact version tag as protected by a tag ruleset. The publish
job requires a fresh Hex build and the downloaded registry tar to match the
attested package byte for byte.

### Required GitHub release settings

Workflow YAML cannot create or prove owner-managed repository protections.
Before releasing, an administrator must:

1. activate a ruleset covering `v*` tags so `github.ref_protected` is `true`;
2. create the `hex-publish` environment, require approval by the library owner
   (`futhr`), allow the owner to approve their own releases, disable
   protection-rule bypass, and restrict deployment tags to `v*`;
3. store `HEX_API_KEY` as an environment secret, or use an existing repository
   secret when the library owner explicitly authorizes publication; and
4. protect `main` with required pull-request review and the complete CI checks.

Releases initiated by other maintainers still require the owner's approval.

Without the protected tag the workflow fails during release-identity
verification. Without the environment protections, the workflow declaration
alone is not a protected publication boundary and the release must not proceed.

## Implementing a WORM / append-only anchor store

Audit checkpoints and exports are the tamper-evidence layer; anchoring writes a
compact receipt to external storage, so removing events that an anchored
checkpoint covers becomes detectable. Events appended after the latest anchor
are unprotected until the next one. `SigilGuard.Audit.Anchor.Store.LocalFile`
appends to a local file; for durable WORM storage (object-lock buckets,
transparency logs, WORM appliances) a host provides an HTTP endpoint and reaches
it through the `SigilGuard.Audit.Anchor.Store.HTTP` adapter plus a
`SigilGuard.HTTPClient`.

### The HTTP client seam

The anchor HTTP store makes no network calls itself. It routes every request
through a host-provided `SigilGuard.HTTPClient`, the library's only sanctioned
HTTP seam. Configure it per call (`http_client:` in the store options) or in the
application environment:

```elixir
# config/runtime.exs
config :sigil_guard, :http_client, MyApp.AnchorHTTPClient
```

```elixir
defmodule MyApp.AnchorHTTPClient do
  @behaviour SigilGuard.HTTPClient

  @impl true
  def request(method, url, headers, body, opts) do
    # Honor opts[:timeout]; return {:ok, %{status:, headers:, body:}} or
    # {:error, reason}. Retries, if any, live here within the timeout budget.
    MyApp.HTTP.request(method, url, headers, body, timeout: opts[:timeout])
  end
end
```

With no resolvable client, the store fails closed with
`:http_client_not_configured` at first use.

### Requiring WORM semantics

A WORM store MUST prove the object cannot be overwritten. Pass `require_worm:
true` so the store rejects any receipt unless the remote service explicitly
returns `"worm": true`, and require a signed receipt so the provenance is
verifiable offline:

```elixir
alias SigilGuard.Audit.Anchor.Store

{:ok, receipt} =
  Store.put(Store.HTTP, anchor,
    url: "https://audit.example.internal",
    require_worm: true,
    require_receipt_signature: true,
    receipt_public_key_b64u: worm_service_public_key
  )
```

`Store.fetch/3` reads a record back by receipt or digest and rejects it unless
its canonical digest matches the request. When it falls back to a receipt URI,
a hostname must have an exact entry in `:receipt_url_hosts`, and private,
loopback, and link-local targets are rejected with `:unsafe_receipt_url`;
`allow_private_receipt_url: true` lifts both checks. Bodies over
`:max_body_bytes` (default 1 MiB) fail `:response_too_large`.

The remote endpoint contract (paths, request body, receipt shape) is documented
on `SigilGuard.Audit.Anchor.Store.HTTP`; a WORM adapter is that endpoint backed
by object-lock or append-only storage.
