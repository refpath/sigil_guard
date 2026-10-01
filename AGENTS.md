# SigilGuard Agent Contract

This file is the canonical repository contract for every coding agent.

## Working Agreements

- Never push branches, tags, commits, or other Git refs. The user performs every
  push manually.
- Never change repository visibility. If work depends on a visibility change,
  report the user-managed blocker and continue independent work.
- Preserve unrelated changes and local client settings. Release tags, package
  publication, and production consumer changes are maintainer-owned operations.
- Use Conventional Commits (`feat`, `fix`, `docs`, `test`, `refactor`, `chore`,
  with an optional scope). Keep commits local.

## Architecture

SigilGuard is a native Elixir Hex library for embedded MCP and agent-tool
security. Host applications own transports, authentication, sandbox execution,
durable storage, and deployment. The library supplies verification, policy,
scanning, audit, vault, and trust-bundle primitives.

The v3 Agent Trust Profile is defined in
[SP.01](docs/specs/SP.01-sigilguard-trust-profile.md). The implementation flows
through `SigilGuard`, the native Elixir backend, trust bundles and attestations,
boundary policy and runtime/MCP gates, then confirmation, audit, and vault APIs.

`SigilGuard.Application` starts `SigilGuard.Runtime` by default. Hosts can set
`runtime: false` and supervise it themselves. Replay and bundle state use
process-global named ETS tables; preserve their supervised ownership and
lifetime. Pure APIs must not acquire hidden process, clock, network, or global
configuration dependencies. Host side effects belong behind behaviours/options.

The Elixir floor and dependency constraints live in [mix.exs](mix.exs). Runtime
dependencies are `:telemetry`, `:nimble_options`, and `:jason` plus OTP/stdlib;
new runtime dependencies require an individually justified design decision.

## Hard Rules

1. No Rust or NIF backend work. Native Elixir is the supported built-in backend.
2. Do not depend on the old upstream project, public service, or hosted registry.
   `sigil` remains the project idiom; old material is historical inspiration and
   compatibility context only.
3. Preserve v3 consumer contracts: `_agent_trust`, `_agent_confirmation`, Agent
   Trust statements, trust bundles, capability manifests, and boundary decisions.
   Removed v2 APIs stay deleted; their mappings belong in
   [MIGRATING-1.0.md](MIGRATING-1.0.md), without permanent compatibility shims.
   A consumer-facing contract change must update the applicable
   [consumer assertions](test/sigil_guard/conformance/consumer_contracts_test.exs)
   and that guide in the same commit.
4. Default trust material is embedded and local; remote fetching is host-owned.
   Core decision paths perform no HTTP. The sanctioned HTTP seam is the
   host-provided `SigilGuard.HTTPClient` behaviour for optional audit anchor
   stores ([SP.05](docs/specs/SP.05-audit-and-release-provenance.md)). There is no
   public registry runtime path.
5. Runtime security decisions must account for phase, origin, sink,
   actor/identity, trust zone, action digest, payload digest, and policy verdict.
   Preserve fail-closed behavior, input bounds, confirmation binding, replay
   resistance, expiry, and key/bundle rollback protection.
6. Every public API needs `@doc` and `@spec`; complex structs need typedocs.
7. Never use `String.to_atom/1` on external input. Use closed maps or
   `String.to_existing_atom/1` only for an already-known atom set.
8. Do not add network calls to core decision paths. Changes to host-owned network
   integrations need a spec defining trust, timeouts, retries, and failures.
9. Keep coverage at or above the 95% floor configured in
   [coveralls.json](coveralls.json). New security modules need negative, tamper,
   replay, expiration, and malformed-input tests. Do not pad coverage, broaden
   skips/excludes, or disable quality checks to obtain a pass. Respect the Credo
   nesting limit in [.credo.exs](.credo.exs); refactor the owning code instead.
10. Never add AI attribution, co-author trailers, or generated-by comments to
    commits or source files. Comments should explain decisions rather than
    restate code.
11. Never write the private consumer project's name or internal module names into
    repository files or commits. Call it "the reference consumer" and use generic
    public contracts and neutral fixture identifiers.

## Guidance and Skills

- Apply [naming guidance](.agents/standards/naming.md) when editing public terms.
- Apply [quality guidance](.agents/standards/quality-gates.md) before committing
  or handing off. [.check.exs](.check.exs) defines the complete application gate;
  report actual executed checks separately from skipped or blocked checks.
- Canonical skills live in tracked `.agents/skills/<name>/SKILL.md`. Select and
  apply them automatically from their descriptions as the task, changed
  mechanism, or delivery stage requires. Do not ask users to invoke skills or
  choose slash commands. Keep implicit invocation enabled.
- Clients without native discovery must read descriptions in `.agents/skills/`,
  select matching skills themselves, and read their `SKILL.md` files. Load linked
  supporting material only when relevant.
- Claude Code discovers skills through ignored individual directory symlinks at
  `.claude/skills/<name>` pointing to `../../.agents/skills/<name>`. Create missing
  links only where no local entry exists. Preserve local entries and repair
  repository-owned dangling links without adding aliases. Keep `.claude/`
  entirely ignored and shared guidance in `.agents/`.

## Design and Documentation

Read affected modules, tests, and the relevant spec rather than the entire docs
tree for every edit. Research external protocol/security facts using primary
sources before making design decisions. Accepted protocol/security designs need
a spec and task entry before broad implementation.

- `docs/research/` owns design evidence, alternatives, and decisions.
- `docs/specs/` owns observable behavior and implementation contracts.
- `docs/tasks/sigil-tasks.md` owns execution status and acceptance criteria;
  completed historical milestones are context, not new work.
- `docs/templates/` holds the existing formats for research, specs, and tasks.
- `guides/` and `notebooks/` explain public consumer behavior.

Size documents to the evidence and decisions needed. Split for coherent ownership
or lifecycle boundaries, not arbitrary word, token, page, or diff limits. Product
runtime bounds remain explicit. Distinguish design reasoning, executed tests,
mutation/coverage measurements, generic consumer checks, and live host evidence.
Absence of findings or a text search is not a security guarantee.
