# SigilGuard Benchmarks

[Benchee](https://hexdocs.pm/benchee) suites for the calls a host makes at a
boundary: scanning, the runtime gate, streaming, the tool gateway,
confirmation tokens, attestations, trust bundles, agent-to-agent trust, audit
evidence, and the primitives under them. The methodology, the scenario matrix,
and the fairness rules are specified in `docs/specs/SP.15` of the source
repository.

```sh
mix bench            # every suite, the summary page, and benchmarks.json
mix bench.scanner    # one suite and its page
mix bench --smoke    # tiny budgets, written to bench/output/smoke/
mix bench.corpus     # regenerate bench/corpus/ from the fixed seed
mix run bench/compare.exs
```

Each suite writes a Markdown report to `bench/output/`. The reports are the
Performance section of the generated documentation, and they are committed so
that `mix docs` works on a fresh clone. Run the suites again and commit the
reports when a timed path changes.

| Suite | Writes | Measures |
| --- | --- | --- |
| `scanner.exs` | `output/scanner.md` | Secret scanning of clean and hit text at 1 KiB, 64 KiB and 1 MiB; scan and redact; the quarantine inspector; pattern set resolution |
| `gate.exs` | `output/gate.md` | `Runtime.Gate.evaluate/3` on the allow, block, redact and quarantine paths; the risk and trust ladder; the policy kernel; a policy file with an output contract; repo policy |
| `stream.exs` | `output/stream.md` | `Runtime.Stream` over 64 KiB in 512-byte chunks with a secret across a chunk boundary, against one gate pass over the same bytes |
| `gateway.exs` | `output/gateway.md` | `ToolGateway.guard_request/3` plain, with a pinned manifest, and with a required attestation; `guard_result/3`; capability manifests; a physical-effect request and its admission check |
| `confirmation.exs` | `output/confirmation.md` | The token digest, issuing and verifying a token, and a gateway request with an accepted token |
| `attestation.exs` | `output/attestation.md` | Digests, `from_decision/3`, validation, signing, and verification against a key map and a trust bundle role |
| `trust_bundle.exs` | `output/trust_bundle.md` | Cold verification, load, the warm cache read, and pattern sets of a bundle with two delegations and ten patterns |
| `agent_trust.exs` | `output/agent_trust.md` | Agent card sign, verify and digest; attested requests and responses; response verification with every binding |
| `audit.exs` | `output/audit.md` | Append, chain verification, checkpoints, inclusion and consistency proofs, and export |
| `primitives.exs` | `output/primitives.md` | Canonical JSON encoding and decoding, hashing, identifier checks, vault reads, replay detection, and telemetry attributes |

`mix bench` also writes `output/benchmarks.md`, a summary with every scenario,
and `output/benchmarks.json`, which `bench/compare.exs` checks against
`bench/baseline.json`.

## Reading The Numbers

Every scenario runs with two seconds of warmup, five seconds of measurement
and two seconds of memory measurement. Each page records the machine, the
Elixir and OTP versions, the library version and commit, and the Benchee
configuration. A measurement describes that machine. It is not a guarantee,
and numbers from two machines are not comparable.

Run the suites without builds, tests, or other heavy work beside them.
Scenarios that take microseconds vary by several percent between runs on a
workstation; compare complete runs on the same machine and versions.

A clock that reports nanoseconds can advance in coarser steps: about 42 ns
on Apple silicon. Benchee repeats a fast function only when the reported
resolution is coarse, so a 450 ns scenario would move in 9% steps. The
harness times each scenario before the run, and one that takes less than
10 µs runs enough calls per sample to take about 10 µs. The samples are
divided back to one call before the statistics, so every page reports per
call.

## Fixture Preconditions

A scenario is named for a path through the code. Before timing starts, each
suite runs every fixture once and stops when it takes another path: a gate
fixture that reaches a different action, a stream that halts before
`finish/1`, an attestation that does not verify, a corpus with the wrong
number of secrets. Change a fixture and its precondition together. The test
suite runs the same preconditions, so a change to the library that moves a
fixture to another path fails `mix test`.

## Corpus

`bench/corpus/` holds the committed inputs. `bench/corpus.exs` generates the
text files from a fixed seed and copies the policy, manifest and
physical-effect fixtures from the test suite, so regenerating reproduces the
same bytes. Hit files embed only the documented synthetic key
`AKIAIOSFODNN7EXAMPLE`.

## Smoke Runs

`--smoke`, or `CI=true`, shortens every scenario to verify that the suites
still execute. A smoke run writes under `bench/output/smoke/`, which is not
committed, so it never replaces the published reports. CI runs the smoke and
checks that every baseline scenario is still present.

## Revision Comparison

The weekly `comparable-performance` job runs the full matrix for two
revisions on one runner and compares them with `--require-comparable`. A
scheduled run measures the default branch tip against its parent. To
measure another change, run the workflow by hand with `head` set to the
commit and `base` to the commit before it. The job writes both commit hashes
to its summary and to `revisions.txt` in the uploaded reports. A result
covers the changes between those two revisions only; it does not replace
the baseline or support a claim about a release as a whole.

## Baseline Refresh

Refresh `bench/baseline.json` only in a dedicated PR. Run the full matrix
three times in a row on one runner, then check the set:

```sh
mix run bench/compare.exs --band run-1.json --band run-2.json --band run-3.json \
  --write-baseline bench/baseline.json
```

The check passes when every scenario median lies within +/-5% of the mean
of its three medians. It names each scenario outside the band and writes
nothing; when the set holds, it writes the last run without its `mode` as
the baseline.

On a workstation, the machine's own speed drifts between runs, mostly in
the allocation-heavy scenarios. The `Benchmark baseline candidate` workflow
(`.github/workflows/benchmark-baseline.yml`, run by hand) makes the three
runs on one GitHub-hosted runner, runs the check, and uploads the runs and
the candidate `baseline.json` as the `benchmark-baseline-candidate`
artifact.

The commit message must state why the baseline changed: accepted performance
change, fixture change, runner change, or Elixir/OTP bump. Silent baseline
edits are treated as masking a regression.

## Other Scripts

`bench/llm_guard_compare.exs` compares `SigilGuard.scan/1` with the Python
llm-guard scanners on the same corpus under the fairness rules of the
methodology spec. `bench/audit_remediation.exs` compares two revisions of the
scanner in one BEAM instance. Neither is part of `mix bench`.
