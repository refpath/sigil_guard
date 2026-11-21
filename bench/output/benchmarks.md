# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Each suite has its own page with the full Benchee statistics.

## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (becb2d6)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-21

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 114.231 |  |
| BM.04 stream overhead versus single pass | 11361.426 | 348.5 |
| BM.08 gateway overhead versus no-op | 62.330 |  |

## Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

Full statistics: [Scanner Benchmarks](scanner.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.01 scan clean 1k | 12.000 | 14.667 | 3384 |
| BM.01 scan clean 1m | 12247.834 | 12590.532 | 3528 |
| BM.01 scan clean 64k | 761.959 | 804.879 | 3408 |
| BM.02 scan hits 1k | 14.500 | 19.875 | 11040 |
| BM.02 scan hits 1m | 13269.333 | 13573.361 | 2024112 |
| BM.02 scan hits 64k | 790.458 | 830.478 | 128848 |
| BM.09 scan and redact hits 1k | 14.791 | 22.458 | 11480 |
| BM.09 scan and redact hits 64k | 799.375 | 882.208 | 131744 |
| BM.10 quarantine inspect clean 1k | 6.063 | 9.209 | 3068 |
| BM.10 quarantine inspect injection | 31.500 | 37.959 | 10296 |
| BM.11 pattern sets resolve 10 entries | 7.209 | 20.834 | 7796 |

## Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

Full statistics: [Runtime Gate and Policy Benchmarks](gate.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.03 runtime gate allow | 40.042 | 52.959 | 46464 |
| BM.03 runtime gate block | 21.918 | 35.834 | 55784 |
| BM.03 runtime gate quarantine | 80.625 | 96.916 | 63696 |
| BM.03 runtime gate redact | 29.125 | 41.168 | 56440 |
| BM.12 policy verdict allowed | 0.411 | 0.536 | 812 |
| BM.12 policy verdict blocked | 0.243 | 0.286 | 856 |
| BM.13 boundary policy kernel | 2.313 | 8.865 | 4094 |
| BM.14 policy file parse | 71.791 | 91.917 | 53656 |
| BM.14 runtime gate with output contract | 1460.257 | 1558.892 | 424232 |
| BM.15 repo policy compile | 10.916 | 26.043 | 11216 |
| BM.15 repo policy evaluate | 6.063 | 14.313 | 10180 |
| BM.15 runtime gate repo change | 37.667 | 49.500 | 95632 |

## Streaming Benchmarks

`SigilGuard.Runtime.Stream` evaluates each pushed chunk together with the
bytes it still holds back, so that a secret split across two chunks is
caught. The suite pushes 64 KiB in 128 chunks of 512 bytes, with one
secret across a chunk boundary, and compares that with one gate
evaluation over the same bytes. The context has high trust, so secrets
are redacted and every chunk is evaluated. At low trust the first secret
asks for confirmation and halts the stream.

Full statistics: [Streaming Benchmarks](stream.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.04 runtime stream 64k clean | 15001.982 | 15721.758 | 6128584 |
| BM.04 runtime stream 64k split secret | 14621.607 | 15100.416 | 6210760 |
| BM.04 single pass gate 64k | 3260.181 | 3548.892 | 1894240 |

## Tool Gateway Benchmarks

`SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
result. The suite times a request with and without a pinned capability
manifest and with a required inbound attestation, a result, manifest
validation and drift comparison, and a physical-effect request with its
admission check. The no-op baseline is an empty function in the same run.

Full statistics: [Tool Gateway Benchmarks](gateway.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.08 no-op baseline | 0.003 | 0.004 | 0 |
| BM.08 tool gateway guard_request | 62.333 | 73.625 | 90024 |
| BM.16 guard_request pinned compiled manifest | 65.709 | 77.167 | 108064 |
| BM.16 guard_request pinned manifest | 116.042 | 138.880 | 190368 |
| BM.16 guard_request required attestation | 196.335 | 235.773 | 290024 |
| BM.17 guard_result | 33.750 | 45.334 | 82816 |
| BM.17 guard_result pinned manifest | 78.500 | 97.857 | 180704 |
| BM.18 capability manifest drifted fields | 46.917 | 60.085 | 85952 |
| BM.18 capability manifest new | 41.542 | 52.709 | 81936 |
| BM.18 capability manifest verify | 41.417 | 53.292 | 80984 |
| BM.19 effect authority admit | 38.583 | 52.958 | 85312 |
| BM.19 guard_request effect binding | 252.126 | 307.702 | 492600 |

## Confirmation Token Benchmarks

A decision that needs approval is released by a confirmation token bound
to the exact payload and context. The suite times the digest a token
binds, issuing and verifying a token, and a gateway request that carries
an accepted token. Verification runs with `consume: false`, so one token
can be verified repeatedly; a consuming verification also writes the
nonce to the replay store.

Full statistics: [Confirmation Token Benchmarks](confirmation.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.20 confirmation action digest | 8.104 | 15.230 | 22732 |
| BM.20 confirmation issue | 28.125 | 45.750 | 63256 |
| BM.20 confirmation verify | 34.834 | 51.292 | 68504 |
| BM.20 guard_request accepted token | 176.918 | 217.509 | 309392 |

## Attestation Benchmarks

An attestation is a DSSE envelope over a JCS-canonical statement whose
subjects are the action, payload, context and manifest digests. The suite
times each step a host or a verifier runs: computing the digests,
building the statement from a decision, validating it, signing, and
verifying against a key map and against a trust bundle role. Signing and
verification are dominated by Ed25519.

Full statistics: [Attestation Benchmarks](attestation.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.05 attestation sign | 86.834 | 105.710 | 50464 |
| BM.05 attestation verify | 72.750 | 89.042 | 80952 |
| BM.21 attestation digests | 16.125 | 25.334 | 51904 |
| BM.21 attestation from_decision | 26.209 | 38.166 | 66392 |
| BM.21 trust profile validate | 2.050 | 8.792 | 3309 |
| BM.22 attestation verify signature only | 52.625 | 65.167 | 28176 |
| BM.22 attestation verify with trust bundle | 72.000 | 85.000 | 86664 |

## Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

Full statistics: [Trust Bundle Benchmarks](trust_bundle.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.06 trust bundle cache warm | 1.153 | 1.410 | 4949 |
| BM.06 trust bundle verify cold | 92.292 | 112.751 | 111312 |
| BM.23 trust bundle load | 97.000 | 119.876 | 132646 |
| BM.23 trust bundle pattern sets | 7.833 | 18.375 | 7868 |

## Agent-To-Agent Trust Benchmarks

An agent exchange signs a card once and attests each request and
response. The suite times card signing, verification and digest, an
attested request with a three-hop delegation chain, an attested response
bound to its requester, and the requester's verification of that
response with every binding checked. Each attest and verify step
verifies the peer's card envelope first, so it carries two Ed25519
operations.

Full statistics: [Agent-To-Agent Trust Benchmarks](agent_trust.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.24 agent card digest | 15.541 | 33.375 | 37888 |
| BM.24 agent card sign | 79.625 | 93.293 | 40920 |
| BM.24 agent card verify | 60.875 | 73.750 | 49480 |
| BM.25 attest agent request | 204.792 | 242.765 | 227560 |
| BM.25 attest agent response | 211.543 | 243.637 | 210752 |
| BM.25 verify agent response | 157.916 | 188.168 | 163120 |
| BM.25 verify delegation chain | 3.597 | 10.194 | 9291 |

## Audit Evidence Benchmarks

Every decision can append one HMAC-chained audit event, and a host
periodically checkpoints the chain into a Merkle root and exports
evidence. The suite appends to a chain of 10,000 events, creates a
checkpoint over it, builds and verifies inclusion and consistency proofs,
verifies a chain of 1,000 events, and exports it. Event ids and
timestamps follow from the event index, so the chain has the same bytes
on every run.

Full statistics: [Audit Evidence Benchmarks](audit.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.07 audit append onto 10k chain | 1.486 | 3.132 | 1737 |
| BM.07 audit checkpoint create 10k | 5420.565 | 6943.743 | 3932338 |
| BM.07 audit inclusion verify 10k | 6.605 | 51.813 | 5668 |
| BM.26 audit consistency proof 10k | 5545.357 | 6794.218 | 4183952 |
| BM.26 audit consistency verify 10k | 9.583 | 100.543 | 8240 |
| BM.26 audit export create 1k | 3471.058 | 3729.779 | 2708619 |
| BM.26 audit inclusion proof 10k | 5595.088 | 6937.767 | 4082672 |
| BM.26 audit verify chain 1k | 1584.674 | 1884.168 | 1536072 |

## Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Full statistics: [Primitive Benchmarks](primitives.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.27 canonical json decode statement | 4.167 | 6.125 | 10931 |
| BM.27 jcs encode statement | 11.958 | 32.834 | 43704 |
| BM.28 secure compare 64 bytes | 0.046 | 0.055 | 0 |
| BM.28 sha256 hex 1k | 0.445 | 1.475 | 155 |
| BM.29 identity did:key public key | 1.157 | 1.560 | 2188 |
| BM.29 identity spiffe id check | 1.351 | 5.083 | 707 |
| BM.30 replay store detect replay | 0.335 | 0.537 | 369 |
| BM.30 vault decrypt | 1.069 | 1.329 | 341 |
| BM.30 vault exists | 0.688 | 0.827 | 276 |
| BM.31 telemetry otel attributes | 2.615 | 3.761 | 5772 |
| BM.31 telemetry otel attributes high cardinality | 2.448 | 4.646 | 5006 |
