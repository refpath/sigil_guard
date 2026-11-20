# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Each suite has its own page with the full Benchee statistics.

## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (39a9315)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 119.259 |  |
| BM.04 stream overhead versus single pass | 11601.335 | 316.6 |
| BM.08 gateway overhead versus no-op | 62.914 |  |

## Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

Full statistics: [Scanner Benchmarks](scanner.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.01 scan clean 1k | 13.709 | 30.959 | 3240 |
| BM.01 scan clean 1m | 13195.667 | 15139.565 | 3384 |
| BM.01 scan clean 64k | 851.917 | 988.426 | 3264 |
| BM.02 scan hits 1k | 16.333 | 23.416 | 11112 |
| BM.02 scan hits 1m | 15137.063 | 16655.770 | 2024152 |
| BM.02 scan hits 64k | 1001.334 | 1088.721 | 129136 |
| BM.09 scan and redact hits 1k | 16.458 | 22.334 | 11352 |
| BM.09 scan and redact hits 64k | 844.625 | 1037.925 | 132320 |
| BM.10 quarantine inspect clean 1k | 6.896 | 11.771 | 3068 |
| BM.10 quarantine inspect injection | 32.417 | 44.792 | 10296 |
| BM.11 pattern sets resolve 10 entries | 6.917 | 18.709 | 8040 |

## Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

Full statistics: [Runtime Gate and Policy Benchmarks](gate.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.03 runtime gate allow | 46.750 | 61.001 | 46296 |
| BM.03 runtime gate block | 25.375 | 39.709 | 54904 |
| BM.03 runtime gate quarantine | 89.709 | 116.333 | 63528 |
| BM.03 runtime gate redact | 32.000 | 47.000 | 56672 |
| BM.12 policy verdict allowed | 0.438 | 0.627 | 813 |
| BM.12 policy verdict blocked | 0.271 | 0.510 | 856 |
| BM.13 boundary policy kernel | 2.875 | 12.820 | 4094 |
| BM.14 policy file parse | 77.584 | 103.417 | 54568 |
| BM.14 runtime gate with output contract | 1571.569 | 1913.786 | 423760 |
| BM.15 repo policy compile | 12.459 | 34.334 | 13328 |
| BM.15 repo policy evaluate | 6.604 | 14.584 | 10260 |
| BM.15 runtime gate repo change | 39.751 | 50.293 | 96400 |

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
| BM.04 runtime stream 64k clean | 15580.478 | 17115.086 | 6112608 |
| BM.04 runtime stream 64k split secret | 15265.222 | 16361.250 | 6200240 |
| BM.04 single pass gate 64k | 3663.887 | 4197.028 | 1894096 |

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
| BM.08 tool gateway guard_request | 62.917 | 79.626 | 90088 |
| BM.16 guard_request pinned compiled manifest | 66.126 | 83.137 | 108016 |
| BM.16 guard_request pinned manifest | 108.834 | 132.051 | 191328 |
| BM.16 guard_request required attestation | 195.544 | 240.877 | 291208 |
| BM.17 guard_result | 35.000 | 45.291 | 82728 |
| BM.17 guard_result pinned manifest | 81.875 | 102.293 | 181624 |
| BM.18 capability manifest drifted fields | 45.626 | 57.041 | 87736 |
| BM.18 capability manifest new | 40.875 | 51.416 | 82848 |
| BM.18 capability manifest verify | 41.000 | 57.001 | 81632 |
| BM.19 effect authority admit | 29.001 | 41.542 | 57056 |
| BM.19 guard_request effect binding | 245.584 | 318.873 | 482048 |

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
| BM.20 confirmation action digest | 8.917 | 15.501 | 22732 |
| BM.20 confirmation issue | 26.125 | 41.042 | 62888 |
| BM.20 confirmation verify | 40.334 | 60.250 | 68184 |
| BM.20 guard_request accepted token | 164.418 | 208.417 | 311864 |

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
| BM.05 attestation sign | 85.293 | 99.518 | 51136 |
| BM.05 attestation verify | 73.001 | 86.250 | 81264 |
| BM.21 attestation digests | 15.917 | 32.541 | 51672 |
| BM.21 attestation from_decision | 25.875 | 48.755 | 67040 |
| BM.21 trust profile validate | 2.365 | 16.083 | 3488 |
| BM.22 attestation verify signature only | 58.792 | 82.694 | 28496 |
| BM.22 attestation verify with trust bundle | 82.833 | 242.168 | 86784 |

## Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

Full statistics: [Trust Bundle Benchmarks](trust_bundle.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.06 trust bundle cache warm | 0.958 | 3.320 | 3339 |
| BM.06 trust bundle verify cold | 108.458 | 167.125 | 111568 |
| BM.23 trust bundle load | 110.668 | 221.112 | 132903 |
| BM.23 trust bundle pattern sets | 7.750 | 25.897 | 8212 |

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
| BM.24 agent card digest | 16.250 | 64.458 | 37704 |
| BM.24 agent card sign | 88.750 | 112.906 | 40528 |
| BM.24 agent card verify | 65.375 | 77.916 | 49824 |
| BM.25 attest agent request | 221.584 | 256.676 | 232392 |
| BM.25 attest agent response | 218.001 | 255.457 | 214560 |
| BM.25 verify agent response | 166.418 | 191.476 | 164544 |
| BM.25 verify delegation chain | 3.167 | 9.833 | 10195 |

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
| BM.07 audit append onto 10k chain | 1.590 | 4.014 | 1737 |
| BM.07 audit checkpoint create 10k | 8001.326 | 17064.736 | 4172354 |
| BM.07 audit inclusion verify 10k | 7.459 | 54.981 | 5808 |
| BM.26 audit consistency proof 10k | 7215.302 | 11783.880 | 4424016 |
| BM.26 audit consistency verify 10k | 11.500 | 135.835 | 8488 |
| BM.26 audit export create 1k | 3353.931 | 3747.291 | 2787387 |
| BM.26 audit inclusion proof 10k | 7762.158 | 19208.591 | 4317736 |
| BM.26 audit verify chain 1k | 1938.592 | 3606.395 | 1536072 |

## Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Full statistics: [Primitive Benchmarks](primitives.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.27 canonical json decode statement | 5.042 | 24.750 | 10904 |
| BM.27 jcs encode statement | 13.583 | 35.750 | 43616 |
| BM.28 secure compare 64 bytes | 0.053 | 0.071 | 1 |
| BM.28 sha256 hex 1k | 0.493 | 1.824 | 155 |
| BM.29 identity did:key public key | 1.208 | 2.651 | 2189 |
| BM.29 identity spiffe id check | 1.633 | 3.695 | 706 |
| BM.30 replay store detect replay | 0.370 | 0.646 | 368 |
| BM.30 vault decrypt | 1.281 | 3.323 | 340 |
| BM.30 vault exists | 0.796 | 1.038 | 285 |
| BM.31 telemetry otel attributes | 2.781 | 3.792 | 5772 |
| BM.31 telemetry otel attributes high cardinality | 2.740 | 6.667 | 5006 |
