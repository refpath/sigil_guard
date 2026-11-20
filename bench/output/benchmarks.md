# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Each suite has its own page with the full Benchee statistics.

## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (1426856)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 137.619 |  |
| BM.04 stream overhead versus single pass | 13414.924 | 319.4 |
| BM.08 gateway overhead versus no-op | 54.749 |  |

## Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

Full statistics: [Scanner Benchmarks](scanner.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.01 scan clean 1k | 13.750 | 17.625 | 3208 |
| BM.01 scan clean 1m | 13969.063 | 15259.621 | 3352 |
| BM.01 scan clean 64k | 886.146 | 1024.318 | 3232 |
| BM.02 scan hits 1k | 16.292 | 23.541 | 11080 |
| BM.02 scan hits 1m | 15130.125 | 16967.893 | 2023720 |
| BM.02 scan hits 64k | 912.625 | 1043.945 | 128624 |
| BM.09 scan and redact hits 1k | 16.500 | 25.291 | 11368 |
| BM.09 scan and redact hits 64k | 858.875 | 1025.513 | 132160 |
| BM.10 quarantine inspect clean 1k | 23.125 | 32.792 | 2944 |
| BM.10 quarantine inspect injection | 15.750 | 22.125 | 10088 |
| BM.11 pattern sets resolve 10 entries | 8.667 | 20.291 | 8040 |

## Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

Full statistics: [Runtime Gate and Policy Benchmarks](gate.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.03 runtime gate allow | 68.583 | 83.417 | 44760 |
| BM.03 runtime gate block | 35.125 | 46.001 | 52984 |
| BM.03 runtime gate quarantine | 51.041 | 63.333 | 61480 |
| BM.03 runtime gate redact | 43.000 | 55.917 | 55088 |
| BM.12 policy verdict allowed | 0.500 | 13.709 | 808 |
| BM.12 policy verdict blocked | 0.292 | 0.500 | 856 |
| BM.13 boundary policy kernel | 2.459 | 6.750 | 3208 |
| BM.14 policy file parse | 81.625 | 104.869 | 54088 |
| BM.14 runtime gate with output contract | 1961.425 | 2137.253 | 421648 |
| BM.15 repo policy compile | 9.250 | 12.208 | 12528 |
| BM.15 repo policy evaluate | 5.583 | 10.500 | 9064 |
| BM.15 runtime gate repo change | 40.209 | 57.708 | 89248 |

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
| BM.04 runtime stream 64k clean | 17776.316 | 19877.778 | 5893048 |
| BM.04 runtime stream 64k split secret | 17615.273 | 21096.472 | 5952560 |
| BM.04 single pass gate 64k | 4200.349 | 5035.638 | 1892480 |

## Tool Gateway Benchmarks

`SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
result. The suite times a request with and without a pinned capability
manifest and with a required inbound attestation, a result, manifest
validation and drift comparison, and a physical-effect request with its
admission check. The no-op baseline is an empty function in the same run.

Full statistics: [Tool Gateway Benchmarks](gateway.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.08 no-op baseline | 0.002 | 0.003 | 0 |
| BM.08 tool gateway guard_request | 54.751 | 69.960 | 87368 |
| BM.16 guard_request pinned compiled manifest | 61.375 | 78.000 | 104888 |
| BM.16 guard_request pinned manifest | 117.126 | 139.666 | 188344 |
| BM.16 guard_request required attestation | 205.210 | 255.126 | 286752 |
| BM.17 guard_result | 47.250 | 60.459 | 80216 |
| BM.17 guard_result pinned manifest | 111.041 | 133.626 | 179136 |
| BM.18 capability manifest drifted fields | 57.625 | 70.292 | 87688 |
| BM.18 capability manifest new | 45.167 | 61.916 | 82392 |
| BM.18 capability manifest verify | 52.375 | 66.209 | 82600 |
| BM.19 effect authority admit | 28.083 | 41.505 | 52752 |
| BM.19 guard_request effect binding | 239.876 | 299.981 | 466896 |

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
| BM.20 confirmation action digest | 8.166 | 12.864 | 19544 |
| BM.20 confirmation issue | 26.000 | 48.458 | 59720 |
| BM.20 confirmation verify | 36.667 | 66.543 | 64848 |
| BM.20 guard_request accepted token | 37.583 | 81.334 | 17416 |

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
| BM.05 attestation sign | 92.251 | 116.793 | 51136 |
| BM.05 attestation verify | 74.834 | 98.917 | 79272 |
| BM.21 attestation digests | 15.042 | 25.459 | 51672 |
| BM.21 attestation from_decision | 25.708 | 45.042 | 67040 |
| BM.21 trust profile validate | 2.166 | 4.542 | 3480 |
| BM.22 attestation verify signature only | 61.250 | 74.625 | 26848 |
| BM.22 attestation verify with trust bundle | 76.333 | 98.000 | 85144 |

## Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

Full statistics: [Trust Bundle Benchmarks](trust_bundle.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.06 trust bundle cache warm | 0.834 | 3.750 | 48 |
| BM.06 trust bundle verify cold | 97.625 | 116.886 | 111496 |
| BM.23 trust bundle load | 104.917 | 132.036 | 132830 |
| BM.23 trust bundle pattern sets | 7.791 | 21.542 | 8160 |

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
| BM.24 agent card digest | 17.750 | 34.375 | 37704 |
| BM.24 agent card sign | 98.083 | 118.417 | 40528 |
| BM.24 agent card verify | 67.709 | 87.083 | 49824 |
| BM.25 attest agent request | 257.210 | 318.622 | 232464 |
| BM.25 attest agent response | 244.293 | 313.123 | 214176 |
| BM.25 verify agent response | 175.625 | 210.209 | 162992 |
| BM.25 verify delegation chain | 3.792 | 10.333 | 10152 |

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
| BM.07 audit append onto 10k chain | 1.958 | 3.000 | 1720 |
| BM.07 audit checkpoint create 10k | 7402.885 | 9252.766 | 4164856 |
| BM.07 audit inclusion verify 10k | 7.833 | 48.916 | 5808 |
| BM.26 audit consistency proof 10k | 5969.168 | 8801.369 | 4424016 |
| BM.26 audit consistency verify 10k | 11.750 | 119.714 | 8488 |
| BM.26 audit export create 1k | 3488.740 | 4470.525 | 2779859 |
| BM.26 audit inclusion proof 10k | 6944.036 | 9001.468 | 4317736 |
| BM.26 audit verify chain 1k | 2029.773 | 2470.279 | 1536072 |

## Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Full statistics: [Primitive Benchmarks](primitives.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.27 canonical json decode statement | 4.833 | 7.666 | 10824 |
| BM.27 jcs encode statement | 13.791 | 33.118 | 43616 |
| BM.28 secure compare 64 bytes | 0.083 | 0.125 | 0 |
| BM.28 sha256 hex 1k | 0.542 | 0.792 | 152 |
| BM.29 identity did:key public key | 1.209 | 2.042 | 2176 |
| BM.29 identity spiffe id check | 1.458 | 2.458 | 712 |
| BM.30 replay store detect replay | 0.375 | 0.542 | 376 |
| BM.30 vault decrypt | 1.125 | 2.083 | 352 |
| BM.30 vault exists | 0.792 | 1.333 | 288 |
| BM.31 telemetry otel attributes | 3.375 | 3.958 | 5664 |
| BM.31 telemetry otel attributes high cardinality | 2.417 | 3.875 | 5008 |

