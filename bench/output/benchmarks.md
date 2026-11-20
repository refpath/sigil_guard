# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Each suite has its own page with the full Benchee statistics.

## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (0eca0a4)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 211.803 |  |
| BM.04 stream overhead versus single pass | 20617.852 | 317.5 |
| BM.08 gateway overhead versus no-op | 45.873 |  |

## Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

Full statistics: [Scanner Benchmarks](scanner.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.01 scan clean 1k | 13.834 | 17.833 | 3208 |
| BM.01 scan clean 1m | 13612.166 | 14640.364 | 3352 |
| BM.01 scan clean 64k | 847.958 | 979.299 | 3232 |
| BM.02 scan hits 1k | 16.292 | 22.333 | 11096 |
| BM.02 scan hits 1m | 14578.584 | 15439.308 | 2022456 |
| BM.02 scan hits 64k | 872.958 | 972.637 | 127976 |
| BM.09 scan and redact hits 1k | 16.708 | 25.709 | 10888 |
| BM.09 scan and redact hits 64k | 900.958 | 1002.070 | 131984 |
| BM.10 quarantine inspect clean 1k | 107.542 | 123.958 | 2168 |
| BM.10 quarantine inspect injection | 15.417 | 22.541 | 9912 |
| BM.11 pattern sets resolve 10 entries | 7.750 | 16.000 | 8040 |

## Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

Full statistics: [Runtime Gate and Policy Benchmarks](gate.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.03 runtime gate allow | 135.814 | 163.335 | 42736 |
| BM.03 runtime gate block | 26.834 | 42.708 | 52520 |
| BM.03 runtime gate quarantine | 50.335 | 61.750 | 59784 |
| BM.03 runtime gate redact | 38.584 | 53.793 | 53384 |
| BM.12 policy verdict allowed | 0.541 | 0.791 | 808 |
| BM.12 policy verdict blocked | 0.292 | 0.500 | 856 |
| BM.13 boundary policy kernel | 2.833 | 6.001 | 3208 |
| BM.14 policy file parse | 79.251 | 101.909 | 53872 |
| BM.14 runtime gate with output contract | 3499.756 | 3875.911 | 453288 |
| BM.15 repo policy compile | 10.125 | 13.625 | 12528 |
| BM.15 repo policy evaluate | 5.500 | 9.041 | 9064 |
| BM.15 runtime gate repo change | 37.833 | 52.875 | 88328 |

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
| BM.04 runtime stream 64k clean | 28658.602 | 30221.029 | 5900800 |
| BM.04 runtime stream 64k split secret | 27110.801 | 30121.749 | 5963200 |
| BM.04 single pass gate 64k | 6492.949 | 7344.447 | 1235912 |

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
| BM.08 tool gateway guard_request | 45.875 | 57.043 | 85032 |
| BM.16 guard_request pinned compiled manifest | 53.293 | 70.125 | 102312 |
| BM.16 guard_request pinned manifest | 95.459 | 127.585 | 187080 |
| BM.16 guard_request required attestation | 194.792 | 259.280 | 285160 |
| BM.17 guard_result | 42.458 | 58.250 | 76712 |
| BM.17 guard_result pinned manifest | 93.834 | 111.876 | 175904 |
| BM.18 capability manifest drifted fields | 49.918 | 62.542 | 87760 |
| BM.18 capability manifest new | 44.668 | 58.500 | 82336 |
| BM.18 capability manifest verify | 48.418 | 66.292 | 82472 |
| BM.19 effect authority admit | 31.584 | 44.791 | 50560 |
| BM.19 guard_request effect binding | 260.959 | 396.973 | 470960 |

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
| BM.20 confirmation action digest | 8.333 | 13.583 | 19296 |
| BM.20 confirmation issue | 26.666 | 52.333 | 58712 |
| BM.20 confirmation verify | 33.166 | 59.042 | 64104 |
| BM.20 guard_request accepted token | 34.042 | 78.541 | 15560 |

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
| BM.05 attestation sign | 89.417 | 111.834 | 51136 |
| BM.05 attestation verify | 75.876 | 99.793 | 78816 |
| BM.21 attestation digests | 14.667 | 29.875 | 51096 |
| BM.21 attestation from_decision | 25.000 | 45.625 | 66072 |
| BM.21 trust profile validate | 2.416 | 5.334 | 3480 |
| BM.22 attestation verify signature only | 57.667 | 72.792 | 26848 |
| BM.22 attestation verify with trust bundle | 79.376 | 97.626 | 84000 |

## Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

Full statistics: [Trust Bundle Benchmarks](trust_bundle.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.06 trust bundle cache warm | 0.958 | 4.541 | 48 |
| BM.06 trust bundle verify cold | 103.917 | 130.501 | 111496 |
| BM.23 trust bundle load | 105.417 | 129.417 | 132830 |
| BM.23 trust bundle pattern sets | 8.042 | 24.208 | 8160 |

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
| BM.24 agent card digest | 16.167 | 38.291 | 37704 |
| BM.24 agent card sign | 89.167 | 110.073 | 40528 |
| BM.24 agent card verify | 66.208 | 85.585 | 49824 |
| BM.25 attest agent request | 229.585 | 309.898 | 230992 |
| BM.25 attest agent response | 225.126 | 298.820 | 213160 |
| BM.25 verify agent response | 175.417 | 221.304 | 161944 |
| BM.25 verify delegation chain | 3.500 | 8.542 | 10152 |

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
| BM.07 audit append onto 10k chain | 1.792 | 2.958 | 1720 |
| BM.07 audit checkpoint create 10k | 6932.305 | 9023.712 | 4164856 |
| BM.07 audit inclusion verify 10k | 7.667 | 49.792 | 5808 |
| BM.26 audit consistency proof 10k | 6600.138 | 9749.225 | 4424016 |
| BM.26 audit consistency verify 10k | 11.542 | 124.418 | 8488 |
| BM.26 audit export create 1k | 3782.686 | 4652.726 | 2779859 |
| BM.26 audit inclusion proof 10k | 6687.158 | 10173.919 | 4317736 |
| BM.26 audit verify chain 1k | 1814.738 | 2313.028 | 1536072 |

## Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Full statistics: [Primitive Benchmarks](primitives.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.27 canonical json decode statement | 4.792 | 7.542 | 10824 |
| BM.27 jcs encode statement | 13.542 | 34.167 | 43616 |
| BM.28 secure compare 64 bytes | 0.083 | 0.125 | 0 |
| BM.28 sha256 hex 1k | 0.541 | 0.750 | 152 |
| BM.29 identity did:key public key | 1.208 | 2.375 | 2176 |
| BM.29 identity spiffe id check | 1.583 | 2.917 | 712 |
| BM.30 replay store detect replay | 0.500 | 0.708 | 400 |
| BM.30 vault decrypt | 1.250 | 2.625 | 352 |
| BM.30 vault exists | 0.792 | 1.292 | 288 |
| BM.31 telemetry otel attributes | 2.917 | 4.208 | 5896 |
| BM.31 telemetry otel attributes high cardinality | 2.750 | 7.292 | 5128 |

