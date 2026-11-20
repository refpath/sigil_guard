# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Each suite has its own page with the full Benchee statistics.

## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (3471773)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 129.751 |  |
| BM.04 stream overhead versus single pass | 12687.883 | 323.6 |
| BM.08 gateway overhead versus no-op | 46.790 |  |

## Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

Full statistics: [Scanner Benchmarks](scanner.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.01 scan clean 1k | 13.250 | 16.667 | 3240 |
| BM.01 scan clean 1m | 12822.771 | 13235.701 | 3384 |
| BM.01 scan clean 64k | 801.208 | 859.360 | 3264 |
| BM.02 scan hits 1k | 15.833 | 22.292 | 11112 |
| BM.02 scan hits 1m | 13862.146 | 15811.541 | 2024152 |
| BM.02 scan hits 64k | 871.958 | 979.363 | 129136 |
| BM.09 scan and redact hits 1k | 16.333 | 23.709 | 11352 |
| BM.09 scan and redact hits 64k | 895.500 | 1034.570 | 132320 |
| BM.10 quarantine inspect clean 1k | 6.458 | 8.750 | 2920 |
| BM.10 quarantine inspect injection | 12.875 | 17.875 | 10080 |
| BM.11 pattern sets resolve 10 entries | 6.834 | 16.167 | 8040 |

## Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

Full statistics: [Runtime Gate and Policy Benchmarks](gate.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.03 runtime gate allow | 40.750 | 49.584 | 46272 |
| BM.03 runtime gate block | 24.875 | 38.417 | 54880 |
| BM.03 runtime gate quarantine | 45.958 | 60.958 | 62912 |
| BM.03 runtime gate redact | 32.375 | 47.668 | 56648 |
| BM.12 policy verdict allowed | 0.458 | 0.709 | 808 |
| BM.12 policy verdict blocked | 0.250 | 0.500 | 856 |
| BM.13 boundary policy kernel | 2.500 | 5.708 | 3256 |
| BM.14 policy file parse | 69.042 | 95.709 | 54088 |
| BM.14 runtime gate with output contract | 1628.506 | 1972.802 | 423472 |
| BM.15 repo policy compile | 9.916 | 13.583 | 12528 |
| BM.15 repo policy evaluate | 5.625 | 10.333 | 9904 |
| BM.15 runtime gate repo change | 40.459 | 55.500 | 96072 |

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
| BM.04 runtime stream 64k clean | 16957.172 | 23001.303 | 6127920 |
| BM.04 runtime stream 64k split secret | 16608.170 | 20034.544 | 6188184 |
| BM.04 single pass gate 64k | 3920.287 | 4746.300 | 1893856 |

## Tool Gateway Benchmarks

`SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
result. The suite times a request with and without a pinned capability
manifest and with a required inbound attestation, a result, manifest
validation and drift comparison, and a physical-effect request with its
admission check. The no-op baseline is an empty function in the same run.

Full statistics: [Tool Gateway Benchmarks](gateway.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.08 no-op baseline | 0.002 | 0.018 | 0 |
| BM.08 tool gateway guard_request | 46.792 | 63.958 | 89896 |
| BM.16 guard_request pinned compiled manifest | 55.000 | 74.382 | 107168 |
| BM.16 guard_request pinned manifest | 102.001 | 130.501 | 191240 |
| BM.16 guard_request required attestation | 203.834 | 261.286 | 290304 |
| BM.17 guard_result | 38.416 | 55.583 | 82704 |
| BM.17 guard_result pinned manifest | 91.043 | 119.876 | 182488 |
| BM.18 capability manifest drifted fields | 48.250 | 66.267 | 87208 |
| BM.18 capability manifest new | 44.250 | 62.126 | 82888 |
| BM.18 capability manifest verify | 45.875 | 63.958 | 82704 |
| BM.19 effect authority admit | 32.000 | 46.667 | 57056 |
| BM.19 guard_request effect binding | 276.626 | 382.516 | 470408 |

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
| BM.20 confirmation action digest | 9.501 | 26.084 | 22416 |
| BM.20 confirmation issue | 28.751 | 43.500 | 62888 |
| BM.20 confirmation verify | 34.376 | 51.250 | 68184 |
| BM.20 guard_request accepted token | 37.125 | 68.308 | 17392 |

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
| BM.05 attestation sign | 91.480 | 115.417 | 51136 |
| BM.05 attestation verify | 78.958 | 100.208 | 81264 |
| BM.21 attestation digests | 15.708 | 31.125 | 51672 |
| BM.21 attestation from_decision | 25.083 | 44.041 | 67040 |
| BM.21 trust profile validate | 2.375 | 5.292 | 3480 |
| BM.22 attestation verify signature only | 60.021 | 76.334 | 28496 |
| BM.22 attestation verify with trust bundle | 82.459 | 104.333 | 86784 |

## Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

Full statistics: [Trust Bundle Benchmarks](trust_bundle.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.06 trust bundle cache warm | 0.917 | 4.500 | 48 |
| BM.06 trust bundle verify cold | 104.125 | 140.501 | 111568 |
| BM.23 trust bundle load | 110.750 | 143.583 | 132902 |
| BM.23 trust bundle pattern sets | 7.750 | 22.667 | 8160 |

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
| BM.24 agent card digest | 17.125 | 39.542 | 37704 |
| BM.24 agent card sign | 92.916 | 116.042 | 40528 |
| BM.24 agent card verify | 67.417 | 85.833 | 49824 |
| BM.25 attest agent request | 211.959 | 245.960 | 232464 |
| BM.25 attest agent response | 238.168 | 285.937 | 214560 |
| BM.25 verify agent response | 166.792 | 212.459 | 164544 |
| BM.25 verify delegation chain | 3.125 | 8.166 | 10152 |

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
| BM.07 audit append onto 10k chain | 1.583 | 2.250 | 1720 |
| BM.07 audit checkpoint create 10k | 6512.359 | 10061.786 | 4172354 |
| BM.07 audit inclusion verify 10k | 7.500 | 46.244 | 5808 |
| BM.26 audit consistency proof 10k | 6916.527 | 13726.338 | 4424016 |
| BM.26 audit consistency verify 10k | 11.291 | 118.084 | 8488 |
| BM.26 audit export create 1k | 3632.556 | 4231.253 | 2787387 |
| BM.26 audit inclusion proof 10k | 6888.173 | 8889.686 | 4317736 |
| BM.26 audit verify chain 1k | 1888.841 | 2338.774 | 1536072 |

## Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Full statistics: [Primitive Benchmarks](primitives.md).

| Scenario | Median (us) | p99 (us) | Memory (bytes) |
|----------|------------:|---------:|---------------:|
| BM.27 canonical json decode statement | 4.792 | 18.292 | 10824 |
| BM.27 jcs encode statement | 12.875 | 30.041 | 43616 |
| BM.28 secure compare 64 bytes | 0.083 | 0.125 | 0 |
| BM.28 sha256 hex 1k | 0.459 | 0.750 | 152 |
| BM.29 identity did:key public key | 1.208 | 2.167 | 2176 |
| BM.29 identity spiffe id check | 1.542 | 3.166 | 712 |
| BM.30 replay store detect replay | 0.375 | 0.542 | 376 |
| BM.30 vault decrypt | 1.250 | 2.333 | 352 |
| BM.30 vault exists | 0.792 | 1.375 | 288 |
| BM.31 telemetry otel attributes | 2.875 | 3.875 | 5664 |
| BM.31 telemetry otel attributes high cardinality | 2.458 | 3.917 | 5008 |

