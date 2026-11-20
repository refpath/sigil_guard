# Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Mode: measured. Values are measured for this environment, not ratified SLO bounds.
Scenarios that take less than 10 µs run in batches of calls;
every value is per call.


## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (39a9315)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## System

Benchmark suite executing on the following system:

<table style="width: 1%">
  <tr>
    <th style="width: 1%; white-space: nowrap">Operating System</th>
    <td>macOS</td>
  </tr><tr>
    <th style="white-space: nowrap">CPU Information</th>
    <td style="white-space: nowrap">Apple M4 Max</td>
  </tr><tr>
    <th style="white-space: nowrap">Number of Available Cores</th>
    <td style="white-space: nowrap">16</td>
  </tr><tr>
    <th style="white-space: nowrap">Available Memory</th>
    <td style="white-space: nowrap">128 GB</td>
  </tr><tr>
    <th style="white-space: nowrap">Elixir Version</th>
    <td style="white-space: nowrap">1.20.4</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">29.0.4</td>
  </tr>
</table>

## Configuration

Benchmark suite executing with the following configuration:

<table style="width: 1%">
  <tr>
    <th style="width: 1%">:time</th>
    <td style="white-space: nowrap">5 s</td>
  </tr><tr>
    <th>:parallel</th>
    <td style="white-space: nowrap">1</td>
  </tr><tr>
    <th>:warmup</th>
    <td style="white-space: nowrap">2 s</td>
  </tr>
</table>

## Statistics



Run Time

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Deviation</th>
    <th style="text-align: right">Median</th>
    <th style="text-align: right">99th&nbsp;%</th>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 secure compare 64 bytes</td>
    <td style="white-space: nowrap; text-align: right">18235.48 K</td>
    <td style="white-space: nowrap; text-align: right">0.0548 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.04%</td>
    <td style="white-space: nowrap; text-align: right">0.0528 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.0705 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2608.60 K</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.74%</td>
    <td style="white-space: nowrap; text-align: right">0.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1905.19 K</td>
    <td style="white-space: nowrap; text-align: right">0.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;51.93%</td>
    <td style="white-space: nowrap; text-align: right">0.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1228.30 K</td>
    <td style="white-space: nowrap; text-align: right">0.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;644.15%</td>
    <td style="white-space: nowrap; text-align: right">0.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">777.36 K</td>
    <td style="white-space: nowrap; text-align: right">1.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.25%</td>
    <td style="white-space: nowrap; text-align: right">1.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">508.99 K</td>
    <td style="white-space: nowrap; text-align: right">1.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;245.72%</td>
    <td style="white-space: nowrap; text-align: right">1.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.70 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">499.46 K</td>
    <td style="white-space: nowrap; text-align: right">2.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1449.62%</td>
    <td style="white-space: nowrap; text-align: right">1.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.32 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">354.23 K</td>
    <td style="white-space: nowrap; text-align: right">2.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.10%</td>
    <td style="white-space: nowrap; text-align: right">2.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">331.68 K</td>
    <td style="white-space: nowrap; text-align: right">3.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;160.12%</td>
    <td style="white-space: nowrap; text-align: right">2.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">140.58 K</td>
    <td style="white-space: nowrap; text-align: right">7.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;412.80%</td>
    <td style="white-space: nowrap; text-align: right">5.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.25 K</td>
    <td style="white-space: nowrap; text-align: right">15.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;126.66%</td>
    <td style="white-space: nowrap; text-align: right">13.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.75 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.28 secure compare 64 bytes</td>
    <td style="white-space: nowrap;text-align: right">18235.48 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2608.60 K</td>
    <td style="white-space: nowrap; text-align: right">6.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1905.19 K</td>
    <td style="white-space: nowrap; text-align: right">9.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1228.30 K</td>
    <td style="white-space: nowrap; text-align: right">14.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">777.36 K</td>
    <td style="white-space: nowrap; text-align: right">23.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">508.99 K</td>
    <td style="white-space: nowrap; text-align: right">35.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">499.46 K</td>
    <td style="white-space: nowrap; text-align: right">36.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">354.23 K</td>
    <td style="white-space: nowrap; text-align: right">51.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">331.68 K</td>
    <td style="white-space: nowrap; text-align: right">54.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">140.58 K</td>
    <td style="white-space: nowrap; text-align: right">129.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.25 K</td>
    <td style="white-space: nowrap; text-align: right">279.46x</td>
  </tr>

</table>



Memory Usage

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Factor</th>
  </tr>
  <tr>
    <td style="white-space: nowrap">BM.28 secure compare 64 bytes</td>
    <td style="white-space: nowrap">0.58 B</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap">368.31 B</td>
    <td>633.91x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap">155.11 B</td>
    <td>266.97x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap">284.80 B</td>
    <td>490.18x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap">2189 B</td>
    <td>3767.61x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap">705.60 B</td>
    <td>1214.45x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap">340 B</td>
    <td>585.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap">5772 B</td>
    <td>9934.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap">5006 B</td>
    <td>8616.1x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap">10904 B</td>
    <td>18767.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap">43616 B</td>
    <td>75069.85x</td>
  </tr>
</table>