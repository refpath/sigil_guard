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
- SigilGuard: 1.0.5 (becb2d6)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-21

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
    <td style="white-space: nowrap; text-align: right">20949.73 K</td>
    <td style="white-space: nowrap; text-align: right">0.0477 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.51%</td>
    <td style="white-space: nowrap; text-align: right">0.0464 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.0546 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2874.20 K</td>
    <td style="white-space: nowrap; text-align: right">0.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.92%</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">2144.45 K</td>
    <td style="white-space: nowrap; text-align: right">0.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.09%</td>
    <td style="white-space: nowrap; text-align: right">0.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.48 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1429.84 K</td>
    <td style="white-space: nowrap; text-align: right">0.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.14%</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">920.99 K</td>
    <td style="white-space: nowrap; text-align: right">1.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.31%</td>
    <td style="white-space: nowrap; text-align: right">1.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">862.09 K</td>
    <td style="white-space: nowrap; text-align: right">1.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.89%</td>
    <td style="white-space: nowrap; text-align: right">1.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.56 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">615.64 K</td>
    <td style="white-space: nowrap; text-align: right">1.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;175.68%</td>
    <td style="white-space: nowrap; text-align: right">1.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">389.20 K</td>
    <td style="white-space: nowrap; text-align: right">2.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.56%</td>
    <td style="white-space: nowrap; text-align: right">2.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">379.20 K</td>
    <td style="white-space: nowrap; text-align: right">2.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.77%</td>
    <td style="white-space: nowrap; text-align: right">2.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.76 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">232.34 K</td>
    <td style="white-space: nowrap; text-align: right">4.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.96%</td>
    <td style="white-space: nowrap; text-align: right">4.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">75.88 K</td>
    <td style="white-space: nowrap; text-align: right">13.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.79%</td>
    <td style="white-space: nowrap; text-align: right">11.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.83 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">20949.73 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2874.20 K</td>
    <td style="white-space: nowrap; text-align: right">7.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">2144.45 K</td>
    <td style="white-space: nowrap; text-align: right">9.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1429.84 K</td>
    <td style="white-space: nowrap; text-align: right">14.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">920.99 K</td>
    <td style="white-space: nowrap; text-align: right">22.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">862.09 K</td>
    <td style="white-space: nowrap; text-align: right">24.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">615.64 K</td>
    <td style="white-space: nowrap; text-align: right">34.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">389.20 K</td>
    <td style="white-space: nowrap; text-align: right">53.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">379.20 K</td>
    <td style="white-space: nowrap; text-align: right">55.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">232.34 K</td>
    <td style="white-space: nowrap; text-align: right">90.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">75.88 K</td>
    <td style="white-space: nowrap; text-align: right">276.07x</td>
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
    <td style="white-space: nowrap">0.50 B</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap">368.86 B</td>
    <td>741.26x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap">154.55 B</td>
    <td>310.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap">276 B</td>
    <td>554.65x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap">341.33 B</td>
    <td>685.95x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap">2187.56 B</td>
    <td>4396.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap">707.43 B</td>
    <td>1421.66x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap">5006 B</td>
    <td>10060.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap">5772 B</td>
    <td>11599.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap">10930.67 B</td>
    <td>21966.44x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap">43704 B</td>
    <td>87828.23x</td>
  </tr>
</table>