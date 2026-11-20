# Primitive Benchmarks

The building blocks the decision paths call: RFC 8785 canonical encoding
of a statement, strict JSON decoding, SHA-256 and constant-time
comparison, identifier syntax checks, reads from the in-memory vault, the
replay store's rejection of a seen nonce, and the projection of a gate
event into OpenTelemetry attributes.

Mode: measured. Values are measured for this environment, not ratified SLO bounds.


## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (1426856)
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
    <td style="white-space: nowrap; text-align: right">13291.69 K</td>
    <td style="white-space: nowrap; text-align: right">0.0752 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.55%</td>
    <td style="white-space: nowrap; text-align: right">0.0830 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.125 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2337.03 K</td>
    <td style="white-space: nowrap; text-align: right">0.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1010.76%</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1758.51 K</td>
    <td style="white-space: nowrap; text-align: right">0.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.93%</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1147.97 K</td>
    <td style="white-space: nowrap; text-align: right">0.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;735.26%</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">795.41 K</td>
    <td style="white-space: nowrap; text-align: right">1.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;337.51%</td>
    <td style="white-space: nowrap; text-align: right">1.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">742.75 K</td>
    <td style="white-space: nowrap; text-align: right">1.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;328.74%</td>
    <td style="white-space: nowrap; text-align: right">1.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">566.18 K</td>
    <td style="white-space: nowrap; text-align: right">1.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;759.87%</td>
    <td style="white-space: nowrap; text-align: right">1.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">364.56 K</td>
    <td style="white-space: nowrap; text-align: right">2.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;247.01%</td>
    <td style="white-space: nowrap; text-align: right">2.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">310.73 K</td>
    <td style="white-space: nowrap; text-align: right">3.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;216.33%</td>
    <td style="white-space: nowrap; text-align: right">3.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">196.16 K</td>
    <td style="white-space: nowrap; text-align: right">5.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;122.07%</td>
    <td style="white-space: nowrap; text-align: right">4.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.22 K</td>
    <td style="white-space: nowrap; text-align: right">15.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.04%</td>
    <td style="white-space: nowrap; text-align: right">13.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.12 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">13291.69 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2337.03 K</td>
    <td style="white-space: nowrap; text-align: right">5.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1758.51 K</td>
    <td style="white-space: nowrap; text-align: right">7.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1147.97 K</td>
    <td style="white-space: nowrap; text-align: right">11.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">795.41 K</td>
    <td style="white-space: nowrap; text-align: right">16.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">742.75 K</td>
    <td style="white-space: nowrap; text-align: right">17.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">566.18 K</td>
    <td style="white-space: nowrap; text-align: right">23.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">364.56 K</td>
    <td style="white-space: nowrap; text-align: right">36.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">310.73 K</td>
    <td style="white-space: nowrap; text-align: right">42.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">196.16 K</td>
    <td style="white-space: nowrap; text-align: right">67.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.22 K</td>
    <td style="white-space: nowrap; text-align: right">203.8x</td>
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
    <td style="white-space: nowrap">0 B</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap">376 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap">152 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap">287.99 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap">352.00 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap">2176 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap">712 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap">5008 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap">5664 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap">10824 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap">43616 B</td>
    <td>&mdash;</td>
  </tr>
</table>