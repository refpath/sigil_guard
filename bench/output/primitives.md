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
- SigilGuard: 1.0.5 (3471773)
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
    <td style="white-space: nowrap; text-align: right">14107.37 K</td>
    <td style="white-space: nowrap; text-align: right">0.0709 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;66.85%</td>
    <td style="white-space: nowrap; text-align: right">0.0830 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.125 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2317.50 K</td>
    <td style="white-space: nowrap; text-align: right">0.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1187.63%</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1972.96 K</td>
    <td style="white-space: nowrap; text-align: right">0.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;66.61%</td>
    <td style="white-space: nowrap; text-align: right">0.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1141.25 K</td>
    <td style="white-space: nowrap; text-align: right">0.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;806.50%</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">755.98 K</td>
    <td style="white-space: nowrap; text-align: right">1.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;338.26%</td>
    <td style="white-space: nowrap; text-align: right">1.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">733.16 K</td>
    <td style="white-space: nowrap; text-align: right">1.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;313.64%</td>
    <td style="white-space: nowrap; text-align: right">1.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">491.93 K</td>
    <td style="white-space: nowrap; text-align: right">2.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;868.42%</td>
    <td style="white-space: nowrap; text-align: right">1.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">374.67 K</td>
    <td style="white-space: nowrap; text-align: right">2.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;248.71%</td>
    <td style="white-space: nowrap; text-align: right">2.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">326.90 K</td>
    <td style="white-space: nowrap; text-align: right">3.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;222.24%</td>
    <td style="white-space: nowrap; text-align: right">2.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">188.32 K</td>
    <td style="white-space: nowrap; text-align: right">5.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;141.45%</td>
    <td style="white-space: nowrap; text-align: right">4.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">69.63 K</td>
    <td style="white-space: nowrap; text-align: right">14.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.17%</td>
    <td style="white-space: nowrap; text-align: right">12.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.04 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">14107.37 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">2317.50 K</td>
    <td style="white-space: nowrap; text-align: right">6.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1972.96 K</td>
    <td style="white-space: nowrap; text-align: right">7.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1141.25 K</td>
    <td style="white-space: nowrap; text-align: right">12.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">755.98 K</td>
    <td style="white-space: nowrap; text-align: right">18.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">733.16 K</td>
    <td style="white-space: nowrap; text-align: right">19.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">491.93 K</td>
    <td style="white-space: nowrap; text-align: right">28.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">374.67 K</td>
    <td style="white-space: nowrap; text-align: right">37.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">326.90 K</td>
    <td style="white-space: nowrap; text-align: right">43.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">188.32 K</td>
    <td style="white-space: nowrap; text-align: right">74.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">69.63 K</td>
    <td style="white-space: nowrap; text-align: right">202.61x</td>
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
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap">2176 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap">352.00 B</td>
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