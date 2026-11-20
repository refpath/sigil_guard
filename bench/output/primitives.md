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
- SigilGuard: 1.0.5 (0eca0a4)
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
    <td style="white-space: nowrap; text-align: right">13829.57 K</td>
    <td style="white-space: nowrap; text-align: right">0.0723 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.21%</td>
    <td style="white-space: nowrap; text-align: right">0.0830 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.125 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1816.68 K</td>
    <td style="white-space: nowrap; text-align: right">0.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;62.53%</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">1774.05 K</td>
    <td style="white-space: nowrap; text-align: right">0.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1017.77%</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1141.00 K</td>
    <td style="white-space: nowrap; text-align: right">0.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;731.22%</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">759.55 K</td>
    <td style="white-space: nowrap; text-align: right">1.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;319.55%</td>
    <td style="white-space: nowrap; text-align: right">1.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">727.28 K</td>
    <td style="white-space: nowrap; text-align: right">1.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;377.77%</td>
    <td style="white-space: nowrap; text-align: right">1.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">484.12 K</td>
    <td style="white-space: nowrap; text-align: right">2.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;934.79%</td>
    <td style="white-space: nowrap; text-align: right">1.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">325.57 K</td>
    <td style="white-space: nowrap; text-align: right">3.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;180.74%</td>
    <td style="white-space: nowrap; text-align: right">2.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">265.68 K</td>
    <td style="white-space: nowrap; text-align: right">3.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1950.53%</td>
    <td style="white-space: nowrap; text-align: right">2.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">199.89 K</td>
    <td style="white-space: nowrap; text-align: right">5.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;128.75%</td>
    <td style="white-space: nowrap; text-align: right">4.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.34 K</td>
    <td style="white-space: nowrap; text-align: right">15.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;43.99%</td>
    <td style="white-space: nowrap; text-align: right">13.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.17 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">13829.57 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap; text-align: right">1816.68 K</td>
    <td style="white-space: nowrap; text-align: right">7.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap; text-align: right">1774.05 K</td>
    <td style="white-space: nowrap; text-align: right">7.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault exists</td>
    <td style="white-space: nowrap; text-align: right">1141.00 K</td>
    <td style="white-space: nowrap; text-align: right">12.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity did:key public key</td>
    <td style="white-space: nowrap; text-align: right">759.55 K</td>
    <td style="white-space: nowrap; text-align: right">18.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.30 vault decrypt</td>
    <td style="white-space: nowrap; text-align: right">727.28 K</td>
    <td style="white-space: nowrap; text-align: right">19.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.29 identity spiffe id check</td>
    <td style="white-space: nowrap; text-align: right">484.12 K</td>
    <td style="white-space: nowrap; text-align: right">28.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap; text-align: right">325.57 K</td>
    <td style="white-space: nowrap; text-align: right">42.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap; text-align: right">265.68 K</td>
    <td style="white-space: nowrap; text-align: right">52.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 canonical json decode statement</td>
    <td style="white-space: nowrap; text-align: right">199.89 K</td>
    <td style="white-space: nowrap; text-align: right">69.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.27 jcs encode statement</td>
    <td style="white-space: nowrap; text-align: right">65.34 K</td>
    <td style="white-space: nowrap; text-align: right">211.66x</td>
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
    <td style="white-space: nowrap">BM.28 sha256 hex 1k</td>
    <td style="white-space: nowrap">152 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.30 replay store detect replay</td>
    <td style="white-space: nowrap">400 B</td>
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
    <td style="white-space: nowrap">BM.31 telemetry otel attributes</td>
    <td style="white-space: nowrap">5896 B</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.31 telemetry otel attributes high cardinality</td>
    <td style="white-space: nowrap">5128 B</td>
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