# Trust Bundle Benchmarks

A host verifies a trust bundle when it loads one and reads it from the
cache afterwards. The fixture is a signed bundle with one root key, two
delegate roles and ten pattern entries. Cold verification covers the
envelope signature, the schema, role thresholds, freshness and the
rollback check against the cache. The warm path is one cache read.

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
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">751.86 K</td>
    <td style="white-space: nowrap; text-align: right">1.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;357.53%</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.23 trust bundle pattern sets</td>
    <td style="white-space: nowrap; text-align: right">108.56 K</td>
    <td style="white-space: nowrap; text-align: right">9.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;124.42%</td>
    <td style="white-space: nowrap; text-align: right">8.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">9.46 K</td>
    <td style="white-space: nowrap; text-align: right">105.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.87%</td>
    <td style="white-space: nowrap; text-align: right">103.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">130.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.23 trust bundle load</td>
    <td style="white-space: nowrap; text-align: right">9.42 K</td>
    <td style="white-space: nowrap; text-align: right">106.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.18%</td>
    <td style="white-space: nowrap; text-align: right">105.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.42 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap;text-align: right">751.86 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.23 trust bundle pattern sets</td>
    <td style="white-space: nowrap; text-align: right">108.56 K</td>
    <td style="white-space: nowrap; text-align: right">6.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">9.46 K</td>
    <td style="white-space: nowrap; text-align: right">79.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.23 trust bundle load</td>
    <td style="white-space: nowrap; text-align: right">9.42 K</td>
    <td style="white-space: nowrap; text-align: right">79.82x</td>
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
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap">0.0469 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.23 trust bundle pattern sets</td>
    <td style="white-space: nowrap">7.97 KB</td>
    <td>170.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap">108.88 KB</td>
    <td>2322.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.23 trust bundle load</td>
    <td style="white-space: nowrap">129.72 KB</td>
    <td>2767.29x</td>
  </tr>
</table>