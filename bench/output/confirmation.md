# Confirmation Token Benchmarks

A decision that needs approval is released by a confirmation token bound
to the exact payload and context. The suite times the digest a token
binds, issuing and verifying a token, and a gateway request that carries
an accepted token. Verification runs with `consume: false`, so one token
can be verified repeatedly; a consuming verification also writes the
nonce to the replay store.

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
    <td style="white-space: nowrap">BM.20 confirmation action digest</td>
    <td style="white-space: nowrap; text-align: right">117.09 K</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.37%</td>
    <td style="white-space: nowrap; text-align: right">8.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12.86 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">35.51 K</td>
    <td style="white-space: nowrap; text-align: right">28.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.93%</td>
    <td style="white-space: nowrap; text-align: right">26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">48.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">26.02 K</td>
    <td style="white-space: nowrap; text-align: right">38.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.59%</td>
    <td style="white-space: nowrap; text-align: right">36.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">25.40 K</td>
    <td style="white-space: nowrap; text-align: right">39.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.62%</td>
    <td style="white-space: nowrap; text-align: right">37.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.33 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.20 confirmation action digest</td>
    <td style="white-space: nowrap;text-align: right">117.09 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">35.51 K</td>
    <td style="white-space: nowrap; text-align: right">3.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">26.02 K</td>
    <td style="white-space: nowrap; text-align: right">4.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">25.40 K</td>
    <td style="white-space: nowrap; text-align: right">4.61x</td>
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
    <td style="white-space: nowrap">BM.20 confirmation action digest</td>
    <td style="white-space: nowrap">19.09 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap">58.32 KB</td>
    <td>3.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap">63.33 KB</td>
    <td>3.32x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap">17.01 KB</td>
    <td>0.89x</td>
  </tr>
</table>