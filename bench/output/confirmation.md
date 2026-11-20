# Confirmation Token Benchmarks

A decision that needs approval is released by a confirmation token bound
to the exact payload and context. The suite times the digest a token
binds, issuing and verifying a token, and a gateway request that carries
an accepted token. Verification runs with `consume: false`, so one token
can be verified repeatedly; a consuming verification also writes the
nonce to the replay store.

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
    <td style="white-space: nowrap">BM.20 confirmation action digest</td>
    <td style="white-space: nowrap; text-align: right">107.14 K</td>
    <td style="white-space: nowrap; text-align: right">9.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.02%</td>
    <td style="white-space: nowrap; text-align: right">8.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">37.61 K</td>
    <td style="white-space: nowrap; text-align: right">26.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.26%</td>
    <td style="white-space: nowrap; text-align: right">26.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">26.36 K</td>
    <td style="white-space: nowrap; text-align: right">37.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.73%</td>
    <td style="white-space: nowrap; text-align: right">40.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">5.97 K</td>
    <td style="white-space: nowrap; text-align: right">167.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.50%</td>
    <td style="white-space: nowrap; text-align: right">164.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">208.42 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">107.14 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">37.61 K</td>
    <td style="white-space: nowrap; text-align: right">2.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">26.36 K</td>
    <td style="white-space: nowrap; text-align: right">4.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">5.97 K</td>
    <td style="white-space: nowrap; text-align: right">17.96x</td>
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
    <td style="white-space: nowrap">22.20 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap">61.41 KB</td>
    <td>2.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap">66.59 KB</td>
    <td>3.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap">304.55 KB</td>
    <td>13.72x</td>
  </tr>
</table>