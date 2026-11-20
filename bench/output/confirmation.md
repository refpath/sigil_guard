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
    <td style="white-space: nowrap">BM.20 confirmation action digest</td>
    <td style="white-space: nowrap; text-align: right">113.20 K</td>
    <td style="white-space: nowrap; text-align: right">8.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.18%</td>
    <td style="white-space: nowrap; text-align: right">8.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">35.15 K</td>
    <td style="white-space: nowrap; text-align: right">28.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.92%</td>
    <td style="white-space: nowrap; text-align: right">26.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">28.63 K</td>
    <td style="white-space: nowrap; text-align: right">34.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.80%</td>
    <td style="white-space: nowrap; text-align: right">33.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">27.82 K</td>
    <td style="white-space: nowrap; text-align: right">35.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.19%</td>
    <td style="white-space: nowrap; text-align: right">34.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.54 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">113.20 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap; text-align: right">35.15 K</td>
    <td style="white-space: nowrap; text-align: right">3.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap; text-align: right">28.63 K</td>
    <td style="white-space: nowrap; text-align: right">3.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap; text-align: right">27.82 K</td>
    <td style="white-space: nowrap; text-align: right">4.07x</td>
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
    <td style="white-space: nowrap">18.84 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation issue</td>
    <td style="white-space: nowrap">57.34 KB</td>
    <td>3.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 confirmation verify</td>
    <td style="white-space: nowrap">62.60 KB</td>
    <td>3.32x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.20 guard_request accepted token</td>
    <td style="white-space: nowrap">15.20 KB</td>
    <td>0.81x</td>
  </tr>
</table>