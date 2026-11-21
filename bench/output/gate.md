# Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap; text-align: right">4138.39 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.67%</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2392.91 K</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.32%</td>
    <td style="white-space: nowrap; text-align: right">0.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">361.69 K</td>
    <td style="white-space: nowrap; text-align: right">2.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;82.62%</td>
    <td style="white-space: nowrap; text-align: right">2.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.86 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">153.43 K</td>
    <td style="white-space: nowrap; text-align: right">6.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.59%</td>
    <td style="white-space: nowrap; text-align: right">6.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.31 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">84.68 K</td>
    <td style="white-space: nowrap; text-align: right">11.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.27%</td>
    <td style="white-space: nowrap; text-align: right">10.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">42.38 K</td>
    <td style="white-space: nowrap; text-align: right">23.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.94%</td>
    <td style="white-space: nowrap; text-align: right">21.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">32.99 K</td>
    <td style="white-space: nowrap; text-align: right">30.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.66%</td>
    <td style="white-space: nowrap; text-align: right">29.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">26.18 K</td>
    <td style="white-space: nowrap; text-align: right">38.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.91%</td>
    <td style="white-space: nowrap; text-align: right">37.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">24.45 K</td>
    <td style="white-space: nowrap; text-align: right">40.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.54%</td>
    <td style="white-space: nowrap; text-align: right">40.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">13.79 K</td>
    <td style="white-space: nowrap; text-align: right">72.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.15%</td>
    <td style="white-space: nowrap; text-align: right">71.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">12.22 K</td>
    <td style="white-space: nowrap; text-align: right">81.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.76%</td>
    <td style="white-space: nowrap; text-align: right">80.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">96.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.69 K</td>
    <td style="white-space: nowrap; text-align: right">1456.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.81%</td>
    <td style="white-space: nowrap; text-align: right">1460.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1558.89 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap;text-align: right">4138.39 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2392.91 K</td>
    <td style="white-space: nowrap; text-align: right">1.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">361.69 K</td>
    <td style="white-space: nowrap; text-align: right">11.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">153.43 K</td>
    <td style="white-space: nowrap; text-align: right">26.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">84.68 K</td>
    <td style="white-space: nowrap; text-align: right">48.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">42.38 K</td>
    <td style="white-space: nowrap; text-align: right">97.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">32.99 K</td>
    <td style="white-space: nowrap; text-align: right">125.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">26.18 K</td>
    <td style="white-space: nowrap; text-align: right">158.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">24.45 K</td>
    <td style="white-space: nowrap; text-align: right">169.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">13.79 K</td>
    <td style="white-space: nowrap; text-align: right">300.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">12.22 K</td>
    <td style="white-space: nowrap; text-align: right">338.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.69 K</td>
    <td style="white-space: nowrap; text-align: right">6025.88x</td>
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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap">0.84 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap">0.79 KB</td>
    <td>0.95x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap">4.00 KB</td>
    <td>4.78x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap">9.94 KB</td>
    <td>11.9x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap">10.95 KB</td>
    <td>13.11x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">54.48 KB</td>
    <td>65.2x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">55.12 KB</td>
    <td>65.97x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap">93.39 KB</td>
    <td>111.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">45.38 KB</td>
    <td>54.31x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap">52.40 KB</td>
    <td>62.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">62.20 KB</td>
    <td>74.45x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap">414.29 KB</td>
    <td>495.83x</td>
  </tr>
</table>