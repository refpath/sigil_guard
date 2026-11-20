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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap; text-align: right">3523.75 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.69%</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.51 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2207.26 K</td>
    <td style="white-space: nowrap; text-align: right">0.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.39%</td>
    <td style="white-space: nowrap; text-align: right">0.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">314.27 K</td>
    <td style="white-space: nowrap; text-align: right">3.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;73.58%</td>
    <td style="white-space: nowrap; text-align: right">2.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">142.75 K</td>
    <td style="white-space: nowrap; text-align: right">7.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.60%</td>
    <td style="white-space: nowrap; text-align: right">6.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">73.96 K</td>
    <td style="white-space: nowrap; text-align: right">13.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.39%</td>
    <td style="white-space: nowrap; text-align: right">12.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">37.86 K</td>
    <td style="white-space: nowrap; text-align: right">26.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.11%</td>
    <td style="white-space: nowrap; text-align: right">25.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">30.14 K</td>
    <td style="white-space: nowrap; text-align: right">33.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.76%</td>
    <td style="white-space: nowrap; text-align: right">32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">25.00 K</td>
    <td style="white-space: nowrap; text-align: right">40.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.24%</td>
    <td style="white-space: nowrap; text-align: right">39.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">21.34 K</td>
    <td style="white-space: nowrap; text-align: right">46.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.00%</td>
    <td style="white-space: nowrap; text-align: right">46.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.77 K</td>
    <td style="white-space: nowrap; text-align: right">78.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.44%</td>
    <td style="white-space: nowrap; text-align: right">77.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">103.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">10.92 K</td>
    <td style="white-space: nowrap; text-align: right">91.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.39%</td>
    <td style="white-space: nowrap; text-align: right">89.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">116.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.62 K</td>
    <td style="white-space: nowrap; text-align: right">1607.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.23%</td>
    <td style="white-space: nowrap; text-align: right">1571.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1913.79 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3523.75 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2207.26 K</td>
    <td style="white-space: nowrap; text-align: right">1.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">314.27 K</td>
    <td style="white-space: nowrap; text-align: right">11.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">142.75 K</td>
    <td style="white-space: nowrap; text-align: right">24.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">73.96 K</td>
    <td style="white-space: nowrap; text-align: right">47.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">37.86 K</td>
    <td style="white-space: nowrap; text-align: right">93.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">30.14 K</td>
    <td style="white-space: nowrap; text-align: right">116.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">25.00 K</td>
    <td style="white-space: nowrap; text-align: right">140.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">21.34 K</td>
    <td style="white-space: nowrap; text-align: right">165.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.77 K</td>
    <td style="white-space: nowrap; text-align: right">275.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">10.92 K</td>
    <td style="white-space: nowrap; text-align: right">322.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.62 K</td>
    <td style="white-space: nowrap; text-align: right">5665.5x</td>
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
    <td>4.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap">10.02 KB</td>
    <td>11.99x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap">13.02 KB</td>
    <td>15.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">53.62 KB</td>
    <td>64.17x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">55.34 KB</td>
    <td>66.24x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap">94.14 KB</td>
    <td>112.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">45.21 KB</td>
    <td>54.11x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap">53.29 KB</td>
    <td>63.78x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">62.04 KB</td>
    <td>74.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap">413.83 KB</td>
    <td>495.29x</td>
  </tr>
</table>