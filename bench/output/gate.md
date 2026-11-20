# Runtime Gate and Policy Benchmarks

`SigilGuard.Runtime.Gate.evaluate/3` is the decision a host makes at each
boundary: scan, quarantine check, risk and trust ladder, and the policy
kernel. The suite times the four verdict paths, the ladder and the kernel
alone, a policy file with an output contract, and repo policy for a file
change.

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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap; text-align: right">3327.90 K</td>
    <td style="white-space: nowrap; text-align: right">0.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2169.39%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2011.54 K</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1205.29%</td>
    <td style="white-space: nowrap; text-align: right">0.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">335.92 K</td>
    <td style="white-space: nowrap; text-align: right">2.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;289.55%</td>
    <td style="white-space: nowrap; text-align: right">2.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">167.14 K</td>
    <td style="white-space: nowrap; text-align: right">5.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;73.61%</td>
    <td style="white-space: nowrap; text-align: right">5.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">10.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">97.15 K</td>
    <td style="white-space: nowrap; text-align: right">10.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.48%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">39.06 K</td>
    <td style="white-space: nowrap; text-align: right">25.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.04%</td>
    <td style="white-space: nowrap; text-align: right">24.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">29.95 K</td>
    <td style="white-space: nowrap; text-align: right">33.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.42%</td>
    <td style="white-space: nowrap; text-align: right">32.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">24.70 K</td>
    <td style="white-space: nowrap; text-align: right">40.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.19%</td>
    <td style="white-space: nowrap; text-align: right">40.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">24.05 K</td>
    <td style="white-space: nowrap; text-align: right">41.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.57%</td>
    <td style="white-space: nowrap; text-align: right">40.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">21.42 K</td>
    <td style="white-space: nowrap; text-align: right">46.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.56%</td>
    <td style="white-space: nowrap; text-align: right">45.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">14.28 K</td>
    <td style="white-space: nowrap; text-align: right">70.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.67%</td>
    <td style="white-space: nowrap; text-align: right">69.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">95.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.61 K</td>
    <td style="white-space: nowrap; text-align: right">1627.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.00%</td>
    <td style="white-space: nowrap; text-align: right">1628.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1972.80 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3327.90 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">2011.54 K</td>
    <td style="white-space: nowrap; text-align: right">1.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">335.92 K</td>
    <td style="white-space: nowrap; text-align: right">9.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">167.14 K</td>
    <td style="white-space: nowrap; text-align: right">19.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">97.15 K</td>
    <td style="white-space: nowrap; text-align: right">34.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">39.06 K</td>
    <td style="white-space: nowrap; text-align: right">85.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">29.95 K</td>
    <td style="white-space: nowrap; text-align: right">111.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">24.70 K</td>
    <td style="white-space: nowrap; text-align: right">134.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">24.05 K</td>
    <td style="white-space: nowrap; text-align: right">138.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">21.42 K</td>
    <td style="white-space: nowrap; text-align: right">155.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">14.28 K</td>
    <td style="white-space: nowrap; text-align: right">233.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.61 K</td>
    <td style="white-space: nowrap; text-align: right">5415.05x</td>
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
    <td>0.94x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap">3.18 KB</td>
    <td>3.8x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap">9.67 KB</td>
    <td>11.57x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap">12.23 KB</td>
    <td>14.64x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">53.59 KB</td>
    <td>64.11x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">55.32 KB</td>
    <td>66.18x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">45.19 KB</td>
    <td>54.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap">93.82 KB</td>
    <td>112.23x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">61.44 KB</td>
    <td>73.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap">52.82 KB</td>
    <td>63.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap">413.55 KB</td>
    <td>494.71x</td>
  </tr>
</table>