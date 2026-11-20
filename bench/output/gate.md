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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap; text-align: right">3057.80 K</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1804.55%</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">1232.32 K</td>
    <td style="white-space: nowrap; text-align: right">0.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;813.74%</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">319.85 K</td>
    <td style="white-space: nowrap; text-align: right">3.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;372.51%</td>
    <td style="white-space: nowrap; text-align: right">2.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">162.93 K</td>
    <td style="white-space: nowrap; text-align: right">6.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;70.01%</td>
    <td style="white-space: nowrap; text-align: right">5.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">107.62 K</td>
    <td style="white-space: nowrap; text-align: right">9.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.14%</td>
    <td style="white-space: nowrap; text-align: right">9.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">28.73 K</td>
    <td style="white-space: nowrap; text-align: right">34.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.99%</td>
    <td style="white-space: nowrap; text-align: right">35.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">24.18 K</td>
    <td style="white-space: nowrap; text-align: right">41.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.98%</td>
    <td style="white-space: nowrap; text-align: right">40.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">23.51 K</td>
    <td style="white-space: nowrap; text-align: right">42.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.30%</td>
    <td style="white-space: nowrap; text-align: right">43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.68 K</td>
    <td style="white-space: nowrap; text-align: right">50.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.38%</td>
    <td style="white-space: nowrap; text-align: right">51.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">14.76 K</td>
    <td style="white-space: nowrap; text-align: right">67.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.35%</td>
    <td style="white-space: nowrap; text-align: right">68.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.14 K</td>
    <td style="white-space: nowrap; text-align: right">82.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.08%</td>
    <td style="white-space: nowrap; text-align: right">81.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">104.87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.51 K</td>
    <td style="white-space: nowrap; text-align: right">1950.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.32%</td>
    <td style="white-space: nowrap; text-align: right">1961.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2137.25 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3057.80 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">1232.32 K</td>
    <td style="white-space: nowrap; text-align: right">2.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">319.85 K</td>
    <td style="white-space: nowrap; text-align: right">9.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">162.93 K</td>
    <td style="white-space: nowrap; text-align: right">18.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">107.62 K</td>
    <td style="white-space: nowrap; text-align: right">28.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">28.73 K</td>
    <td style="white-space: nowrap; text-align: right">106.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">24.18 K</td>
    <td style="white-space: nowrap; text-align: right">126.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">23.51 K</td>
    <td style="white-space: nowrap; text-align: right">130.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.68 K</td>
    <td style="white-space: nowrap; text-align: right">155.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">14.76 K</td>
    <td style="white-space: nowrap; text-align: right">207.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.14 K</td>
    <td style="white-space: nowrap; text-align: right">251.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.51 K</td>
    <td style="white-space: nowrap; text-align: right">5965.29x</td>
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
    <td style="white-space: nowrap">3.13 KB</td>
    <td>3.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap">8.85 KB</td>
    <td>10.59x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap">12.23 KB</td>
    <td>14.64x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">51.74 KB</td>
    <td>61.9x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap">87.16 KB</td>
    <td>104.26x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">53.80 KB</td>
    <td>64.36x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">60.04 KB</td>
    <td>71.82x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">43.71 KB</td>
    <td>52.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap">52.82 KB</td>
    <td>63.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap">411.77 KB</td>
    <td>492.58x</td>
  </tr>
</table>