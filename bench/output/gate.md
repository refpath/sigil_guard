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
    <td style="white-space: nowrap">BM.12 policy verdict blocked</td>
    <td style="white-space: nowrap; text-align: right">3054.36 K</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1796.87%</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">1813.86 K</td>
    <td style="white-space: nowrap; text-align: right">0.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1128.29%</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">311.72 K</td>
    <td style="white-space: nowrap; text-align: right">3.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;270.61%</td>
    <td style="white-space: nowrap; text-align: right">2.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">174.79 K</td>
    <td style="white-space: nowrap; text-align: right">5.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;76.86%</td>
    <td style="white-space: nowrap; text-align: right">5.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">95.21 K</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.98%</td>
    <td style="white-space: nowrap; text-align: right">10.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">34.88 K</td>
    <td style="white-space: nowrap; text-align: right">28.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.40%</td>
    <td style="white-space: nowrap; text-align: right">26.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">25.80 K</td>
    <td style="white-space: nowrap; text-align: right">38.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.83%</td>
    <td style="white-space: nowrap; text-align: right">38.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">25.69 K</td>
    <td style="white-space: nowrap; text-align: right">38.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.64%</td>
    <td style="white-space: nowrap; text-align: right">37.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.59 K</td>
    <td style="white-space: nowrap; text-align: right">51.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.92%</td>
    <td style="white-space: nowrap; text-align: right">50.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.62 K</td>
    <td style="white-space: nowrap; text-align: right">79.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.91%</td>
    <td style="white-space: nowrap; text-align: right">79.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">101.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">7.18 K</td>
    <td style="white-space: nowrap; text-align: right">139.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.82%</td>
    <td style="white-space: nowrap; text-align: right">135.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">163.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.29 K</td>
    <td style="white-space: nowrap; text-align: right">3507.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.65%</td>
    <td style="white-space: nowrap; text-align: right">3499.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3875.91 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3054.36 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.12 policy verdict allowed</td>
    <td style="white-space: nowrap; text-align: right">1813.86 K</td>
    <td style="white-space: nowrap; text-align: right">1.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.13 boundary policy kernel</td>
    <td style="white-space: nowrap; text-align: right">311.72 K</td>
    <td style="white-space: nowrap; text-align: right">9.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy evaluate</td>
    <td style="white-space: nowrap; text-align: right">174.79 K</td>
    <td style="white-space: nowrap; text-align: right">17.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 repo policy compile</td>
    <td style="white-space: nowrap; text-align: right">95.21 K</td>
    <td style="white-space: nowrap; text-align: right">32.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">34.88 K</td>
    <td style="white-space: nowrap; text-align: right">87.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">25.80 K</td>
    <td style="white-space: nowrap; text-align: right">118.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap; text-align: right">25.69 K</td>
    <td style="white-space: nowrap; text-align: right">118.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.59 K</td>
    <td style="white-space: nowrap; text-align: right">155.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap; text-align: right">12.62 K</td>
    <td style="white-space: nowrap; text-align: right">242.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">7.18 K</td>
    <td style="white-space: nowrap; text-align: right">425.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap; text-align: right">0.29 K</td>
    <td style="white-space: nowrap; text-align: right">10713.91x</td>
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
    <td style="white-space: nowrap">51.29 KB</td>
    <td>61.36x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">52.13 KB</td>
    <td>62.36x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.15 runtime gate repo change</td>
    <td style="white-space: nowrap">86.26 KB</td>
    <td>103.19x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">58.38 KB</td>
    <td>69.84x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 policy file parse</td>
    <td style="white-space: nowrap">52.61 KB</td>
    <td>62.93x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">41.73 KB</td>
    <td>49.93x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.14 runtime gate with output contract</td>
    <td style="white-space: nowrap">442.66 KB</td>
    <td>529.54x</td>
  </tr>
</table>