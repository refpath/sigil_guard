# Tool Gateway Benchmarks

`SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
result. The suite times a request with and without a pinned capability
manifest and with a required inbound attestation, a result, manifest
validation and drift comparison, and a physical-effect request with its
admission check. The no-op baseline is an empty function in the same run.

Mode: measured. Values are measured for this environment, not ratified SLO bounds.


## Environment

- Hardware: Apple M4 Max, 16 cores, 128 GB RAM
- OS: unix/darwin
- Elixir: 1.20.4 / OTP: 29
- SigilGuard: 1.0.5 (0eca0a4)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.08 gateway overhead versus no-op | 45.873 |  |

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
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap; text-align: right">464050.24 K</td>
    <td style="white-space: nowrap; text-align: right">0.00215 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;96.13%</td>
    <td style="white-space: nowrap; text-align: right">0.00213 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00279 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">31.72 K</td>
    <td style="white-space: nowrap; text-align: right">31.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.13%</td>
    <td style="white-space: nowrap; text-align: right">31.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">23.05 K</td>
    <td style="white-space: nowrap; text-align: right">43.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.97%</td>
    <td style="white-space: nowrap; text-align: right">42.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.99 K</td>
    <td style="white-space: nowrap; text-align: right">45.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.39%</td>
    <td style="white-space: nowrap; text-align: right">44.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">21.63 K</td>
    <td style="white-space: nowrap; text-align: right">46.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.49%</td>
    <td style="white-space: nowrap; text-align: right">45.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">20.46 K</td>
    <td style="white-space: nowrap; text-align: right">48.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.64%</td>
    <td style="white-space: nowrap; text-align: right">48.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">19.69 K</td>
    <td style="white-space: nowrap; text-align: right">50.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.85%</td>
    <td style="white-space: nowrap; text-align: right">49.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">18.42 K</td>
    <td style="white-space: nowrap; text-align: right">54.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.97%</td>
    <td style="white-space: nowrap; text-align: right">53.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.55 K</td>
    <td style="white-space: nowrap; text-align: right">94.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.59%</td>
    <td style="white-space: nowrap; text-align: right">93.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.30 K</td>
    <td style="white-space: nowrap; text-align: right">97.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.00%</td>
    <td style="white-space: nowrap; text-align: right">95.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">127.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.04 K</td>
    <td style="white-space: nowrap; text-align: right">198.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.01%</td>
    <td style="white-space: nowrap; text-align: right">194.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">259.28 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.76 K</td>
    <td style="white-space: nowrap; text-align: right">265.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.59%</td>
    <td style="white-space: nowrap; text-align: right">260.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">396.97 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap;text-align: right">464050.24 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">31.72 K</td>
    <td style="white-space: nowrap; text-align: right">14629.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">23.05 K</td>
    <td style="white-space: nowrap; text-align: right">20132.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.99 K</td>
    <td style="white-space: nowrap; text-align: right">21102.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">21.63 K</td>
    <td style="white-space: nowrap; text-align: right">21458.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">20.46 K</td>
    <td style="white-space: nowrap; text-align: right">22684.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">19.69 K</td>
    <td style="white-space: nowrap; text-align: right">23571.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">18.42 K</td>
    <td style="white-space: nowrap; text-align: right">25189.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.55 K</td>
    <td style="white-space: nowrap; text-align: right">43994.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.30 K</td>
    <td style="white-space: nowrap; text-align: right">45054.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.04 K</td>
    <td style="white-space: nowrap; text-align: right">92027.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.76 K</td>
    <td style="white-space: nowrap; text-align: right">123321.69x</td>
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
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap">0 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap">49.38 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap">74.91 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap">80.41 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">83.04 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap">80.54 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap">85.70 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap">99.91 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap">171.78 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap">182.70 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap">278.48 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap">459.92 KB</td>
    <td>&mdash;</td>
  </tr>
</table>