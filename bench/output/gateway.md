# Tool Gateway Benchmarks

`SigilGuard.ToolGateway` guards each MCP `tools/call` request and each
result. The suite times a request with and without a pinned capability
manifest and with a required inbound attestation, a result, manifest
validation and drift comparison, and a physical-effect request with its
admission check. The no-op baseline is an empty function in the same run.

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

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.08 gateway overhead versus no-op | 62.330 |  |

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
    <td style="white-space: nowrap; text-align: right">306981.25 K</td>
    <td style="white-space: nowrap; text-align: right">0.00326 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.94%</td>
    <td style="white-space: nowrap; text-align: right">0.00316 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00359 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">29.07 K</td>
    <td style="white-space: nowrap; text-align: right">34.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.56%</td>
    <td style="white-space: nowrap; text-align: right">33.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">25.35 K</td>
    <td style="white-space: nowrap; text-align: right">39.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.50%</td>
    <td style="white-space: nowrap; text-align: right">38.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">23.68 K</td>
    <td style="white-space: nowrap; text-align: right">42.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.20%</td>
    <td style="white-space: nowrap; text-align: right">41.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">23.62 K</td>
    <td style="white-space: nowrap; text-align: right">42.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.28%</td>
    <td style="white-space: nowrap; text-align: right">41.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">20.91 K</td>
    <td style="white-space: nowrap; text-align: right">47.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.18%</td>
    <td style="white-space: nowrap; text-align: right">46.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">16.00 K</td>
    <td style="white-space: nowrap; text-align: right">62.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.20%</td>
    <td style="white-space: nowrap; text-align: right">62.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">15.10 K</td>
    <td style="white-space: nowrap; text-align: right">66.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.95%</td>
    <td style="white-space: nowrap; text-align: right">65.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">12.40 K</td>
    <td style="white-space: nowrap; text-align: right">80.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.88%</td>
    <td style="white-space: nowrap; text-align: right">78.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.86 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">8.61 K</td>
    <td style="white-space: nowrap; text-align: right">116.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.45%</td>
    <td style="white-space: nowrap; text-align: right">116.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">138.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">197.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.66%</td>
    <td style="white-space: nowrap; text-align: right">196.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">235.77 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.95 K</td>
    <td style="white-space: nowrap; text-align: right">253.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.53%</td>
    <td style="white-space: nowrap; text-align: right">252.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">307.70 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">306981.25 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">29.07 K</td>
    <td style="white-space: nowrap; text-align: right">10558.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">25.35 K</td>
    <td style="white-space: nowrap; text-align: right">12110.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">23.68 K</td>
    <td style="white-space: nowrap; text-align: right">12964.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">23.62 K</td>
    <td style="white-space: nowrap; text-align: right">12995.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">20.91 K</td>
    <td style="white-space: nowrap; text-align: right">14680.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">16.00 K</td>
    <td style="white-space: nowrap; text-align: right">19191.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">15.10 K</td>
    <td style="white-space: nowrap; text-align: right">20333.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">12.40 K</td>
    <td style="white-space: nowrap; text-align: right">24758.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">8.61 K</td>
    <td style="white-space: nowrap; text-align: right">35642.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">60733.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.95 K</td>
    <td style="white-space: nowrap; text-align: right">77702.49x</td>
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
    <td style="white-space: nowrap">0.00003 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap">80.88 KB</td>
    <td>2654889.85x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap">83.31 KB</td>
    <td>2734905.85x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap">80.02 KB</td>
    <td>2626679.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap">79.09 KB</td>
    <td>2596160.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap">83.94 KB</td>
    <td>2755422.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">87.91 KB</td>
    <td>2885961.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap">105.53 KB</td>
    <td>3464282.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap">176.47 KB</td>
    <td>5792953.23x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap">185.91 KB</td>
    <td>6102758.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap">283.23 KB</td>
    <td>9297500.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap">481.05 KB</td>
    <td>15791619.23x</td>
  </tr>
</table>