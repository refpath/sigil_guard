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
- SigilGuard: 1.0.5 (1426856)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.08 gateway overhead versus no-op | 54.749 |  |

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
    <td style="white-space: nowrap; text-align: right">480197.47 K</td>
    <td style="white-space: nowrap; text-align: right">0.00208 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.65%</td>
    <td style="white-space: nowrap; text-align: right">0.00204 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00279 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">34.16 K</td>
    <td style="white-space: nowrap; text-align: right">29.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.53%</td>
    <td style="white-space: nowrap; text-align: right">28.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.65 K</td>
    <td style="white-space: nowrap; text-align: right">46.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.48%</td>
    <td style="white-space: nowrap; text-align: right">45.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">21.01 K</td>
    <td style="white-space: nowrap; text-align: right">47.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.41%</td>
    <td style="white-space: nowrap; text-align: right">47.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">18.95 K</td>
    <td style="white-space: nowrap; text-align: right">52.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.37%</td>
    <td style="white-space: nowrap; text-align: right">52.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">18.13 K</td>
    <td style="white-space: nowrap; text-align: right">55.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.95%</td>
    <td style="white-space: nowrap; text-align: right">54.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">17.24 K</td>
    <td style="white-space: nowrap; text-align: right">58.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.11%</td>
    <td style="white-space: nowrap; text-align: right">57.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">16.24 K</td>
    <td style="white-space: nowrap; text-align: right">61.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.99%</td>
    <td style="white-space: nowrap; text-align: right">61.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.05 K</td>
    <td style="white-space: nowrap; text-align: right">110.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.87%</td>
    <td style="white-space: nowrap; text-align: right">111.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">133.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">8.55 K</td>
    <td style="white-space: nowrap; text-align: right">116.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.10%</td>
    <td style="white-space: nowrap; text-align: right">117.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">139.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">4.86 K</td>
    <td style="white-space: nowrap; text-align: right">205.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.49%</td>
    <td style="white-space: nowrap; text-align: right">205.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">255.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">4.14 K</td>
    <td style="white-space: nowrap; text-align: right">241.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.71%</td>
    <td style="white-space: nowrap; text-align: right">239.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">299.98 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">480197.47 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">34.16 K</td>
    <td style="white-space: nowrap; text-align: right">14056.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.65 K</td>
    <td style="white-space: nowrap; text-align: right">22183.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">21.01 K</td>
    <td style="white-space: nowrap; text-align: right">22853.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">18.95 K</td>
    <td style="white-space: nowrap; text-align: right">25338.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">18.13 K</td>
    <td style="white-space: nowrap; text-align: right">26487.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">17.24 K</td>
    <td style="white-space: nowrap; text-align: right">27850.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">16.24 K</td>
    <td style="white-space: nowrap; text-align: right">29573.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.05 K</td>
    <td style="white-space: nowrap; text-align: right">53080.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">8.55 K</td>
    <td style="white-space: nowrap; text-align: right">56154.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">4.86 K</td>
    <td style="white-space: nowrap; text-align: right">98900.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">4.14 K</td>
    <td style="white-space: nowrap; text-align: right">115965.83x</td>
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
    <td style="white-space: nowrap">51.52 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap">80.46 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap">78.34 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap">80.66 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">85.32 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap">85.63 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap">102.43 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap">174.94 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap">183.93 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap">280.03 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap">455.95 KB</td>
    <td>&mdash;</td>
  </tr>
</table>