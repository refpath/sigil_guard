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
- SigilGuard: 1.0.5 (3471773)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.08 gateway overhead versus no-op | 46.790 |  |

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
    <td style="white-space: nowrap; text-align: right">245859.21 K</td>
    <td style="white-space: nowrap; text-align: right">0.00407 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;119.60%</td>
    <td style="white-space: nowrap; text-align: right">0.00217 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.0180 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">30.58 K</td>
    <td style="white-space: nowrap; text-align: right">32.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.04%</td>
    <td style="white-space: nowrap; text-align: right">32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">25.43 K</td>
    <td style="white-space: nowrap; text-align: right">39.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.92%</td>
    <td style="white-space: nowrap; text-align: right">38.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.90 K</td>
    <td style="white-space: nowrap; text-align: right">45.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.14%</td>
    <td style="white-space: nowrap; text-align: right">44.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">21.46 K</td>
    <td style="white-space: nowrap; text-align: right">46.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.30%</td>
    <td style="white-space: nowrap; text-align: right">45.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">20.70 K</td>
    <td style="white-space: nowrap; text-align: right">48.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.55%</td>
    <td style="white-space: nowrap; text-align: right">46.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">20.29 K</td>
    <td style="white-space: nowrap; text-align: right">49.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.47%</td>
    <td style="white-space: nowrap; text-align: right">48.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.27 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">17.82 K</td>
    <td style="white-space: nowrap; text-align: right">56.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.99%</td>
    <td style="white-space: nowrap; text-align: right">55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.75 K</td>
    <td style="white-space: nowrap; text-align: right">93.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.87%</td>
    <td style="white-space: nowrap; text-align: right">91.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">119.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.66 K</td>
    <td style="white-space: nowrap; text-align: right">103.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.59%</td>
    <td style="white-space: nowrap; text-align: right">102.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">130.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">4.89 K</td>
    <td style="white-space: nowrap; text-align: right">204.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.02%</td>
    <td style="white-space: nowrap; text-align: right">203.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">261.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.62 K</td>
    <td style="white-space: nowrap; text-align: right">276.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.30%</td>
    <td style="white-space: nowrap; text-align: right">276.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">382.52 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">245859.21 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">30.58 K</td>
    <td style="white-space: nowrap; text-align: right">8038.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">25.43 K</td>
    <td style="white-space: nowrap; text-align: right">9667.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">21.90 K</td>
    <td style="white-space: nowrap; text-align: right">11224.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">21.46 K</td>
    <td style="white-space: nowrap; text-align: right">11458.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">20.70 K</td>
    <td style="white-space: nowrap; text-align: right">11878.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">20.29 K</td>
    <td style="white-space: nowrap; text-align: right">12119.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">17.82 K</td>
    <td style="white-space: nowrap; text-align: right">13793.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">10.75 K</td>
    <td style="white-space: nowrap; text-align: right">22873.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.66 K</td>
    <td style="white-space: nowrap; text-align: right">25458.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">4.89 K</td>
    <td style="white-space: nowrap; text-align: right">50289.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">3.62 K</td>
    <td style="white-space: nowrap; text-align: right">67899.56x</td>
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
    <td style="white-space: nowrap">55.72 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap">80.77 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap">80.95 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap">80.77 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">87.79 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap">85.16 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap">104.66 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap">178.21 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap">186.76 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap">283.50 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap">459.38 KB</td>
    <td>&mdash;</td>
  </tr>
</table>