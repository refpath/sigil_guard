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
- SigilGuard: 1.0.5 (39a9315)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.08 gateway overhead versus no-op | 62.914 |  |

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
    <td style="white-space: nowrap; text-align: right">290057.60 K</td>
    <td style="white-space: nowrap; text-align: right">0.00345 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.75%</td>
    <td style="white-space: nowrap; text-align: right">0.00347 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00437 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">33.85 K</td>
    <td style="white-space: nowrap; text-align: right">29.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.32%</td>
    <td style="white-space: nowrap; text-align: right">29.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">28.55 K</td>
    <td style="white-space: nowrap; text-align: right">35.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.54%</td>
    <td style="white-space: nowrap; text-align: right">35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">24.30 K</td>
    <td style="white-space: nowrap; text-align: right">41.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.34%</td>
    <td style="white-space: nowrap; text-align: right">40.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">24.22 K</td>
    <td style="white-space: nowrap; text-align: right">41.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.41%</td>
    <td style="white-space: nowrap; text-align: right">41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">21.76 K</td>
    <td style="white-space: nowrap; text-align: right">45.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.00%</td>
    <td style="white-space: nowrap; text-align: right">45.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">15.69 K</td>
    <td style="white-space: nowrap; text-align: right">63.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.86%</td>
    <td style="white-space: nowrap; text-align: right">62.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">79.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">14.76 K</td>
    <td style="white-space: nowrap; text-align: right">67.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.32%</td>
    <td style="white-space: nowrap; text-align: right">66.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.14 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">11.98 K</td>
    <td style="white-space: nowrap; text-align: right">83.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.79%</td>
    <td style="white-space: nowrap; text-align: right">81.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">102.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.00 K</td>
    <td style="white-space: nowrap; text-align: right">111.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.68%</td>
    <td style="white-space: nowrap; text-align: right">108.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">132.05 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">198.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.21%</td>
    <td style="white-space: nowrap; text-align: right">195.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">240.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">4.03 K</td>
    <td style="white-space: nowrap; text-align: right">248.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.58%</td>
    <td style="white-space: nowrap; text-align: right">245.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">318.87 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">290057.60 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap; text-align: right">33.85 K</td>
    <td style="white-space: nowrap; text-align: right">8567.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap; text-align: right">28.55 K</td>
    <td style="white-space: nowrap; text-align: right">10159.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap; text-align: right">24.30 K</td>
    <td style="white-space: nowrap; text-align: right">11938.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap; text-align: right">24.22 K</td>
    <td style="white-space: nowrap; text-align: right">11976.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap; text-align: right">21.76 K</td>
    <td style="white-space: nowrap; text-align: right">13331.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">15.69 K</td>
    <td style="white-space: nowrap; text-align: right">18486.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap; text-align: right">14.76 K</td>
    <td style="white-space: nowrap; text-align: right">19648.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">11.98 K</td>
    <td style="white-space: nowrap; text-align: right">24212.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap; text-align: right">9.00 K</td>
    <td style="white-space: nowrap; text-align: right">32243.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">57435.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap; text-align: right">4.03 K</td>
    <td style="white-space: nowrap; text-align: right">72060.49x</td>
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
    <td style="white-space: nowrap">BM.19 effect authority admit</td>
    <td style="white-space: nowrap">55.72 KB</td>
    <td>1829083.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result</td>
    <td style="white-space: nowrap">80.79 KB</td>
    <td>2652068.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest new</td>
    <td style="white-space: nowrap">80.91 KB</td>
    <td>2655915.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest verify</td>
    <td style="white-space: nowrap">79.72 KB</td>
    <td>2616933.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.18 capability manifest drifted fields</td>
    <td style="white-space: nowrap">85.68 KB</td>
    <td>2812613.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">87.98 KB</td>
    <td>2888013.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned compiled manifest</td>
    <td style="white-space: nowrap">105.48 KB</td>
    <td>3462743.69x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.17 guard_result pinned manifest</td>
    <td style="white-space: nowrap">177.37 KB</td>
    <td>5822446.31x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request pinned manifest</td>
    <td style="white-space: nowrap">186.84 KB</td>
    <td>6133534.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.16 guard_request required attestation</td>
    <td style="white-space: nowrap">284.38 KB</td>
    <td>9335456.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.19 guard_request effect binding</td>
    <td style="white-space: nowrap">470.75 KB</td>
    <td>15453346.46x</td>
  </tr>
</table>