# Streaming Benchmarks

`SigilGuard.Runtime.Stream` evaluates each pushed chunk together with the
bytes it still holds back, so that a secret split across two chunks is
caught. The suite pushes 64 KiB in 128 chunks of 512 bytes, with one
secret across a chunk boundary, and compares that with one gate
evaluation over the same bytes. The context has high trust, so secrets
are redacted and every chunk is evaluated. At low trust the first secret
asks for confirmation and halts the stream.

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
| BM.04 stream median per chunk | 129.751 |  |
| BM.04 stream overhead versus single pass | 12687.883 | 323.6 |

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
    <td style="white-space: nowrap">BM.04 single pass gate 64k</td>
    <td style="white-space: nowrap; text-align: right">254.77</td>
    <td style="white-space: nowrap; text-align: right">3.93 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.27%</td>
    <td style="white-space: nowrap; text-align: right">3.92 ms</td>
    <td style="white-space: nowrap; text-align: right">4.75 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">60.30</td>
    <td style="white-space: nowrap; text-align: right">16.58 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.44%</td>
    <td style="white-space: nowrap; text-align: right">16.61 ms</td>
    <td style="white-space: nowrap; text-align: right">20.03 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap; text-align: right">58.76</td>
    <td style="white-space: nowrap; text-align: right">17.02 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.63%</td>
    <td style="white-space: nowrap; text-align: right">16.96 ms</td>
    <td style="white-space: nowrap; text-align: right">23.00 ms</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.04 single pass gate 64k</td>
    <td style="white-space: nowrap;text-align: right">254.77</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">60.30</td>
    <td style="white-space: nowrap; text-align: right">4.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap; text-align: right">58.76</td>
    <td style="white-space: nowrap; text-align: right">4.34x</td>
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
    <td style="white-space: nowrap">BM.04 single pass gate 64k</td>
    <td style="white-space: nowrap">1.81 MB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap">5.90 MB</td>
    <td>3.27x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap">5.84 MB</td>
    <td>3.24x</td>
  </tr>
</table>