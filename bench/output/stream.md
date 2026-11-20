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
- SigilGuard: 1.0.5 (1426856)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-11-20

## Derived figures

| Figure | Median (us) | Percent |
|--------|------------:|--------:|
| BM.04 stream median per chunk | 137.619 |  |
| BM.04 stream overhead versus single pass | 13414.924 | 319.4 |

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
    <td style="white-space: nowrap; text-align: right">235.54</td>
    <td style="white-space: nowrap; text-align: right">4.25 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.39%</td>
    <td style="white-space: nowrap; text-align: right">4.20 ms</td>
    <td style="white-space: nowrap; text-align: right">5.04 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">56.09</td>
    <td style="white-space: nowrap; text-align: right">17.83 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.37%</td>
    <td style="white-space: nowrap; text-align: right">17.62 ms</td>
    <td style="white-space: nowrap; text-align: right">21.10 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap; text-align: right">55.85</td>
    <td style="white-space: nowrap; text-align: right">17.91 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.98%</td>
    <td style="white-space: nowrap; text-align: right">17.78 ms</td>
    <td style="white-space: nowrap; text-align: right">19.88 ms</td>
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
    <td style="white-space: nowrap;text-align: right">235.54</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">56.09</td>
    <td style="white-space: nowrap; text-align: right">4.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap; text-align: right">55.85</td>
    <td style="white-space: nowrap; text-align: right">4.22x</td>
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
    <td style="white-space: nowrap">1.80 MB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap">5.68 MB</td>
    <td>3.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k clean</td>
    <td style="white-space: nowrap">5.62 MB</td>
    <td>3.11x</td>
  </tr>
</table>