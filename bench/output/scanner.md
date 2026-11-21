# Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

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
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">162.80 K</td>
    <td style="white-space: nowrap; text-align: right">6.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.80%</td>
    <td style="white-space: nowrap; text-align: right">6.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">126.33 K</td>
    <td style="white-space: nowrap; text-align: right">7.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.38%</td>
    <td style="white-space: nowrap; text-align: right">7.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">80.54 K</td>
    <td style="white-space: nowrap; text-align: right">12.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.27%</td>
    <td style="white-space: nowrap; text-align: right">12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">66.22 K</td>
    <td style="white-space: nowrap; text-align: right">15.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.33%</td>
    <td style="white-space: nowrap; text-align: right">14.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">64.76 K</td>
    <td style="white-space: nowrap; text-align: right">15.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.03%</td>
    <td style="white-space: nowrap; text-align: right">14.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">31.05 K</td>
    <td style="white-space: nowrap; text-align: right">32.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.42%</td>
    <td style="white-space: nowrap; text-align: right">31.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.31 K</td>
    <td style="white-space: nowrap; text-align: right">761.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.18%</td>
    <td style="white-space: nowrap; text-align: right">761.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">804.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.27 K</td>
    <td style="white-space: nowrap; text-align: right">790.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.94%</td>
    <td style="white-space: nowrap; text-align: right">790.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">830.48 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.25 K</td>
    <td style="white-space: nowrap; text-align: right">801.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.85%</td>
    <td style="white-space: nowrap; text-align: right">799.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">882.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0815 K</td>
    <td style="white-space: nowrap; text-align: right">12264.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.29%</td>
    <td style="white-space: nowrap; text-align: right">12247.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12590.53 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0754 K</td>
    <td style="white-space: nowrap; text-align: right">13260.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.07%</td>
    <td style="white-space: nowrap; text-align: right">13269.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13573.36 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap;text-align: right">162.80 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">126.33 K</td>
    <td style="white-space: nowrap; text-align: right">1.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">80.54 K</td>
    <td style="white-space: nowrap; text-align: right">2.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">66.22 K</td>
    <td style="white-space: nowrap; text-align: right">2.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">64.76 K</td>
    <td style="white-space: nowrap; text-align: right">2.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">31.05 K</td>
    <td style="white-space: nowrap; text-align: right">5.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.31 K</td>
    <td style="white-space: nowrap; text-align: right">124.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.27 K</td>
    <td style="white-space: nowrap; text-align: right">128.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.25 K</td>
    <td style="white-space: nowrap; text-align: right">130.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0815 K</td>
    <td style="white-space: nowrap; text-align: right">1996.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0754 K</td>
    <td style="white-space: nowrap; text-align: right">2158.92x</td>
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
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap">3.00 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap">7.61 KB</td>
    <td>2.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">3.30 KB</td>
    <td>1.1x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">10.78 KB</td>
    <td>3.6x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap">11.21 KB</td>
    <td>3.74x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap">10.05 KB</td>
    <td>3.36x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.33 KB</td>
    <td>1.11x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">125.83 KB</td>
    <td>42.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap">128.66 KB</td>
    <td>42.94x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.45 KB</td>
    <td>1.15x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1976.67 KB</td>
    <td>659.75x</td>
  </tr>
</table>