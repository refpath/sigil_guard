# Scanner Benchmarks

Every boundary crossing starts with a scan, so its cost bounds everything
built on it. The suite scans clean text and text with one documented
synthetic secret per 4 KiB at three sizes, redacts what it finds, runs the
quarantine inspector that looks for prompt injection, and compiles a
bundle's pattern entries into the sets the scanner uses.

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
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">109.62 K</td>
    <td style="white-space: nowrap; text-align: right">9.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;85.24%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">69.35 K</td>
    <td style="white-space: nowrap; text-align: right">14.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.27%</td>
    <td style="white-space: nowrap; text-align: right">13.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">62.50 K</td>
    <td style="white-space: nowrap; text-align: right">16.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.28%</td>
    <td style="white-space: nowrap; text-align: right">15.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">58.47 K</td>
    <td style="white-space: nowrap; text-align: right">17.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.52%</td>
    <td style="white-space: nowrap; text-align: right">16.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">57.18 K</td>
    <td style="white-space: nowrap; text-align: right">17.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.44%</td>
    <td style="white-space: nowrap; text-align: right">16.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">40.54 K</td>
    <td style="white-space: nowrap; text-align: right">24.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.37%</td>
    <td style="white-space: nowrap; text-align: right">23.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.13 K</td>
    <td style="white-space: nowrap; text-align: right">885.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.60%</td>
    <td style="white-space: nowrap; text-align: right">858.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1025.51 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.12 K</td>
    <td style="white-space: nowrap; text-align: right">891.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.68%</td>
    <td style="white-space: nowrap; text-align: right">886.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1024.32 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.09 K</td>
    <td style="white-space: nowrap; text-align: right">916.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.89%</td>
    <td style="white-space: nowrap; text-align: right">912.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1043.95 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0718 K</td>
    <td style="white-space: nowrap; text-align: right">13919.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.81%</td>
    <td style="white-space: nowrap; text-align: right">13969.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15259.62 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0660 K</td>
    <td style="white-space: nowrap; text-align: right">15140.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.11%</td>
    <td style="white-space: nowrap; text-align: right">15130.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16967.89 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap;text-align: right">109.62 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">69.35 K</td>
    <td style="white-space: nowrap; text-align: right">1.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">62.50 K</td>
    <td style="white-space: nowrap; text-align: right">1.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">58.47 K</td>
    <td style="white-space: nowrap; text-align: right">1.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">57.18 K</td>
    <td style="white-space: nowrap; text-align: right">1.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">40.54 K</td>
    <td style="white-space: nowrap; text-align: right">2.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.13 K</td>
    <td style="white-space: nowrap; text-align: right">97.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.12 K</td>
    <td style="white-space: nowrap; text-align: right">97.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.09 K</td>
    <td style="white-space: nowrap; text-align: right">100.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0718 K</td>
    <td style="white-space: nowrap; text-align: right">1525.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0660 K</td>
    <td style="white-space: nowrap; text-align: right">1659.61x</td>
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
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap">7.85 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">3.13 KB</td>
    <td>0.4x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap">9.85 KB</td>
    <td>1.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">10.82 KB</td>
    <td>1.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap">11.10 KB</td>
    <td>1.41x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap">2.88 KB</td>
    <td>0.37x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap">129.06 KB</td>
    <td>16.44x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.16 KB</td>
    <td>0.4x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">125.61 KB</td>
    <td>16.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.27 KB</td>
    <td>0.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1976.29 KB</td>
    <td>251.71x</td>
  </tr>
</table>