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
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">117.36 K</td>
    <td style="white-space: nowrap; text-align: right">8.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;98.54%</td>
    <td style="white-space: nowrap; text-align: right">7.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">68.94 K</td>
    <td style="white-space: nowrap; text-align: right">14.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.34%</td>
    <td style="white-space: nowrap; text-align: right">13.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">63.40 K</td>
    <td style="white-space: nowrap; text-align: right">15.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.68%</td>
    <td style="white-space: nowrap; text-align: right">15.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">59.55 K</td>
    <td style="white-space: nowrap; text-align: right">16.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.20%</td>
    <td style="white-space: nowrap; text-align: right">16.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">56.76 K</td>
    <td style="white-space: nowrap; text-align: right">17.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.94%</td>
    <td style="white-space: nowrap; text-align: right">16.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">106.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.89%</td>
    <td style="white-space: nowrap; text-align: right">107.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">123.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.16 K</td>
    <td style="white-space: nowrap; text-align: right">862.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.38%</td>
    <td style="white-space: nowrap; text-align: right">847.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">979.30 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.14 K</td>
    <td style="white-space: nowrap; text-align: right">877.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.20%</td>
    <td style="white-space: nowrap; text-align: right">872.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">972.64 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.10 K</td>
    <td style="white-space: nowrap; text-align: right">906.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.67%</td>
    <td style="white-space: nowrap; text-align: right">900.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1002.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0728 K</td>
    <td style="white-space: nowrap; text-align: right">13733.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.65%</td>
    <td style="white-space: nowrap; text-align: right">13612.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14640.36 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0687 K</td>
    <td style="white-space: nowrap; text-align: right">14565.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.66%</td>
    <td style="white-space: nowrap; text-align: right">14578.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15439.31 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">117.36 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">68.94 K</td>
    <td style="white-space: nowrap; text-align: right">1.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">63.40 K</td>
    <td style="white-space: nowrap; text-align: right">1.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">59.55 K</td>
    <td style="white-space: nowrap; text-align: right">1.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">56.76 K</td>
    <td style="white-space: nowrap; text-align: right">2.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">12.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.16 K</td>
    <td style="white-space: nowrap; text-align: right">101.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.14 K</td>
    <td style="white-space: nowrap; text-align: right">102.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.10 K</td>
    <td style="white-space: nowrap; text-align: right">106.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0728 K</td>
    <td style="white-space: nowrap; text-align: right">1611.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0687 K</td>
    <td style="white-space: nowrap; text-align: right">1709.31x</td>
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
    <td style="white-space: nowrap">9.68 KB</td>
    <td>1.23x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">10.84 KB</td>
    <td>1.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap">10.63 KB</td>
    <td>1.35x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap">2.12 KB</td>
    <td>0.27x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.16 KB</td>
    <td>0.4x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">124.98 KB</td>
    <td>15.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap">128.89 KB</td>
    <td>16.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.27 KB</td>
    <td>0.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1975.05 KB</td>
    <td>251.55x</td>
  </tr>
</table>