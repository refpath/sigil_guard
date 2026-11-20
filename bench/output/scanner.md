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
- SigilGuard: 1.0.5 (39a9315)
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
    <td style="white-space: nowrap">BM.10 quarantine inspect clean 1k</td>
    <td style="white-space: nowrap; text-align: right">137.80 K</td>
    <td style="white-space: nowrap; text-align: right">7.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.82%</td>
    <td style="white-space: nowrap; text-align: right">6.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">11.77 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">129.08 K</td>
    <td style="white-space: nowrap; text-align: right">7.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;102.32%</td>
    <td style="white-space: nowrap; text-align: right">6.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">67.69 K</td>
    <td style="white-space: nowrap; text-align: right">14.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.46%</td>
    <td style="white-space: nowrap; text-align: right">13.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">60.83 K</td>
    <td style="white-space: nowrap; text-align: right">16.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.94%</td>
    <td style="white-space: nowrap; text-align: right">16.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">59.78 K</td>
    <td style="white-space: nowrap; text-align: right">16.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.93%</td>
    <td style="white-space: nowrap; text-align: right">16.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">29.99 K</td>
    <td style="white-space: nowrap; text-align: right">33.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.43%</td>
    <td style="white-space: nowrap; text-align: right">32.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.17 K</td>
    <td style="white-space: nowrap; text-align: right">854.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.83%</td>
    <td style="white-space: nowrap; text-align: right">851.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">988.43 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.16 K</td>
    <td style="white-space: nowrap; text-align: right">862.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.96%</td>
    <td style="white-space: nowrap; text-align: right">844.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1037.93 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.01 K</td>
    <td style="white-space: nowrap; text-align: right">991.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.67%</td>
    <td style="white-space: nowrap; text-align: right">1001.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1088.72 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0741 K</td>
    <td style="white-space: nowrap; text-align: right">13497.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.60%</td>
    <td style="white-space: nowrap; text-align: right">13195.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15139.56 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0659 K</td>
    <td style="white-space: nowrap; text-align: right">15180.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.19%</td>
    <td style="white-space: nowrap; text-align: right">15137.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16655.77 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">137.80 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">129.08 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">67.69 K</td>
    <td style="white-space: nowrap; text-align: right">2.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">60.83 K</td>
    <td style="white-space: nowrap; text-align: right">2.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">59.78 K</td>
    <td style="white-space: nowrap; text-align: right">2.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">29.99 K</td>
    <td style="white-space: nowrap; text-align: right">4.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.17 K</td>
    <td style="white-space: nowrap; text-align: right">117.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.16 K</td>
    <td style="white-space: nowrap; text-align: right">118.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.01 K</td>
    <td style="white-space: nowrap; text-align: right">136.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0741 K</td>
    <td style="white-space: nowrap; text-align: right">1859.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0659 K</td>
    <td style="white-space: nowrap; text-align: right">2091.85x</td>
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
    <td style="white-space: nowrap">7.85 KB</td>
    <td>2.62x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">3.16 KB</td>
    <td>1.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap">11.09 KB</td>
    <td>3.7x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">10.85 KB</td>
    <td>3.62x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap">10.05 KB</td>
    <td>3.36x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.19 KB</td>
    <td>1.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap">129.22 KB</td>
    <td>43.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">126.11 KB</td>
    <td>42.09x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.30 KB</td>
    <td>1.1x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1976.71 KB</td>
    <td>659.76x</td>
  </tr>
</table>