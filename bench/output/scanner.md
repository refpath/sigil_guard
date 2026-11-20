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
- SigilGuard: 1.0.5 (3471773)
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
    <td style="white-space: nowrap; text-align: right">150.46 K</td>
    <td style="white-space: nowrap; text-align: right">6.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;100.89%</td>
    <td style="white-space: nowrap; text-align: right">6.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">131.24 K</td>
    <td style="white-space: nowrap; text-align: right">7.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;103.79%</td>
    <td style="white-space: nowrap; text-align: right">6.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">76.46 K</td>
    <td style="white-space: nowrap; text-align: right">13.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.74%</td>
    <td style="white-space: nowrap; text-align: right">13.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">74.96 K</td>
    <td style="white-space: nowrap; text-align: right">13.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.57%</td>
    <td style="white-space: nowrap; text-align: right">12.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">64.15 K</td>
    <td style="white-space: nowrap; text-align: right">15.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.88%</td>
    <td style="white-space: nowrap; text-align: right">15.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">60.27 K</td>
    <td style="white-space: nowrap; text-align: right">16.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.34%</td>
    <td style="white-space: nowrap; text-align: right">16.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.25 K</td>
    <td style="white-space: nowrap; text-align: right">801.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.21%</td>
    <td style="white-space: nowrap; text-align: right">801.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">859.36 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.14 K</td>
    <td style="white-space: nowrap; text-align: right">873.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.63%</td>
    <td style="white-space: nowrap; text-align: right">871.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">979.36 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.11 K</td>
    <td style="white-space: nowrap; text-align: right">898.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.86%</td>
    <td style="white-space: nowrap; text-align: right">895.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1034.57 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0780 K</td>
    <td style="white-space: nowrap; text-align: right">12821.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.45%</td>
    <td style="white-space: nowrap; text-align: right">12822.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13235.70 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0710 K</td>
    <td style="white-space: nowrap; text-align: right">14077.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.90%</td>
    <td style="white-space: nowrap; text-align: right">13862.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15811.54 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">150.46 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap; text-align: right">131.24 K</td>
    <td style="white-space: nowrap; text-align: right">1.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">76.46 K</td>
    <td style="white-space: nowrap; text-align: right">1.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap; text-align: right">74.96 K</td>
    <td style="white-space: nowrap; text-align: right">2.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">64.15 K</td>
    <td style="white-space: nowrap; text-align: right">2.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap; text-align: right">60.27 K</td>
    <td style="white-space: nowrap; text-align: right">2.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.25 K</td>
    <td style="white-space: nowrap; text-align: right">120.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.14 K</td>
    <td style="white-space: nowrap; text-align: right">131.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.11 K</td>
    <td style="white-space: nowrap; text-align: right">135.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0780 K</td>
    <td style="white-space: nowrap; text-align: right">1929.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0710 K</td>
    <td style="white-space: nowrap; text-align: right">2118.06x</td>
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
    <td style="white-space: nowrap">2.85 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.11 pattern sets resolve 10 entries</td>
    <td style="white-space: nowrap">7.85 KB</td>
    <td>2.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">3.16 KB</td>
    <td>1.11x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.10 quarantine inspect injection</td>
    <td style="white-space: nowrap">9.84 KB</td>
    <td>3.45x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">10.85 KB</td>
    <td>3.81x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 1k</td>
    <td style="white-space: nowrap">11.09 KB</td>
    <td>3.89x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.19 KB</td>
    <td>1.12x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">126.11 KB</td>
    <td>44.22x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.09 scan and redact hits 64k</td>
    <td style="white-space: nowrap">129.22 KB</td>
    <td>45.32x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.30 KB</td>
    <td>1.16x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1976.71 KB</td>
    <td>693.2x</td>
  </tr>
</table>