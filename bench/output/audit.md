# Audit Evidence Benchmarks

Every decision can append one HMAC-chained audit event, and a host
periodically checkpoints the chain into a Merkle root and exports
evidence. The suite appends to a chain of 10,000 events, creates a
checkpoint over it, builds and verifies inclusion and consistency proofs,
verifies a chain of 1,000 events, and exports it. Event ids and
timestamps follow from the event index, so the chain has the same bytes
on every run.

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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">578610.25</td>
    <td style="white-space: nowrap; text-align: right">0.00173 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;386.86%</td>
    <td style="white-space: nowrap; text-align: right">0.00158 ms</td>
    <td style="white-space: nowrap; text-align: right">0.00225 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">113393.97</td>
    <td style="white-space: nowrap; text-align: right">0.00882 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;135.30%</td>
    <td style="white-space: nowrap; text-align: right">0.00750 ms</td>
    <td style="white-space: nowrap; text-align: right">0.0462 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">75321.96</td>
    <td style="white-space: nowrap; text-align: right">0.0133 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;104.56%</td>
    <td style="white-space: nowrap; text-align: right">0.0113 ms</td>
    <td style="white-space: nowrap; text-align: right">0.118 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">525.40</td>
    <td style="white-space: nowrap; text-align: right">1.90 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.01%</td>
    <td style="white-space: nowrap; text-align: right">1.89 ms</td>
    <td style="white-space: nowrap; text-align: right">2.34 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">273.84</td>
    <td style="white-space: nowrap; text-align: right">3.65 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.95%</td>
    <td style="white-space: nowrap; text-align: right">3.63 ms</td>
    <td style="white-space: nowrap; text-align: right">4.23 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">155.42</td>
    <td style="white-space: nowrap; text-align: right">6.43 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.78%</td>
    <td style="white-space: nowrap; text-align: right">6.51 ms</td>
    <td style="white-space: nowrap; text-align: right">10.06 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">149.19</td>
    <td style="white-space: nowrap; text-align: right">6.70 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.89%</td>
    <td style="white-space: nowrap; text-align: right">6.89 ms</td>
    <td style="white-space: nowrap; text-align: right">8.89 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">136.77</td>
    <td style="white-space: nowrap; text-align: right">7.31 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.54%</td>
    <td style="white-space: nowrap; text-align: right">6.92 ms</td>
    <td style="white-space: nowrap; text-align: right">13.73 ms</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap;text-align: right">578610.25</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">113393.97</td>
    <td style="white-space: nowrap; text-align: right">5.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">75321.96</td>
    <td style="white-space: nowrap; text-align: right">7.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">525.40</td>
    <td style="white-space: nowrap; text-align: right">1101.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">273.84</td>
    <td style="white-space: nowrap; text-align: right">2112.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">155.42</td>
    <td style="white-space: nowrap; text-align: right">3722.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">149.19</td>
    <td style="white-space: nowrap; text-align: right">3878.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">136.77</td>
    <td style="white-space: nowrap; text-align: right">4230.61x</td>
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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap">0.00164 MB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap">0.00554 MB</td>
    <td>3.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap">0.00809 MB</td>
    <td>4.93x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap">1.46 MB</td>
    <td>893.07x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap">2.66 MB</td>
    <td>1620.57x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">3.98 MB</td>
    <td>2425.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap">4.12 MB</td>
    <td>2510.31x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap">4.22 MB</td>
    <td>2572.1x</td>
  </tr>
</table>