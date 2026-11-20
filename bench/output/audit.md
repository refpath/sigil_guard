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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">478250.91</td>
    <td style="white-space: nowrap; text-align: right">0.00209 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;334.37%</td>
    <td style="white-space: nowrap; text-align: right">0.00196 ms</td>
    <td style="white-space: nowrap; text-align: right">0.00300 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">104809.15</td>
    <td style="white-space: nowrap; text-align: right">0.00954 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;126.71%</td>
    <td style="white-space: nowrap; text-align: right">0.00783 ms</td>
    <td style="white-space: nowrap; text-align: right">0.0489 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">70586.53</td>
    <td style="white-space: nowrap; text-align: right">0.0142 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;98.05%</td>
    <td style="white-space: nowrap; text-align: right">0.0118 ms</td>
    <td style="white-space: nowrap; text-align: right">0.120 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">490.45</td>
    <td style="white-space: nowrap; text-align: right">2.04 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.00%</td>
    <td style="white-space: nowrap; text-align: right">2.03 ms</td>
    <td style="white-space: nowrap; text-align: right">2.47 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">290.24</td>
    <td style="white-space: nowrap; text-align: right">3.45 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.18%</td>
    <td style="white-space: nowrap; text-align: right">3.49 ms</td>
    <td style="white-space: nowrap; text-align: right">4.47 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">164.04</td>
    <td style="white-space: nowrap; text-align: right">6.10 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.83%</td>
    <td style="white-space: nowrap; text-align: right">5.97 ms</td>
    <td style="white-space: nowrap; text-align: right">8.80 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">147.14</td>
    <td style="white-space: nowrap; text-align: right">6.80 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.13%</td>
    <td style="white-space: nowrap; text-align: right">6.94 ms</td>
    <td style="white-space: nowrap; text-align: right">9.00 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">136.43</td>
    <td style="white-space: nowrap; text-align: right">7.33 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.22%</td>
    <td style="white-space: nowrap; text-align: right">7.40 ms</td>
    <td style="white-space: nowrap; text-align: right">9.25 ms</td>
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
    <td style="white-space: nowrap;text-align: right">478250.91</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">104809.15</td>
    <td style="white-space: nowrap; text-align: right">4.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">70586.53</td>
    <td style="white-space: nowrap; text-align: right">6.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">490.45</td>
    <td style="white-space: nowrap; text-align: right">975.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">290.24</td>
    <td style="white-space: nowrap; text-align: right">1647.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">164.04</td>
    <td style="white-space: nowrap; text-align: right">2915.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">147.14</td>
    <td style="white-space: nowrap; text-align: right">3250.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">136.43</td>
    <td style="white-space: nowrap; text-align: right">3505.38x</td>
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
    <td style="white-space: nowrap">2.65 MB</td>
    <td>1616.2x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap">4.22 MB</td>
    <td>2572.1x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap">4.12 MB</td>
    <td>2510.31x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">3.97 MB</td>
    <td>2421.43x</td>
  </tr>
</table>