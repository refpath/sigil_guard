# Audit Evidence Benchmarks

Every decision can append one HMAC-chained audit event, and a host
periodically checkpoints the chain into a Merkle root and exports
evidence. The suite appends to a chain of 10,000 events, creates a
checkpoint over it, builds and verifies inclusion and consistency proofs,
verifies a chain of 1,000 events, and exports it. Event ids and
timestamps follow from the event index, so the chain has the same bytes
on every run.

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
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">589011.38</td>
    <td style="white-space: nowrap; text-align: right">0.00170 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.75%</td>
    <td style="white-space: nowrap; text-align: right">0.00159 ms</td>
    <td style="white-space: nowrap; text-align: right">0.00401 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">110189.16</td>
    <td style="white-space: nowrap; text-align: right">0.00908 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;136.51%</td>
    <td style="white-space: nowrap; text-align: right">0.00746 ms</td>
    <td style="white-space: nowrap; text-align: right">0.0550 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">72850.85</td>
    <td style="white-space: nowrap; text-align: right">0.0137 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;115.59%</td>
    <td style="white-space: nowrap; text-align: right">0.0115 ms</td>
    <td style="white-space: nowrap; text-align: right">0.136 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">494.10</td>
    <td style="white-space: nowrap; text-align: right">2.02 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.86%</td>
    <td style="white-space: nowrap; text-align: right">1.94 ms</td>
    <td style="white-space: nowrap; text-align: right">3.61 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">297.42</td>
    <td style="white-space: nowrap; text-align: right">3.36 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.06%</td>
    <td style="white-space: nowrap; text-align: right">3.35 ms</td>
    <td style="white-space: nowrap; text-align: right">3.75 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">137.20</td>
    <td style="white-space: nowrap; text-align: right">7.29 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.65%</td>
    <td style="white-space: nowrap; text-align: right">7.22 ms</td>
    <td style="white-space: nowrap; text-align: right">11.78 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">114.59</td>
    <td style="white-space: nowrap; text-align: right">8.73 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.55%</td>
    <td style="white-space: nowrap; text-align: right">7.76 ms</td>
    <td style="white-space: nowrap; text-align: right">19.21 ms</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">112.41</td>
    <td style="white-space: nowrap; text-align: right">8.90 ms</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.11%</td>
    <td style="white-space: nowrap; text-align: right">8.00 ms</td>
    <td style="white-space: nowrap; text-align: right">17.06 ms</td>
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
    <td style="white-space: nowrap;text-align: right">589011.38</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">110189.16</td>
    <td style="white-space: nowrap; text-align: right">5.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap; text-align: right">72850.85</td>
    <td style="white-space: nowrap; text-align: right">8.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap; text-align: right">494.10</td>
    <td style="white-space: nowrap; text-align: right">1192.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap; text-align: right">297.42</td>
    <td style="white-space: nowrap; text-align: right">1980.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap; text-align: right">137.20</td>
    <td style="white-space: nowrap; text-align: right">4293.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap; text-align: right">114.59</td>
    <td style="white-space: nowrap; text-align: right">5140.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">112.41</td>
    <td style="white-space: nowrap; text-align: right">5239.72x</td>
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
    <td style="white-space: nowrap">0.00166 MB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap">0.00554 MB</td>
    <td>3.34x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency verify 10k</td>
    <td style="white-space: nowrap">0.00809 MB</td>
    <td>4.89x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit verify chain 1k</td>
    <td style="white-space: nowrap">1.46 MB</td>
    <td>884.16x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit export create 1k</td>
    <td style="white-space: nowrap">2.66 MB</td>
    <td>1604.41x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit consistency proof 10k</td>
    <td style="white-space: nowrap">4.22 MB</td>
    <td>2546.44x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.26 audit inclusion proof 10k</td>
    <td style="white-space: nowrap">4.12 MB</td>
    <td>2485.27x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">3.98 MB</td>
    <td>2401.58x</td>
  </tr>
</table>